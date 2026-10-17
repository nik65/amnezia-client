package uniontun

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func ipv4Packet(destination string, protocol byte, port uint16) []byte {
	packet := make([]byte, 40)
	packet[0], packet[9] = 0x45, protocol
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], netip.MustParseAddr("10.66.66.2").AsSlice())
	copy(packet[16:20], netip.MustParseAddr(destination).AsSlice())
	binary.BigEndian.PutUint16(packet[20:22], 50000)
	binary.BigEndian.PutUint16(packet[22:24], port)
	packet[32], packet[33] = 0x50, 0x02
	return packet
}

func ipv6Packet(destination string, protocol byte) []byte {
	packet := make([]byte, 60)
	packet[0], packet[6] = 0x60, protocol
	binary.BigEndian.PutUint16(packet[4:6], 20)
	copy(packet[8:24], netip.MustParseAddr("fd66::2").AsSlice())
	copy(packet[24:40], netip.MustParseAddr(destination).AsSlice())
	binary.BigEndian.PutUint16(packet[40:42], 50000)
	binary.BigEndian.PutUint16(packet[42:44], 443)
	packet[52], packet[53] = 0x50, 0x02
	return packet
}

func TestIncludedUnionMatrix(t *testing.T) {
	for _, protocol := range []byte{6, 17} {
		for _, version := range []int{4, 6} {
			for _, app := range []bool{false, true} {
				for _, site := range []bool{false, true} {
					p, err := newPolicy(`{"sites":["198.51.100.0/24","2001:db8:1::/48"],"dns":["10.66.66.1"]}`,
						func(_ int, _, _ netip.AddrPort) int {
							if app {
								return 1
							}
							return 0
						})
					if err != nil {
						t.Fatal(err)
					}
					var packet []byte
					if version == 4 {
						address := "203.0.113.4"
						if site {
							address = "198.51.100.8"
						}
						packet = ipv4Packet(address, protocol, 443)
					} else {
						address := "2001:db8:2::4"
						if site {
							address = "2001:db8:1::8"
						}
						packet = ipv6Packet(address, protocol)
					}
					if actual := p.throughVPN(packet, time.Now()); actual != (app || site) {
						t.Fatalf("IPv%d proto=%d app=%t site=%t: VPN=%t", version, protocol, app, site, actual)
					}
				}
			}
		}
	}
}

func TestUnknownOwnerDNSFragmentsAndMalformedStayInVPN(t *testing.T) {
	ownerCalls := 0
	p, err := newPolicy(`{"sites":["198.51.100.0/24"],"dns":["10.66.66.1"]}`,
		func(_ int, _, _ netip.AddrPort) int { ownerCalls++; return -1 })
	if err != nil {
		t.Fatal(err)
	}
	dns := ipv4Packet("10.66.66.1", 17, 53)
	if !p.throughVPN(dns, time.Now()) || ownerCalls != 0 {
		t.Fatal("shared DNS bypassed/owner dependent")
	}
	packet := ipv4Packet("203.0.113.1", 6, 443)
	if !p.throughVPN(packet, time.Now()) {
		t.Fatal("unknown owner bypassed")
	}
	p.owner = func(_ int, _, _ netip.AddrPort) int { t.Fatal("unattributable packet queried owner"); return 0 }
	fragment := ipv4Packet("203.0.113.1", 17, 443)
	fragment[6] = 0x20
	v6fragment := ipv6Packet("2001:db8:2::1", 44)
	for _, malformed := range [][]byte{nil, {0x45}, packet[:22], fragment, v6fragment} {
		if !p.throughVPN(malformed, time.Now()) {
			t.Fatal("unsafe packet bypassed")
		}
	}
}

func TestMalformedIPv6OptionsStayInVPNWithoutOwnerLookup(t *testing.T) {
	p, err := newPolicy(`{"sites":["198.51.100.0/24"]}`,
		func(_ int, _, _ netip.AddrPort) int {
			t.Fatal("malformed IPv6 packet queried owner")
			return 0
		})
	if err != nil {
		t.Fatal(err)
	}
	// A destination-options header claims 2048 bytes while the IPv6 payload
	// contains only one eight-byte extension header. Parsing must fail closed
	// before TCP sequence inspection or owner attribution.
	packet := ipv6Packet("203.0.113.1", 60)
	packet[40], packet[41] = 6, 0xff
	if !p.throughVPN(packet, time.Now()) {
		t.Fatal("malformed IPv6 options bypassed VPN")
	}

	// A bounded chain of eight options is still safe, but a ninth extension is
	// unsupported and must remain in the VPN without walking out of bounds.
	packet = make([]byte, 40+9*8+20)
	packet[0], packet[6] = 0x60, 0
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	copy(packet[8:24], netip.MustParseAddr("fd66::2").AsSlice())
	copy(packet[24:40], netip.MustParseAddr("203.0.113.1").AsSlice())
	for offset := 40; offset < 40+9*8; offset += 8 {
		packet[offset], packet[offset+1] = 0, 0
	}
	if p.throughVPN(packet, time.Now()) == false {
		t.Fatal("overlong IPv6 extension chain bypassed VPN")
	}
}

func TestTCPRetransmitPinsRouteButReusedTupleRechecksOwner(t *testing.T) {
	selected := false
	ownerCalls := 0
	p, _ := newPolicy(`{"sites":["198.51.100.0/24"]}`,
		func(_ int, _, _ netip.AddrPort) int {
			ownerCalls++
			if selected {
				return 1
			}
			return 0
		})
	packet := ipv4Packet("203.0.113.1", 6, 443)
	if p.throughVPN(packet, time.Now()) {
		t.Fatal("known other app failed to bypass")
	}
	selected = true
	if p.throughVPN(packet, time.Now()) || ownerCalls != 1 {
		t.Fatal("retransmitted SYN changed route")
	}
	binary.BigEndian.PutUint32(packet[24:28], 42)
	if !p.throughVPN(packet, time.Now()) || ownerCalls != 2 {
		t.Fatal("new app inherited old TCP bypass")
	}
}

func TestUDPTupleRechecksOwnerAndPolicyCacheIsBounded(t *testing.T) {
	selected := false
	p, _ := newPolicy(`{"sites":["198.51.100.0/24"]}`,
		func(_ int, _, _ netip.AddrPort) int {
			if selected {
				return 1
			}
			return 0
		})
	packet := ipv4Packet("203.0.113.1", 17, 443)
	if p.throughVPN(packet, time.Now()) {
		t.Fatal("UDP bypass denied")
	}
	selected = true
	if !p.throughVPN(packet, time.Now()) {
		t.Fatal("new app inherited old UDP bypass")
	}
	selected = false
	packet = ipv4Packet("203.0.113.1", 6, 443)
	for i := 1; i <= 8200; i++ {
		binary.BigEndian.PutUint16(packet[20:22], uint16(i))
		p.throughVPN(packet, time.Now())
	}
	if len(p.flows) > 8192 {
		t.Fatal("unbounded owner cache")
	}
	if !p.throughVPN(packet, time.Now()) {
		t.Fatal("saturated cache authorized bypass")
	}
}

func TestPolicyValidation(t *testing.T) {
	for _, text := range []string{`{}`, `{"sites":["bad"]}`, `{"sites":["198.51.100.0/24"],"dns":["bad"]}`} {
		if _, err := newPolicy(text, func(_ int, _, _ netip.AddrPort) int { return 0 }); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
}
