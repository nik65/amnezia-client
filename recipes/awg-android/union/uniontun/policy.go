// SPDX-License-Identifier: Apache-2.0
package uniontun

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"time"
)

// Owner returns 1 for an included UID, 0 for a known other UID, -1 if unknown.
// Unknown owners never authorize bypass. Android shares a UID between some apps.
type Owner func(protocol int, source, destination netip.AddrPort) int

type Config struct {
	Sites []string `json:"sites"`
	DNS   []string `json:"dns"`
}

type flow struct {
	source, destination netip.AddrPort
	protocol            byte
}

type decision struct {
	vpn      bool
	seen     time.Time
	sequence uint32
}

type policy struct {
	sites                map[netip.Prefix]bool
	v4Lengths, v6Lengths []int
	dns                  map[netip.Addr]bool
	owner                Owner
	flows                map[flow]decision
}

func newPolicy(text string, owner Owner) (*policy, error) {
	var config Config
	if len(text) > 1<<20 || json.Unmarshal([]byte(text), &config) != nil || owner == nil {
		return nil, errors.New("invalid included union policy")
	}
	p := &policy{owner: owner, sites: make(map[netip.Prefix]bool), dns: make(map[netip.Addr]bool), flows: make(map[flow]decision)}
	if len(config.Sites) == 0 || len(config.Sites) > 16384 {
		return nil, errors.New("invalid included union site count")
	}
	v4Lengths, v6Lengths := make(map[int]bool), make(map[int]bool)
	for _, value := range config.Sites {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, errors.New("invalid included union prefix")
		}
		p.sites[prefix.Masked()] = true
		if prefix.Addr().Is4() {
			v4Lengths[prefix.Bits()] = true
		} else {
			v6Lengths[prefix.Bits()] = true
		}
	}
	for bits := 0; bits <= 128; bits++ {
		if v4Lengths[bits] {
			p.v4Lengths = append(p.v4Lengths, bits)
		}
		if v6Lengths[bits] {
			p.v6Lengths = append(p.v6Lengths, bits)
		}
	}
	for _, value := range config.DNS {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return nil, errors.New("invalid included union DNS")
		}
		p.dns[address.Unmap()] = true
	}
	return p, nil
}

// parsePacket validates the IP and transport headers and returns the transport
// header offset. Fragmented packets and unsupported transports remain in VPN: a
// later fragment has no owner tuple, and sending parts of one datagram to
// different transports is unsafe.
func parsePacket(packet []byte) (flow, int, bool) {
	var source, destination netip.Addr
	var protocol byte
	var offset int
	if len(packet) < 1 {
		return flow{}, 0, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return flow{}, 0, false
		}
		offset = int(packet[0]&15) * 4
		length := int(binary.BigEndian.Uint16(packet[2:4]))
		if offset < 20 || length < offset || length > len(packet) || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return flow{}, 0, false
		}
		packet = packet[:length]
		source = netip.AddrFrom4([4]byte(packet[12:16]))
		destination = netip.AddrFrom4([4]byte(packet[16:20]))
		protocol = packet[9]
	case 6:
		if len(packet) < 40 {
			return flow{}, 0, false
		}
		length := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if length > len(packet) {
			return flow{}, 0, false
		}
		packet = packet[:length]
		source = netip.AddrFrom16([16]byte(packet[8:24]))
		destination = netip.AddrFrom16([16]byte(packet[24:40]))
		protocol, offset = packet[6], 40
		for count := 0; protocol != 6 && protocol != 17; count++ {
			if count >= 8 || offset+2 > len(packet) {
				return flow{}, 0, false
			}
			switch protocol {
			case 0, 43, 60: // hop-by-hop, routing, destination options
				next := packet[offset]
				headerLength := (int(packet[offset+1]) + 1) * 8
				if offset+headerLength > len(packet) {
					return flow{}, 0, false
				}
				offset += headerLength
				protocol = next
			default: // including fragment, ESP and AH
				return flow{}, 0, false
			}
		}
	default:
		return flow{}, 0, false
	}
	minimum := 8
	if protocol == 6 {
		minimum = 20
	} else if protocol != 17 {
		return flow{}, 0, false
	}
	if offset+minimum > len(packet) {
		return flow{}, 0, false
	}
	if protocol == 6 {
		headerLength := int(packet[offset+12]>>4) * 4
		if headerLength < 20 || offset+headerLength > len(packet) {
			return flow{}, 0, false
		}
	}
	return flow{
		source:      netip.AddrPortFrom(source, binary.BigEndian.Uint16(packet[offset:offset+2])),
		destination: netip.AddrPortFrom(destination, binary.BigEndian.Uint16(packet[offset+2:offset+4])),
		protocol:    protocol,
	}, offset, true
}

func packetFlow(packet []byte) (flow, bool) {
	f, _, ok := parsePacket(packet)
	return f, ok
}

func (p *policy) throughVPN(packet []byte, now time.Time) bool {
	f, offset, ok := parsePacket(packet)
	if !ok {
		return true
	}
	if p.dns[f.destination.Addr().Unmap()] {
		return true // shared/system DNS cannot reliably be attributed to an app
	}
	lengths := p.v6Lengths
	if f.destination.Addr().Is4() {
		lengths = p.v4Lengths
	}
	for _, bits := range lengths {
		if p.sites[netip.PrefixFrom(f.destination.Addr(), bits).Masked()] {
			return true
		}
	}
	// UDP tuples can be reused by another UID without any handshake. Lookup
	// each datagram rather than letting an old app's bypass permit escape.
	if f.protocol == 17 {
		return p.owner(int(f.protocol), f.source, f.destination) != 0
	}
	sequence := binary.BigEndian.Uint32(packet[offset+4 : offset+8])
	starting := packet[offset+13]&0x12 == 0x02
	if saved, exists := p.flows[f]; starting && exists && saved.sequence != sequence {
		delete(p.flows, f)
	}
	if saved, exists := p.flows[f]; exists && now.Sub(saved.seen) < 2*time.Minute {
		saved.seen = now
		p.flows[f] = saved
		return saved.vpn
	}
	// A bounded cache pins each live flow to its first route, including unknown
	// owner fallback, so a delayed owner response cannot split a TCP connection.
	if len(p.flows) >= 8192 {
		for key, saved := range p.flows {
			if now.Sub(saved.seen) >= 2*time.Minute {
				delete(p.flows, key)
			}
		}
		if len(p.flows) >= 8192 {
			return true
		}
	}
	vpn := p.owner(int(f.protocol), f.source, f.destination) != 0
	p.flows[f] = decision{vpn: vpn, seen: now, sequence: sequence}
	return vpn
}
