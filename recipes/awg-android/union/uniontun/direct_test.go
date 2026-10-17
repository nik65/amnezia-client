package uniontun

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// All sockets in this test connect only to an owned loopback echo server.
// Real gVisor TCP/UDP packet handling and the production protect hook execute.
func TestDirectTCPUDPProtectionAndCleanup(t *testing.T) {
	for _, version := range []int{4, 6} {
		for _, protocol := range []string{"tcp", "udp"} {
			t.Run(protocol+map[int]string{4: "4", 6: "6"}[version], func(t *testing.T) {
				testDirectEcho(t, version, protocol, true)
			})
		}
	}
}

func TestDirectProtectionFailureSendsNoData(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) { testDirectEcho(t, 4, protocol, false) })
	}
}

func TestDirectInjectIgnoresEmptyAndClosedPackets(t *testing.T) {
	direct, err := newDirectStack(1280, func(int) bool { return true }, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	direct.inject(nil)
	direct.close()
	// A TUN reader can race teardown with its last packet. The injector must
	// fail closed instead of indexing an empty packet or a closed endpoint.
	direct.inject([]byte{0x45})
}

func testDirectEcho(t *testing.T, version int, protocol string, allow bool) {
	var serverAddress string
	var received atomic.Int32
	serverFamily, bindAddress := "4", "127.0.0.1:0"
	if version == 6 {
		serverFamily, bindAddress = "6", "[::1]:0"
	}
	if protocol == "tcp" {
		listener, err := net.Listen("tcp"+serverFamily, bindAddress)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		serverAddress = listener.Addr().String()
		go func() {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			defer connection.Close()
			io.Copy(connection, connection)
			received.Add(1)
		}()
	} else {
		listener, err := net.ListenPacket("udp"+serverFamily, bindAddress)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		serverAddress = listener.LocalAddr().String()
		go func() {
			data := make([]byte, 4096)
			n, address, err := listener.ReadFrom(data)
			if err == nil {
				received.Add(1)
				listener.WriteTo(data[:n], address)
			}
		}()
	}
	var protected atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	defer client.Close()
	link := channel.New(128, 1280, "")
	defer link.Close()
	if err := client.CreateNIC(1, link); err != nil {
		t.Fatal(err)
	}
	address := tcpip.AddrFrom4([4]byte{10, 66, 66, 2})
	network := ipv4.ProtocolNumber
	destination := tcpip.AddrFrom4([4]byte{198, 51, 100, 2})
	if version == 6 {
		address = tcpip.AddrFrom16([16]byte{0xfd, 0x66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
		network = ipv6.ProtocolNumber
		destination = tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	}
	if err := client.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: network, AddressWithPrefix: address.WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	client.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	direct, err := newDirectStack(1280, func(fd int) bool {
		if fd < 0 {
			t.Error("invalid socket fd")
		}
		protected.Add(1)
		return allow
	}, func(data []byte) error {
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), data...))})
		defer packet.DecRef()
		link.InjectInbound(network, packet)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Map only the test destination to our echo server. The actual production
	// net.Dialer and its pre-connect protect Control callback remain in use.
	direct.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return direct.dialer.DialContext(ctx, network, serverAddress)
	}
	var pump sync.WaitGroup
	pump.Add(1)
	go func() {
		defer pump.Done()
		for {
			packet := link.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			direct.inject(view.AsSlice())
			view.Release()
			packet.DecRef()
		}
	}()
	defer func() { cancel(); pump.Wait(); direct.close() }()
	var connection net.Conn
	if protocol == "tcp" {
		connection, err = gonet.DialContextTCP(ctx, client, tcpip.FullAddress{NIC: 1, Addr: destination, Port: 443}, network)
	} else {
		connection, err = gonet.DialUDP(client, nil, &tcpip.FullAddress{NIC: 1, Addr: destination, Port: 443}, network)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = connection.Write([]byte("union-forwarding"))
	if err != nil && allow {
		t.Fatal(err)
	}
	data := make([]byte, 100)
	n, err := connection.Read(data)
	if allow && (err != nil || string(data[:n]) != "union-forwarding") {
		t.Fatalf("echo: %q %v", data[:n], err)
	}
	if !allow && err == nil {
		t.Fatal("unprotected connection delivered data")
	}
	if protected.Load() == 0 {
		t.Fatal("socket protection not invoked")
	}
	// Stop while the connection is still live, with a bounded cleanup deadline.
	closed := make(chan struct{})
	go func() { direct.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("forwarder cleanup stalled")
	}
	direct.mu.Lock()
	count := len(direct.connections)
	direct.mu.Unlock()
	if count != 0 {
		t.Fatalf("%d sockets survived cleanup", count)
	}
	if !allow && received.Load() != 0 {
		t.Fatal("echo server received unprotected data")
	}
}
