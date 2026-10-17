// SPDX-License-Identifier: Apache-2.0
package uniontun

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
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
	"gvisor.dev/gvisor/pkg/waiter"
)

type directStack struct {
	stack       *stack.Stack
	link        *channel.Endpoint
	ctx         context.Context
	cancel      context.CancelFunc
	dialer      net.Dialer
	dial        func(context.Context, string, string) (net.Conn, error)
	mu          sync.Mutex
	injectMu    sync.Mutex
	closed      bool
	connections map[net.Conn]bool
	workers     sync.WaitGroup
	closeOnce   sync.Once
}

func newDirectStack(mtu int, protect func(int) bool, output func([]byte) error) (*directStack, error) {
	if mtu < 576 || mtu > 65535 || protect == nil || output == nil {
		return nil, errors.New("invalid direct stack configuration")
	}
	d := &directStack{connections: make(map[net.Conn]bool)}
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.dialer = net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second,
		Control: func(_, _ string, socket syscall.RawConn) error {
			var protectionError error
			if err := socket.Control(func(fd uintptr) {
				if !protect(int(fd)) {
					protectionError = errors.New("direct socket protection failed")
				}
			}); err != nil {
				return err
			}
			return protectionError
		},
	}
	d.dial = d.dialer.DialContext
	d.link = channel.New(256, uint32(mtu), "")
	d.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	fail := func(err tcpip.Error) (*directStack, error) {
		d.cancel()
		d.stack.Close()
		d.link.Close()
		return nil, errors.New(err.String())
	}
	if err := d.stack.CreateNIC(1, d.link); err != nil {
		return fail(err)
	}
	if err := d.stack.SetPromiscuousMode(1, true); err != nil {
		return fail(err)
	}
	if err := d.stack.SetSpoofing(1, true); err != nil {
		return fail(err)
	}
	d.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	tcpForwarder := tcp.NewForwarder(d.stack, 0, 1024, func(request *tcp.ForwarderRequest) {
		id := request.ID()
		var queue waiter.Queue
		endpoint, err := request.CreateEndpoint(&queue)
		if err != nil {
			request.Complete(true)
			return
		}
		request.Complete(false)
		local := gonet.NewTCPConn(&queue, endpoint)
		d.launch(local, id, "tcp")
	})
	d.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := udp.NewForwarder(d.stack, func(request *udp.ForwarderRequest) bool {
		var queue waiter.Queue
		endpoint, err := request.CreateEndpoint(&queue)
		if err != nil {
			return false
		}
		d.launch(gonet.NewUDPConn(&queue, endpoint), request.ID(), "udp")
		return true
	})
	d.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	d.workers.Add(1)
	go func() {
		defer d.workers.Done()
		for {
			packet := d.link.ReadContext(d.ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			if err := output(view.AsSlice()); err != nil {
				view.Release()
				packet.DecRef()
				return
			}
			view.Release()
			packet.DecRef()
		}
	}()
	return d, nil
}

func (d *directStack) inject(data []byte) {
	if len(data) == 0 {
		return
	}
	// The caller's AWG read buffer is immediately reused.
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return
	}
	// Serialize endpoint teardown with injection. Keep d.mu available while
	// gVisor dispatches the packet because its forwarder synchronously calls
	// d.launch, which also takes d.mu.
	d.injectMu.Lock()
	defer d.injectMu.Unlock()
	d.mu.Lock()
	closed = d.closed
	d.mu.Unlock()
	if closed {
		return
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), data...))})
	defer packet.DecRef()
	protocol := ipv4.ProtocolNumber
	if data[0]>>4 == 6 {
		protocol = ipv6.ProtocolNumber
	}
	d.link.InjectInbound(protocol, packet)
}

func (d *directStack) track(connection net.Conn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		connection.Close()
		return false
	}
	d.connections[connection] = true
	return true
}

func (d *directStack) forget(connection net.Conn) {
	connection.Close()
	d.mu.Lock()
	delete(d.connections, connection)
	d.mu.Unlock()
}

func (d *directStack) launch(local net.Conn, id stack.TransportEndpointID, protocol string) {
	d.mu.Lock()
	if d.closed || len(d.connections) >= 2048 {
		d.mu.Unlock()
		local.Close()
		return
	}
	d.connections[local] = true
	d.workers.Add(1)
	d.mu.Unlock()
	go func() {
		defer d.workers.Done()
		defer d.forget(local)
		address, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
		if !ok {
			return
		}
		remote, err := d.dial(d.ctx, protocol, netip.AddrPortFrom(address, id.LocalPort).String())
		if err != nil {
			return
		}
		if !d.track(remote) {
			return
		}
		defer d.forget(remote)
		finished := make(chan struct{})
		if protocol == "tcp" {
			go func() { defer close(finished); io.Copy(remote, local); closeWrite(remote) }()
			io.Copy(local, remote)
			closeWrite(local)
		} else {
			go func() { defer close(finished); copyDatagrams(remote, local) }()
			copyDatagrams(local, remote)
			// Either inactivity/error terminates both datagram readers.
			local.Close()
			remote.Close()
		}
		<-finished
	}()
}

func closeWrite(connection net.Conn) {
	if half, ok := connection.(interface{ CloseWrite() error }); ok {
		half.CloseWrite()
	}
}

func copyDatagrams(destination, source net.Conn) {
	data := make([]byte, 65535)
	for {
		source.SetReadDeadline(time.Now().Add(time.Minute))
		n, err := source.Read(data)
		if err != nil {
			return
		}
		destination.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err = destination.Write(data[:n]); err != nil {
			return
		}
	}
}

func (d *directStack) close() {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		d.cancel()
		for connection := range d.connections {
			connection.Close()
		}
		d.mu.Unlock()
		d.stack.Close()
		d.injectMu.Lock()
		d.link.Close()
		d.injectMu.Unlock()
		d.workers.Wait()
		d.stack.Wait()
	})
}
