package uniontun

import (
	"bytes"
	"net/netip"
	"os"
	"sync"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

type memoryTUN struct {
	packets [][]byte
	events  chan tun.Event
	once    sync.Once
}

func (m *memoryTUN) File() *os.File                                  { return nil }
func (m *memoryTUN) Name() (string, error)                           { return "memory", nil }
func (m *memoryTUN) MTU() (int, error)                               { return 1280, nil }
func (m *memoryTUN) BatchSize() int                                  { return 2 }
func (m *memoryTUN) Events() <-chan tun.Event                        { return m.events }
func (m *memoryTUN) Write(packets [][]byte, offset int) (int, error) { return len(packets), nil }
func (m *memoryTUN) Close() error                                    { m.once.Do(func() { close(m.events) }); return nil }
func (m *memoryTUN) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	n := 0
	for n < len(buffers) && len(m.packets) > 0 {
		sizes[n] = copy(buffers[n][offset:], m.packets[0])
		m.packets = m.packets[1:]
		n++
	}
	if n == 0 {
		return 0, os.ErrClosed
	}
	return n, nil
}

func TestDeviceSeparatesPacketsAndCompactsBatch(t *testing.T) {
	directPacket := ipv4Packet("203.0.113.2", 17, 443)
	vpnPacket := ipv4Packet("198.51.100.2", 17, 443)
	raw := &memoryTUN{packets: [][]byte{directPacket, vpnPacket}, events: make(chan tun.Event)}
	device, err := New(raw, `{"sites":["198.51.100.0/24"]}`, func(_ int, _, _ netip.AddrPort) int { return 0 }, func(int) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	buffers := [][]byte{make([]byte, 1500), make([]byte, 1500)}
	sizes := make([]int, 2)
	n, err := device.Read(buffers, sizes, 16)
	if err != nil || n != 1 || !bytes.Equal(buffers[0][16:16+sizes[0]], vpnPacket) {
		t.Fatalf("VPN batch %d %v %v", n, err, sizes)
	}
	if n, err = device.Read(buffers, sizes, 16); n != 0 || err != os.ErrClosed {
		t.Fatal("raw close not propagated")
	}
}
