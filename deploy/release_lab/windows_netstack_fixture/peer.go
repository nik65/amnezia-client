package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// This adapter binds exclusively to guest loopback. The port remains held for
// the lifetime of the AWG device; there is no free-port/rebind race.
type udpBind struct {
	mu     sync.Mutex
	socket *net.UDPConn
}
type endpoint struct{ netip.AddrPort }

func (e endpoint) ClearSrc()           {}
func (e endpoint) SrcToString() string { return "" }
func (e endpoint) DstToString() string { return e.String() }
func (e endpoint) DstToBytes() []byte  { return []byte(e.String()) }
func (e endpoint) DstIP() netip.Addr   { return e.Addr() }
func (e endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (b *udpBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.socket = s
	receive := func(p [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, addr, err := s.ReadFromUDPAddrPort(p[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = endpoint{addr}
		return 1, nil
	}
	return []conn.ReceiveFunc{receive}, uint16(s.LocalAddr().(*net.UDPAddr).Port), nil
}
func (b *udpBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket == nil {
		return nil
	}
	err := b.socket.Close()
	b.socket = nil
	return err
}
func (b *udpBind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("marks forbidden")
	}
	return nil
}
func (b *udpBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	a, e := netip.ParseAddrPort(s)
	if e != nil || !a.Addr().IsLoopback() {
		return nil, errors.New("nonloopback endpoint")
	}
	return endpoint{a}, nil
}
func (b *udpBind) BatchSize() int { return 1 }
func (b *udpBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	s := b.socket
	b.mu.Unlock()
	if s == nil {
		return net.ErrClosed
	}
	for _, p := range bufs {
		if _, err := s.WriteToUDPAddrPort(p, e.AddrPort); err != nil {
			return err
		}
	}
	return nil
}

type peer struct {
	dev     *device.Device
	network *netstack.Net
	bind    conn.Bind
}

func newPeer(bind conn.Bind, address, privateKey, remoteKey, remoteAddress, remoteEndpoint string) (*peer, error) {
	for _, k := range []string{privateKey, remoteKey} {
		v, e := hex.DecodeString(k)
		if e != nil || len(v) != 32 {
			return nil, errors.New("invalid key")
		}
	}
	local, err := netip.ParseAddr(address)
	if err != nil {
		return nil, err
	}
	remote, err := netip.ParseAddr(remoteAddress)
	if err != nil {
		return nil, err
	}
	addresses := []netip.Addr{local}
	if local.String() == "172.29.172.253" {
		addresses = append(addresses, netip.MustParseAddr("172.29.172.251"))
	}
	t, n, err := netstack.CreateNetTUN(addresses, nil, 1280)
	if err != nil {
		return nil, err
	}
	d := device.NewDevice(t, bind, device.NewLogger(device.LogLevelSilent, ""))
	config := "private_key=" + privateKey + "\nrandom_trailers=true\ndisable_cookies=true\npublic_key=" + remoteKey + "\nallowed_ip=" + remote.String() + "/32\n"
	if remoteEndpoint != "" {
		config += "endpoint=" + remoteEndpoint + "\n"
	}
	if err = d.IpcSet(config); err != nil {
		d.Close()
		return nil, errors.New("peer configuration rejected")
	}
	if err = d.Up(); err != nil {
		d.Close()
		return nil, errors.New("peer startup rejected")
	}
	return &peer{d, n, bind}, nil
}

// Every answer is explicitly fixture evidence. No production journal, CAS, or
// ACK result is fabricated by this helper. Migration paths fail closed.
func fixtureHandler(routes []byte, nonce string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/rules.json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(routes)))
		w.Header().Set("X-Amnezia-Lab-Fixture", nonce)
		_, _ = w.Write(routes)
	})
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("X-Amnezia-Lab-Nonce") != nonce {
			w.WriteHeader(403)
			return
		}
		_, _ = io.WriteString(w, nonce)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "fixture_control_contract_pending", 501) })
	return mux
}
func servePeer(p *peer, routes []byte, nonce string) ([]*http.Server, error) {
	var servers []*http.Server
	for _, entry := range []struct {
		ip   string
		port int
	}{{"172.29.172.253", 17864}, {"172.29.172.251", 18082}} {
		l, err := p.network.ListenTCP(&net.TCPAddr{IP: net.ParseIP(entry.ip), Port: entry.port})
		if err != nil {
			for _, s := range servers {
				_ = s.Close()
			}
			return nil, err
		}
		s := &http.Server{Handler: fixtureHandler(routes, nonce), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
		servers = append(servers, s)
		go func() { _ = s.Serve(l) }()
	}
	return servers, nil
}
func digest(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func observation(p *peer) map[string]string {
	raw, err := p.dev.IpcGet()
	if err != nil {
		return map[string]string{"error": "uapi_read_failed"}
	}
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "listen_port", "last_handshake_time_sec", "rx_bytes", "tx_bytes", "random_trailers", "disable_cookies":
			out[k] = v
		}
	}
	return out
}
func peerPort(p *peer) (uint16, error) {
	v, e := strconv.ParseUint(observation(p)["listen_port"], 10, 16)
	if e != nil || v == 0 {
		return 0, fmt.Errorf("missing held peer port")
	}
	return uint16(v), nil
}
