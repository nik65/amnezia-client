package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"golang.org/x/crypto/curve25519"
)

// Real AWG crypto + TCP/IP stack, with datagrams delivered through channels.
// These tests never create an OS socket/listener or a Windows network adapter.
type memoryBind struct {
	incoming chan []byte
	remote   *memoryBind
	closed   chan struct{}
	once     sync.Once
}

func (b *memoryBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.closed = make(chan struct{})
	b.once = sync.Once{}
	closed := b.closed
	return []conn.ReceiveFunc{func(p [][]byte, s []int, e []conn.Endpoint) (int, error) {
		select {
		case <-closed:
			return 0, net.ErrClosed
		case packet := <-b.incoming:
			s[0] = copy(p[0], packet)
			e[0] = endpoint{netip.MustParseAddrPort("127.0.0.1:12345")}
			return 1, nil
		}
	}}, 12345, nil
}
func (b *memoryBind) Close() error         { b.once.Do(func() { close(b.closed) }); return nil }
func (b *memoryBind) SetMark(uint32) error { return nil }
func (b *memoryBind) BatchSize() int       { return 1 }
func (b *memoryBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	a, e := netip.ParseAddrPort(s)
	return endpoint{a}, e
}
func (b *memoryBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	for _, p := range bufs {
		select {
		case <-b.closed:
			return net.ErrClosed
		case <-b.remote.closed:
			return net.ErrClosed
		case b.remote.incoming <- append([]byte(nil), p...):
		}
	}
	return nil
}
func keypair(t *testing.T) (string, string) {
	t.Helper()
	k := make([]byte, 32)
	if _, e := rand.Read(k); e != nil {
		t.Fatal(e)
	}
	p, e := curve25519.X25519(k, curve25519.Basepoint)
	if e != nil {
		t.Fatal(e)
	}
	return hex.EncodeToString(k), hex.EncodeToString(p)
}
func TestActualAWG3EncryptedDataplaneWithoutHostSockets(t *testing.T) {
	for _, role := range []string{"source", "target"} {
		t.Run(role, func(t *testing.T) {
			a := &memoryBind{incoming: make(chan []byte, 256), closed: make(chan struct{})}
			b := &memoryBind{incoming: make(chan []byte, 256), closed: make(chan struct{})}
			a.remote = b
			b.remote = a
			clientKey, clientPublic := keypair(t)
			serverKey, serverPublic := keypair(t)
			server, e := newPeer(b, "172.29.172.253", serverKey, clientPublic, "10.244.0.2", "")
			if e != nil {
				t.Fatal(e)
			}
			defer server.dev.Close()
			client, e := newPeer(a, "10.244.0.2", clientKey, serverPublic, "172.29.172.253", "127.0.0.1:12345")
			if e != nil {
				t.Fatal(e)
			}
			defer client.dev.Close()
			payload := []byte(`{"fixture":true,"routes":[]}`)
			servers, e := servePeer(server, payload, "owned-nonce")
			if e != nil {
				t.Fatal(e)
			}
			defer func() {
				for _, s := range servers {
					_ = s.Close()
				}
			}()
			transport := &http.Transport{DialContext: client.network.DialContext}
			defer transport.CloseIdleConnections()
			h := &http.Client{Transport: transport, Timeout: 8 * time.Second}
			response, e := h.Get("http://172.29.172.253:17864/rules.json")
			if e != nil {
				t.Fatal(e)
			}
			data, e := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if e != nil || string(data) != string(payload) {
				t.Fatal("decrypted payload mismatch")
			}
			for _, p := range []*peer{client, server} {
				o := observation(p)
				t.Logf("%s real encrypted peer observation: %v", role, o)
				if o["last_handshake_time_sec"] == "0" || o["last_handshake_time_sec"] == "" || o["rx_bytes"] == "0" || o["tx_bytes"] == "0" {
					t.Fatalf("missing real handshake/traffic: %v", o)
				}
				if o["random_trailers"] != "1" || o["disable_cookies"] != "1" {
					t.Fatalf("missing AWG3 flags: %v", o)
				}
			}
		})
	}
}
func TestFixtureControlsFailClosed(t *testing.T) {
	h := fixtureHandler([]byte("exact"), "nonce")
	for _, path := range []string{"/offer", "/challenge", "/ack", "/commit"} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("POST", path, strings.NewReader("{}")))
		if r.Code != 501 {
			t.Fatal("fabricated production control")
		}
	}
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "/probe", nil))
	if r.Code != 403 {
		t.Fatal("nonce bypass")
	}
}

func TestWrongPeerKeyCannotProduceHandshakeOrDataplane(t *testing.T) {
	a := &memoryBind{incoming: make(chan []byte, 256), closed: make(chan struct{})}
	b := &memoryBind{incoming: make(chan []byte, 256), closed: make(chan struct{})}
	a.remote = b
	b.remote = a
	ck, cp := keypair(t)
	sk, _ := keypair(t)
	_, wrong := keypair(t)
	server, e := newPeer(b, "172.29.172.253", sk, cp, "10.244.0.2", "")
	if e != nil {
		t.Fatal(e)
	}
	defer server.dev.Close()
	client, e := newPeer(a, "10.244.0.2", ck, wrong, "172.29.172.253", "127.0.0.1:12345")
	if e != nil {
		t.Fatal(e)
	}
	defer client.dev.Close()
	tr := &http.Transport{DialContext: client.network.DialContext}
	defer tr.CloseIdleConnections()
	h := &http.Client{Transport: tr, Timeout: 250 * time.Millisecond}
	if r, e := h.Get("http://172.29.172.253:17864/rules.json"); e == nil {
		r.Body.Close()
		t.Fatal("wrong key produced traffic")
	}
	for _, p := range []*peer{server, client} {
		if v := observation(p)["last_handshake_time_sec"]; v != "" && v != "0" {
			t.Fatal("wrong key produced handshake")
		}
	}
}
func TestEndpointAndKeyNegativesWithoutSockets(t *testing.T) {
	b := &udpBind{}
	for _, s := range []string{"8.8.8.8:80", "0.0.0.0:80", "bad"} {
		if _, e := b.ParseEndpoint(s); e == nil {
			t.Fatal("nonloopback allowed")
		}
	}
	if e := b.SetMark(1); e == nil {
		t.Fatal("mark mutation allowed")
	}
	if _, e := newPeer(b, "10.0.0.2", "bad", "bad", "10.0.0.1", ""); e == nil {
		t.Fatal("invalid key allowed")
	}
	if !errors.Is(b.Send(nil, endpoint{}), net.ErrClosed) {
		t.Fatal("closed bind")
	}
}
