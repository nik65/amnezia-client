package main

import (
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// Real AWG crypto delivered through the existing memory-only bind. The old RED
// case guarantees a padded first response: only if the random tail is zero,
// append ONE explicitly labelled test byte. Live helper code never does this.
type framingObservedBind struct {
	*memoryBind
	mu                  sync.Mutex
	forcePaddedFirst    bool
	original, delivered []int
	injected            bool
}

func (binding *framingObservedBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	for _, packet := range packets {
		frame := append([]byte(nil), packet...)
		binding.mu.Lock()
		if len(binding.original) == 0 && binding.forcePaddedFirst && len(frame) == 92 {
			frame = append(frame, 0x42)
			binding.injected = true
		}
		binding.original = append(binding.original, len(packet))
		binding.delivered = append(binding.delivered, len(frame))
		binding.mu.Unlock()
		if err := binding.memoryBind.Send([][]byte{frame}, endpoint); err != nil {
			return err
		}
	}
	return nil
}
func TestActualMixedFramingOldPaddedREDMatchedFalseGREEN(t *testing.T) {
	for _, serverTrailers := range []bool{true, false} {
		name := "matched_false_GREEN"
		if serverTrailers {
			name = "old_fixture_true_default_client_false_RED"
		}
		t.Run(name, func(t *testing.T) {
			a := &memoryBind{incoming: make(chan []byte, 256), closed: make(chan struct{})}
			base := &memoryBind{incoming: make(chan []byte, 256), closed: make(chan struct{})}
			b := &framingObservedBind{memoryBind: base, forcePaddedFirst: serverTrailers}
			a.remote = base
			base.remote = a
			clientKey, clientPublic := keypair(t)
			serverKey, serverPublic := keypair(t)
			server, err := newPeerWithOptions(b, "172.29.172.253", serverKey, clientPublic, "10.244.0.2", "", peerOptions{RandomTrailers: serverTrailers})
			if err != nil {
				t.Fatal(err)
			}
			defer server.dev.Close()
			client, err := newPeerWithOptions(a, "10.244.0.2", clientKey, serverPublic, "172.29.172.253", "127.0.0.1:12345", peerOptions{RandomTrailers: false})
			if err != nil {
				t.Fatal(err)
			}
			defer client.dev.Close()
			payload := []byte(`{"owned_fixture":"framing_interop"}`)
			servers, err := servePeer(server, payload, "owned-interop")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				for _, s := range servers {
					_ = s.Close()
				}
			}()
			transport := &http.Transport{DialContext: client.network.DialContext}
			defer transport.CloseIdleConnections()
			timeout := 2 * time.Second
			if serverTrailers {
				timeout = 350 * time.Millisecond
			}
			httpClient := &http.Client{Transport: transport, Timeout: timeout}
			response, requestError := httpClient.Get("http://172.29.172.253:17864/rules.json")
			b.mu.Lock()
			if len(b.original) == 0 {
				b.mu.Unlock()
				t.Fatal("real responder sent no frame")
			}
			original, delivered, injected := b.original[0], b.delivered[0], b.injected
			b.mu.Unlock()
			state := observation(client)
			if state["random_trailers"] != "0" || state["disable_cookies"] != "1" || observation(server)["disable_cookies"] != "1" {
				t.Fatal("client mode/cookie policy changed")
			}
			if serverTrailers {
				if delivered <= 92 || requestError == nil || state["last_handshake_time_sec"] != "0" {
					t.Fatalf("old mismatch not reproduced: delivered=%d error=%v state=%v", delivered, requestError, state)
				}
			} else {
				if requestError != nil {
					t.Fatal(requestError)
				}
				raw, readError := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if readError != nil || string(raw) != string(payload) || original != 92 || delivered != 92 || injected || state["last_handshake_time_sec"] == "0" || state["rx_bytes"] == "0" {
					t.Fatal("matched real encrypted dataplane failed", state)
				}
			}
			t.Logf("mode=%s original_response=%d delivered_response=%d zero_random_tail_test_injection=%v actual_client_random_trailers=%s", name, original, delivered, injected, state["random_trailers"])
		})
	}
}

func TestFixtureClientFramingConfigBoolean(t *testing.T) {
	for _, text := range []string{`{"client_random_trailers":false}`, `{"client_random_trailers":true}`} {
		if _, err := decodeConfig([]byte(text)); err != nil { t.Fatal(err) }
	}
	for _, text := range []string{`{}`, `{"client_random_trailers":null}`, `{"client_random_trailers":"false"}`, `{"client_random_trailers":0}`, `{"client_random_trailers":false,"client_random_trailers":true}`} {
		if _, err := decodeConfig([]byte(text)); err == nil { t.Fatal("missing or ambiguous framing accepted", text) }
	}
	c, err := decodeConfig([]byte(`{"client_random_trailers":true}`))
	if err != nil || !c.ClientRandomTrailers { t.Fatal("true framing lost", c, err) }
}
