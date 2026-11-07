package main
import "testing"
func TestFixtureConfigCaseAliasesRejected(t *testing.T) {
 for _, text := range []string{`{"client_random_trailers":false,"CLIENT_RANDOM_TRAILERS":true}`, `{"client_random_trailers":false,"Client_Random_Trailers":null}`} {
  c, err := decodeConfig([]byte(text)); if err == nil {t.Fatalf("case alias accepted and may override mode: %v", c.ClientRandomTrailers)}
 }
}
