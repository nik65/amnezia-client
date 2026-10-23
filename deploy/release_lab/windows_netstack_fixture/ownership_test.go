package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLeaseNeverOverwritesExistingAttempt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease.json")
	if e := exclusiveJSON(path, map[string]string{"nonce": "first"}); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = exclusiveJSON(path, map[string]string{"nonce": "second"}); e == nil {
		t.Fatal("existing lease overwritten")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("foreign lease modified")
	}
}
func TestOwnershipRejectsBeforeAnySocket(t *testing.T) {
	valid := config{RunID: "run", CaseID: "case", Nonce: "0123456789abcdef0123456789abcdef0123456789abcdef", VMID: "a32279c3-a500-4ed4-80ff-c3b72600e18c", TTLSeconds: 10}
	for _, mutate := range []func(*config){
		func(c *config) { c.RunID = "../escape" }, func(c *config) { c.CaseID = "../escape" },
		func(c *config) { c.Nonce = "" }, func(c *config) { c.VMID = "foreign" }, func(c *config) { c.TTLSeconds = 301 },
	} {
		candidate := valid
		mutate(&candidate)
		if validateConfig(candidate, t.TempDir()) == nil {
			t.Fatal("invalid ownership accepted")
		}
	}
	if validateConfig(valid, t.TempDir()) == nil {
		t.Fatal("noncanonical host root accepted")
	}
}

func TestPrivateConfigJSONRejectsAmbiguousOrUnknownFields(t *testing.T) {
	for _, text := range []string{`{"run_id":"a","run_id":"b"}`, `{"run_id":"a"} {}`, `{"run_id":"a"} trailing`, `{"unknown":1}`, `null`, `[]`, `{"run_id":3}`} {
		if _, err := decodeConfig([]byte(text)); err == nil {
			t.Fatal("ambiguous config accepted")
		}
	}
	if c, err := decodeConfig([]byte(`{"run_id":"a"}`)); err != nil || c.RunID != "a" {
		t.Fatal("valid JSON rejected")
	}
}
