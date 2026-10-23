package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type config struct {
	RunID         string `json:"run_id"`
	CaseID        string `json:"case_id"`
	VMID          string `json:"vm_id"`
	Nonce         string `json:"nonce"`
	Marker        string `json:"marker"`
	Routes        string `json:"routes"`
	RoutesSHA     string `json:"routes_sha256"`
	SourcePrivate string `json:"source_private_key"`
	TargetPrivate string `json:"target_private_key"`
	ClientPublic  string `json:"client_public_key"`
	ClientAddress string `json:"client_address"`
	TTLSeconds    int    `json:"ttl_seconds"`
}

var safeID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}$`)
var noncePattern = regexp.MustCompile(`^[a-f0-9]{48}$`)
var vmPattern = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)

func decodeConfig(b []byte) (config, error) {
	var c config
	d := json.NewDecoder(bytes.NewReader(b))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return c, errors.New("config object required")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return c, errors.New("invalid config key")
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return c, errors.New("duplicate config key")
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return c, errors.New("invalid config value")
		}
	}
	if _, err = d.Token(); err != nil {
		return c, errors.New("truncated config")
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return c, errors.New("trailing config document")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, errors.New("invalid config fields")
	}
	return c, nil
}

func validateConfig(c config, root string) error {
	if !safeID.MatchString(c.RunID) || !safeID.MatchString(c.CaseID) || !noncePattern.MatchString(c.Nonce) || !vmPattern.MatchString(c.VMID) || c.TTLSeconds < 1 || c.TTLSeconds > 300 {
		return errors.New("invalid ownership identity or TTL")
	}
	expected := filepath.Join(`C:\ProgramData\AmneziaLab\runs`, c.RunID, "windows-x64", c.CaseID, "netstack-fixture")
	if !strings.EqualFold(filepath.Clean(root), expected) {
		return errors.New("noncanonical guest root")
	}
	if !strings.EqualFold(filepath.Clean(c.Marker), filepath.Join(filepath.Dir(expected), "run-marker.txt")) {
		return errors.New("foreign marker path")
	}
	if !strings.EqualFold(filepath.Clean(c.Routes), filepath.Join(expected, "routes.json")) {
		return errors.New("foreign routes path")
	}
	for _, path := range []string{root, c.Marker, c.Routes} {
		for current := filepath.Clean(path); ; current = filepath.Dir(current) {
			info, err := os.Lstat(current)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("unsafe guest path")
			}
			if filepath.Dir(current) == current {
				break
			}
		}
	}
	marker, err := os.ReadFile(c.Marker)
	if err != nil {
		return errors.New("guest marker unavailable")
	}
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(string(marker), "\r\n", "\n")), "\n")
	if len(lines) != 4 {
		return errors.New("unexpected guest marker fields")
	}
	for _, line := range []string{"amnezia-release-lab:" + c.RunID + ":windows-x64", "backend=hyperv", "case_id=" + c.CaseID, "vm_id=" + c.VMID} {
		count := 0
		for _, v := range lines {
			if v == line {
				count++
			}
		}
		if count != 1 {
			return errors.New("guest marker binding mismatch")
		}
	}
	return nil
}
func exclusiveJSON(path string, value any) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = f.Write(append(b, '\n'))
	return e
}
func run(configPath string) error {
	// Host execution is forbidden by operator policy; there is intentionally no
	// self-test flag or flag allowing the guest-root/marker guards to be disabled.
	if runtime.GOOS != "windows" {
		return errors.New("Windows guest only")
	}
	b, e := os.ReadFile(configPath)
	if e != nil {
		return e
	}
	c, e := decodeConfig(b)
	if e != nil {
		return errors.New("invalid config")
	}
	root := filepath.Dir(configPath)
	if filepath.Base(configPath) != "config.json" {
		return errors.New("noncanonical config name")
	}
	if info, err := os.Lstat(configPath); err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe config path")
	}
	if e = validateConfig(c, root); e != nil {
		return e
	}
	routes, e := os.ReadFile(c.Routes)
	if e != nil || digest(routes) != c.RoutesSHA {
		return errors.New("route bytes changed")
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	exeBytes, e := os.ReadFile(exe)
	if e != nil {
		return e
	}
	start, e := processStartIdentity()
	if e != nil {
		return errors.New("process identity unavailable")
	}
	lease := filepath.Join(root, "lease.json")
	identity := map[string]any{"schema": 1, "run_id": c.RunID, "case_id": c.CaseID, "vm_id": c.VMID, "nonce": c.Nonce, "pid": os.Getpid(), "process_start_unix_ns": start, "created_at": time.Now().UTC(), "exe_sha256": digest(exeBytes), "routes_sha256": c.RoutesSHA, "production_journal": false, "runtime_pass": false}
	if e = exclusiveJSON(lease, identity); e != nil {
		return errors.New("lease exists or cannot be reserved")
	}
	// Lease remains as an immutable attempt receipt. The disposable guest owner
	// performs cleanup; this helper never kills another PID or removes a lease.
	source, e := newPeer(&udpBind{}, "172.29.172.253", c.SourcePrivate, c.ClientPublic, c.ClientAddress, "")
	if e != nil {
		return e
	}
	defer source.dev.Close()
	target, e := newPeer(&udpBind{}, "172.29.172.253", c.TargetPrivate, c.ClientPublic, c.ClientAddress, "")
	if e != nil {
		return e
	}
	defer target.dev.Close()
	sp, e := peerPort(source)
	if e != nil {
		return e
	}
	tp, e := peerPort(target)
	if e != nil {
		return e
	}
	servers, e := servePeer(source, routes, c.Nonce)
	if e != nil {
		return e
	}
	defer func() {
		for _, s := range servers {
			_ = s.Close()
		}
	}()
	targetServers, e := servePeer(target, routes, c.Nonce)
	if e != nil {
		return e
	}
	defer func() {
		for _, s := range targetServers {
			_ = s.Close()
		}
	}()
	identity["source_udp_port"] = sp
	identity["target_udp_port"] = tp
	identity["ready"] = true
	if e = exclusiveJSON(filepath.Join(root, "ready.json"), identity); e != nil {
		return e
	}
	time.Sleep(time.Duration(c.TTLSeconds) * time.Second)
	identity["source_observation"] = observation(source)
	identity["target_observation"] = observation(target)
	identity["terminal_state"] = "closed_by_owned_process"
	source.dev.Close()
	target.dev.Close()
	return exclusiveJSON(filepath.Join(root, "terminal.json"), identity)
}
func main() {
	p := flag.String("config", "", "owned guest config")
	flag.Parse()
	if *p == "" {
		fmt.Fprintln(os.Stderr, "config required")
		os.Exit(2)
	}
	if err := run(*p); err != nil {
		fmt.Fprintln(os.Stderr, "fixture failed; inspect private guest diagnostics")
		os.Exit(1)
	}
}
