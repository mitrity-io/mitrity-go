package admission_test

import (
	"errors"
	"testing"
	"time"

	"github.com/mitrity-io/mitrity-go/admission"
)

func TestParseDurationAcceptsGoDurationsAndBareSeconds(t *testing.T) {
	cases := map[string]time.Duration{
		"500ms": 500 * time.Millisecond,
		"9m":    540 * time.Second,
		"1h30m": 5400 * time.Second,
		"1.5s":  1500 * time.Millisecond,
		"540":   540 * time.Second,
		"0":     0,
		"  2s ": 2 * time.Second,
		"-1s":   -time.Second,
		"+2":    2 * time.Second,
	}
	for value, want := range cases {
		if got := admission.ParseDuration(value, 99*time.Second); got != want {
			t.Errorf("ParseDuration(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestParseDurationFallsBackOnMalformedInput(t *testing.T) {
	// A misconfigured timeout must not crash a hook and leave a session ungoverned.
	for _, value := range []string{"garbage", "", "   ", "1x", "ms", "5m3", "1e3"} {
		if got := admission.ParseDuration(value, 7*time.Second); got != 7*time.Second {
			t.Errorf("ParseDuration(%q) = %v, want the fallback", value, got)
		}
	}
}

func TestSplitAddr(t *testing.T) {
	cases := []struct {
		addr    string
		network admission.Network
		address string
	}{
		{"unix:/run/mitrity/admission.sock", admission.NetworkUnix, "/run/mitrity/admission.sock"},
		{"unix:///tmp/a.sock", admission.NetworkUnix, "/tmp/a.sock"},
		{"/tmp/a.sock", admission.NetworkUnix, "/tmp/a.sock"},
		{"127.0.0.1:8777", admission.NetworkTCP, "127.0.0.1:8777"},
	}
	for _, c := range cases {
		network, address := admission.SplitAddr(c.addr)
		if network != c.network || address != c.address {
			t.Errorf("SplitAddr(%q) = (%q, %q), want (%q, %q)", c.addr, network, address, c.network, c.address)
		}
	}
}

func TestValidateAddrAcceptsLoopbackAndSockets(t *testing.T) {
	for _, addr := range []string{
		"unix:/run/mitrity/admission.sock",
		"/tmp/x.sock",
		"127.0.0.1:8777",
		"[::1]:8777",
		"localhost:8777",
	} {
		if err := admission.ValidateAddr(addr); err != nil {
			t.Errorf("ValidateAddr(%q) = %v, want nil", addr, err)
		}
	}
}

func TestValidateAddrRefusesRoutableAddresses(t *testing.T) {
	for _, addr := range []string{
		"0.0.0.0:8777",
		":8777",
		"10.0.0.5:8777",
		"example.com:80",
		"[2001:db8::1]:8777",
		"unix:",
		// URL-authority confusion: a loopback-looking prefix in front of another host.
		"localhost:8777@attacker.example",
		"127.0.0.1:8777@attacker.example:80",
		"127.0.0.1:8777/../x",
		"127.0.0.1:8777?x=1",
		"127.0.0.1:8777#f",
		"127.0.0.1",
		"127.0.0.1:abc",
		"127.0.0.1:0",
		"127.0.0.1:70000",
		"127.0.0.1:8777 ",
		" 127.0.0.1:8777",
		"[::1]:8777@attacker.example",
		"[::1%lo0]:8777",
		"127.000.000.001:8777",
	} {
		err := admission.ValidateAddr(addr)
		if !errors.Is(err, admission.ErrConfig) {
			t.Errorf("ValidateAddr(%q) = %v, want a config error", addr, err)
		}
	}
}

func TestFromEnvironReadsTheHookVariables(t *testing.T) {
	env := map[string]string{
		admission.EnvAddr:        "unix:/tmp/edge.sock",
		admission.EnvTokenFile:   "/tmp/edge.token",
		admission.EnvTimeout:     "250ms",
		admission.EnvHoldTimeout: "60",
	}
	cfg := admission.FromEnviron(func(k string) string { return env[k] })
	if cfg.Addr != "unix:/tmp/edge.sock" || cfg.TokenFile != "/tmp/edge.token" {
		t.Fatalf("unexpected addr/token: %+v", cfg)
	}
	if cfg.Timeout != 250*time.Millisecond || cfg.HoldTimeout != 60*time.Second {
		t.Fatalf("unexpected timeouts: %+v", cfg)
	}
	if cfg.Network() != admission.NetworkUnix || cfg.Address() != "/tmp/edge.sock" {
		t.Fatalf("unexpected network/address: %q %q", cfg.Network(), cfg.Address())
	}
}

func TestFromEnvironUsesPlatformDefaults(t *testing.T) {
	cfg := admission.FromEnviron(func(string) string { return "" })
	addr, token := admission.PlatformDefaults()
	if cfg.Addr != addr || cfg.TokenFile != token {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.Timeout != admission.DefaultTimeout || cfg.HoldTimeout != admission.DefaultHoldTimeout {
		t.Fatalf("unexpected default timeouts: %+v", cfg)
	}
}

func TestNormalizedClampsTimeoutsToTheHookCeilings(t *testing.T) {
	cfg := admission.Config{Addr: "unix:/x", TokenFile: "/t", Timeout: 10000 * time.Second, HoldTimeout: 10000 * time.Second}.Normalized()
	if cfg.Timeout != admission.MaxTimeout || cfg.HoldTimeout != admission.MaxHoldTimeout {
		t.Fatalf("not clamped: %+v", cfg)
	}
	zero := admission.Config{Addr: "unix:/x", TokenFile: "/t", Timeout: 0, HoldTimeout: -5 * time.Second}.Normalized()
	if zero.Timeout != admission.DefaultTimeout || zero.HoldTimeout != 0 {
		t.Fatalf("zero/negative not normalized: %+v", zero)
	}
}

func TestLocalhostIsASpellingOfTheIPv4LoopbackLiteral(t *testing.T) {
	// Never resolved: a hosts-file entry cannot point it off-box.
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"localhost:8777", "127.0.0.1", 8777},
		{"127.0.0.2:1", "127.0.0.2", 1},
		{"[::1]:8777", "::1", 8777},
	}
	for _, c := range cases {
		host, port, err := admission.ParseLoopbackAddr(c.in)
		if err != nil || host != c.host || port != c.port {
			t.Errorf("ParseLoopbackAddr(%q) = (%q, %d, %v), want (%q, %d)", c.in, host, port, err, c.host, c.port)
		}
	}
}
