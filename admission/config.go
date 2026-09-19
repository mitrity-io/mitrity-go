package admission

import (
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// The hook's environment variables. An adapter finds the edge the way
// mitrity-hook does, so one provisioning step serves both.
const (
	EnvAddr        = "MITRITY_ADMISSION_ADDR"
	EnvTokenFile   = "MITRITY_ADMISSION_TOKEN_FILE" //nolint:gosec // the name of the variable that holds the path, not a credential
	EnvTimeout     = "MITRITY_HOOK_TIMEOUT"
	EnvHoldTimeout = "MITRITY_HOOK_HOLD_TIMEOUT"
	// EnvFailMode is read for documentation's sake and deliberately ignored:
	// adapters have no fail-open mode (adapters.md, G2).
	EnvFailMode = "MITRITY_HOOK_FAIL_MODE"
)

const (
	// DefaultTimeout is the deadline for one decision. The cached-policy path
	// on the edge is sub-millisecond.
	DefaultTimeout = 500 * time.Millisecond
	// MaxTimeout is the ceiling for one decision.
	MaxTimeout = 30 * time.Second
	// DefaultHoldTimeout is how long to wait on a human approval. 0 disables
	// waiting.
	DefaultHoldTimeout = 540 * time.Second
	// MaxHoldTimeout is sized against the framework's own 600 s hook budget,
	// as for the hook.
	MaxHoldTimeout = 570 * time.Second
	// HoldMargin is headroom over the hold budget so the edge's own long-poll
	// can answer first.
	HoldMargin = 5 * time.Second
	// AttestTimeout is the deadline for POST /v1/attest. Nothing is blocked on
	// it, so it may be longer.
	AttestTimeout = 5 * time.Second
)

// Network is how the edge is reached: a Unix socket or loopback TCP.
type Network string

const (
	NetworkUnix Network = "unix"
	NetworkTCP  Network = "tcp"
)

var (
	bareNumber = regexp.MustCompile(`^[+-]?(\d+(\.\d*)?|\.\d+)$`)
	// A loopback address is exactly host:port — no userinfo, path, query,
	// fragment or whitespace, so nothing an HTTP client could read as a
	// different authority.
	tcpAddr = regexp.MustCompile(`^(?:\[([0-9A-Fa-f:.]+)\]|([0-9A-Za-z.\-]+)):(\d{1,5})$`)
)

// PlatformDefaults returns the admission address and token path a standard
// install uses on this platform: a Unix socket wherever one can be dialed,
// loopback TCP on Windows, where the edge listens on a port because Go cannot
// dial a named pipe.
func PlatformDefaults() (addr, tokenFile string) {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("PROGRAMDATA")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return "127.0.0.1:8777", filepath.Join(programData, "Mitrity", "admission.token")
	}
	return "unix:/run/mitrity/admission.sock", "/run/mitrity/admission.token"
}

// ParseDuration parses a Go duration ("500ms", "9m", "1h30m") or a bare number
// of seconds ("540", "1.5").
//
// Malformed input falls back rather than failing: a misconfigured timeout
// must not become a crashed hook and an ungoverned session. Mirrors the hook's
// durationOr.
func ParseDuration(value string, fallback time.Duration) time.Duration {
	text := strings.TrimSpace(value)
	if text == "" {
		return fallback
	}
	if bareNumber.MatchString(text) {
		seconds, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return fallback
		}
		return secondsToDuration(seconds)
	}
	d, err := time.ParseDuration(text)
	if err != nil {
		return fallback
	}
	return d
}

func secondsToDuration(seconds float64) time.Duration {
	nanos := seconds * float64(time.Second)
	switch {
	case nanos >= math.MaxInt64:
		return time.Duration(math.MaxInt64)
	case nanos <= math.MinInt64:
		return time.Duration(math.MinInt64)
	}
	return time.Duration(nanos)
}

// SplitAddr splits a configured address into the network and the dial
// address, as the edge does: a "unix:" or "unix://" prefix or an absolute path
// is a Unix socket; anything else is TCP.
func SplitAddr(addr string) (Network, string) {
	switch {
	case strings.HasPrefix(addr, "unix://"):
		return NetworkUnix, strings.TrimPrefix(addr, "unix://")
	case strings.HasPrefix(addr, "unix:"):
		return NetworkUnix, strings.TrimPrefix(addr, "unix:")
	case strings.HasPrefix(addr, "/"):
		return NetworkUnix, addr
	}
	return NetworkTCP, addr
}

// ParseLoopbackAddr parses a loopback host:port strictly, returning the
// literal host and the port.
//
// The address is parsed, never sliced: "localhost:8777@attacker.example" has
// a loopback-looking prefix and an HTTP client would connect to the host after
// the "@". Only host:port is accepted, the host must be a loopback IP literal
// — "localhost" is taken as a spelling of 127.0.0.1 and never resolved, so a
// hosts-file entry cannot point it off-box — and the port must be a number.
func ParseLoopbackAddr(address string) (host string, port int, err error) {
	m := tcpAddr.FindStringSubmatch(address)
	if m == nil {
		return "", 0, newError(KindConfig, fmt.Sprintf(
			"%s=%q is not a plain host:port: the admission address may carry no userinfo, path, query, fragment or whitespace",
			EnvAddr, address))
	}
	host = m[1]
	if host == "" {
		host = m[2]
	}
	port, err = strconv.Atoi(m[3])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, newError(KindConfig, fmt.Sprintf("%s=%q has an invalid port", EnvAddr, address))
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", 0, newError(KindConfig, fmt.Sprintf(
			"%s=%q is neither loopback nor a Unix socket: the admission API carries the command this agent is about to run and its token, and a routable address would send both to whatever answers there",
			EnvAddr, address))
	}
	return ip.String(), port, nil
}

// ValidateAddr refuses an address that is neither loopback nor a Unix socket.
//
// The admission API carries the command the agent is about to run and the
// token that authorizes judging it. A routable address would send both, in
// cleartext, to whatever answers there — and then act on its answer. The check
// is the hook's, applied before any I/O.
func ValidateAddr(addr string) error {
	network, address := SplitAddr(addr)
	if network == NetworkUnix {
		if address == "" {
			return newError(KindConfig, fmt.Sprintf("%s=%q names no socket path", EnvAddr, addr))
		}
		return nil
	}
	_, _, err := ParseLoopbackAddr(address)
	return err
}

// Config says where the edge is and how long to wait for it.
//
// Explicit values win over the environment; the environment wins over the
// platform defaults. Timeouts are clamped to the same ceilings the hook
// applies, for the same reason: past the framework's own hook budget a patient
// adapter is an irrelevant one.
type Config struct {
	// Addr is the edge's admission listener: "unix:/path.sock", an absolute
	// socket path, or a loopback host:port.
	Addr string
	// TokenFile is the per-process token the edge writes at startup. Read on
	// every attempt.
	TokenFile string
	// Timeout is the deadline for one decision (DefaultTimeout when zero,
	// clamped to MaxTimeout).
	Timeout time.Duration
	// HoldTimeout is the budget of the second call of a hold (DefaultHoldTimeout
	// when unset by FromEnv; 0 disables waiting; clamped to MaxHoldTimeout).
	HoldTimeout time.Duration
}

// FromEnv builds a configuration from the hook's environment variables,
// falling back to the platform defaults.
func FromEnv() Config {
	return FromEnviron(os.Getenv)
}

// FromEnviron is FromEnv over an explicit lookup function (nil reads the
// process environment).
func FromEnviron(lookup func(string) string) Config {
	if lookup == nil {
		lookup = os.Getenv
	}
	defaultAddr, defaultToken := PlatformDefaults()
	addr := strings.TrimSpace(lookup(EnvAddr))
	if addr == "" {
		addr = defaultAddr
	}
	token := strings.TrimSpace(lookup(EnvTokenFile))
	if token == "" {
		token = defaultToken
	}
	return Config{
		Addr:        addr,
		TokenFile:   token,
		Timeout:     ParseDuration(lookup(EnvTimeout), DefaultTimeout),
		HoldTimeout: ParseDuration(lookup(EnvHoldTimeout), DefaultHoldTimeout),
	}.Normalized()
}

// Normalized returns the configuration with the timeouts clamped to the hook's
// ceilings: a zero or negative Timeout becomes DefaultTimeout, a negative
// HoldTimeout becomes 0.
func (c Config) Normalized() Config {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.Timeout > MaxTimeout {
		c.Timeout = MaxTimeout
	}
	if c.HoldTimeout < 0 {
		c.HoldTimeout = 0
	}
	if c.HoldTimeout > MaxHoldTimeout {
		c.HoldTimeout = MaxHoldTimeout
	}
	return c
}

// Network is the network of Addr.
func (c Config) Network() Network {
	network, _ := SplitAddr(c.Addr)
	return network
}

// Address is the dial address of Addr: the socket path or the host:port.
func (c Config) Address() string {
	_, address := SplitAddr(c.Addr)
	return address
}
