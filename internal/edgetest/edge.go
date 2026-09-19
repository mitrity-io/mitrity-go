// Package edgetest is an in-process fake of the admission API, served over a
// Unix socket, for this module's tests.
//
// It speaks exactly the wire shape of iag-specs sentinel/admission-api.md and
// nothing more: token header, version header, /v1/admit, /v1/attest,
// /healthz. Responses are scripted per test; every request is recorded so a
// test can assert what the adapter sent — and, just as often, what it did
// not.
package edgetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Header names, spelled here independently of the package under test.
const (
	HeaderToken   = "X-Mitrity-Admission-Token" //nolint:gosec // a header name, not a credential
	HeaderVersion = "X-Mitrity-Admission-Version"
)

// Recorded is one request the fake edge received.
type Recorded struct {
	Method string
	Path   string
	// Host is the request's Host header (Go's server keeps it out of Header).
	Host   string
	Header http.Header
	// Body is the parsed JSON body (nil when empty or not JSON); Raw is the
	// bytes as received.
	Body map[string]any
	Raw  []byte
}

// HoldBudget returns the hold_timeout_seconds of an admit request, or -1
// when the field is absent.
func (r Recorded) HoldBudget() int {
	v, ok := r.Body["hold_timeout_seconds"].(float64)
	if !ok {
		return -1
	}
	return int(v)
}

// Scripted is one scripted response. Body may be a map (JSON), []byte
// (verbatim) or nil (empty).
type Scripted struct {
	Status int
	Body   any
	Delay  time.Duration
	// Version is the X-Mitrity-Admission-Version to send ("1" when empty);
	// OmitVersion sends none.
	Version     string
	OmitVersion bool
	// ContentType is sent when the body is non-empty ("application/json"
	// when empty); OmitContentType sends none.
	ContentType     string
	OmitContentType bool
}

// Respond implements Response.
func (s Scripted) Respond(Recorded) Scripted { return s }

// Response produces a Scripted for a recorded request.
type Response interface {
	Respond(Recorded) Scripted
}

// ResponderFunc adapts a function to Response.
type ResponderFunc func(Recorded) Scripted

// Respond implements Response.
func (f ResponderFunc) Respond(r Recorded) Scripted { return f(r) }

// Allow is a scripted allow; extra overrides or adds body fields.
func Allow(extra map[string]any) Scripted {
	body := map[string]any{
		"decision":      "allow",
		"reason":        "allowed",
		"approval_id":   nil,
		"risk_score":    0.1,
		"admission_id":  "adm-allow",
		"updated_input": nil,
	}
	for k, v := range extra {
		body[k] = v
	}
	return Scripted{Status: 200, Body: body}
}

// DenyReason is the default policy reason of Deny.
const DenyReason = `policy rule "no destructive commands" denied resolved command: rm`

// Deny is a scripted deny with the given reason (DenyReason when empty).
func Deny(reason string) Scripted {
	if reason == "" {
		reason = DenyReason
	}
	return Scripted{Status: 200, Body: map[string]any{
		"decision":      "deny",
		"reason":        reason,
		"approval_id":   nil,
		"risk_score":    0.9,
		"admission_id":  "adm-deny",
		"updated_input": nil,
	}}
}

// Held is a scripted held decision naming approvalID ("apr-1" when empty).
func Held(approvalID string) Scripted {
	if approvalID == "" {
		approvalID = "apr-1"
	}
	return Scripted{Status: 200, Body: map[string]any{
		"decision":      "held",
		"reason":        "policy requires human approval",
		"approval_id":   approvalID,
		"risk_score":    0.5,
		"admission_id":  "adm-held",
		"updated_input": nil,
	}}
}

// HoldScript answers held to a no-wait request and Outcome to the waiting one.
type HoldScript struct {
	Outcome    Scripted
	Wait       time.Duration
	ApprovalID string
}

// Respond implements Response.
func (h HoldScript) Respond(r Recorded) Scripted {
	approval := h.ApprovalID
	if approval == "" {
		approval = "apr-hold"
	}
	if r.HoldBudget() == 0 {
		return Held(approval)
	}
	out := h.Outcome
	if out.Status == 0 {
		out = Allow(nil)
	}
	out.Delay = h.Wait
	return out
}

// Edge is the fake edge. Start one with New; use Addr and TokenFile for the
// client.
type Edge struct {
	t          testing.TB
	dir        string
	SocketPath string
	TokenFile  string
	server     *httptest.Server

	mu                  sync.Mutex
	token               string
	requests            []Recorded
	script              []Response
	defaultAdmit        Response
	defaultAttest       Scripted
	defaultHealth       Scripted
	rotateOnNextRequest bool
	rejectAllTokens     bool
}

// New starts a fake edge on a fresh Unix socket and registers its cleanup.
func New(t testing.TB) *Edge {
	t.Helper()
	// AF_UNIX paths are capped at 104 bytes on macOS (108 on Linux), and a
	// t.TempDir() path can be longer than that; the socket lives in a short
	// directory of its own.
	dir, err := os.MkdirTemp("", "me-")
	if err != nil {
		t.Fatalf("edgetest: temp dir: %v", err)
	}
	e := &Edge{
		t:             t,
		dir:           dir,
		SocketPath:    filepath.Join(dir, "admission.sock"),
		TokenFile:     filepath.Join(dir, "admission.token"),
		defaultAdmit:  Allow(nil),
		defaultAttest: Scripted{Status: 204},
		defaultHealth: Scripted{Status: 200, Body: map[string]any{"status": "ok", "profile_age_seconds": 3}},
	}
	e.token = e.writeToken()
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", e.SocketPath)
	if err != nil {
		t.Fatalf("edgetest: listen: %v", err)
	}
	e.server = httptest.NewUnstartedServer(http.HandlerFunc(e.serve))
	_ = e.server.Listener.Close()
	e.server.Listener = listener
	e.server.Start()
	t.Cleanup(e.Close)
	return e
}

// Close stops the fake edge and removes its files.
func (e *Edge) Close() {
	e.server.Close()
	_ = os.RemoveAll(e.dir)
}

// Addr is the client's MITRITY_ADMISSION_ADDR for this edge.
func (e *Edge) Addr() string { return "unix:" + e.SocketPath }

// Token is the token the edge currently accepts.
func (e *Edge) Token() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.token
}

// Script queues responses for the next /v1/admit calls, in order.
func (e *Edge) Script(responses ...Response) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.script = append(e.script, responses...)
}

// SetDefaultAdmit sets the response for /v1/admit when nothing is scripted.
func (e *Edge) SetDefaultAdmit(r Response) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.defaultAdmit = r
}

// SetDefaultAttest sets the response for /v1/attest.
func (e *Edge) SetDefaultAttest(s Scripted) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.defaultAttest = s
}

// SetRotateOnNextRequest makes the edge mint a new token right before it
// checks the next request, as an edge restart would (so the presented token
// is stale).
func (e *Edge) SetRotateOnNextRequest(v bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rotateOnNextRequest = v
}

// SetRejectAllTokens makes the edge answer 401 whatever token is presented.
func (e *Edge) SetRejectAllTokens(v bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rejectAllTokens = v
}

// RotateToken mints a new token, as an edge restart does. The old one is
// rejected from now on.
func (e *Edge) RotateToken() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.token = e.writeToken()
	return e.token
}

// Requests returns every request received so far.
func (e *Edge) Requests() []Recorded {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Recorded, len(e.requests))
	copy(out, e.requests)
	return out
}

// Admits returns the /v1/admit requests received so far.
func (e *Edge) Admits() []Recorded { return e.byPath("/v1/admit") }

// Attests returns the /v1/attest requests received so far.
func (e *Edge) Attests() []Recorded { return e.byPath("/v1/attest") }

func (e *Edge) byPath(path string) []Recorded {
	var out []Recorded
	for _, r := range e.Requests() {
		if r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

func (e *Edge) writeToken() string {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		e.t.Fatalf("edgetest: random token: %v", err)
	}
	token := "tok-" + hex.EncodeToString(raw)
	if err := os.WriteFile(e.TokenFile, []byte(token+"\n"), 0o600); err != nil {
		e.t.Fatalf("edgetest: write token: %v", err)
	}
	return token
}

func (e *Edge) serve(w http.ResponseWriter, req *http.Request) {
	raw, _ := readAll(req)
	recorded := Recorded{Method: req.Method, Path: req.URL.Path, Host: req.Host, Header: req.Header.Clone(), Raw: raw}
	if len(raw) > 0 {
		var body map[string]any
		if json.Unmarshal(raw, &body) == nil {
			recorded.Body = body
		}
	}
	e.mu.Lock()
	e.requests = append(e.requests, recorded)
	e.mu.Unlock()

	response := e.respond(recorded)
	if response.Delay > 0 {
		time.Sleep(response.Delay)
	}
	var payload []byte
	switch body := response.Body.(type) {
	case nil:
	case []byte:
		payload = body
	default:
		payload, _ = json.Marshal(body)
	}
	if !response.OmitVersion {
		version := response.Version
		if version == "" {
			version = "1"
		}
		w.Header().Set(HeaderVersion, version)
	}
	if len(payload) > 0 && !response.OmitContentType {
		contentType := response.ContentType
		if contentType == "" {
			contentType = "application/json"
		}
		w.Header().Set("Content-Type", contentType)
	}
	status := response.Status
	if status == 0 {
		status = 200
	}
	w.WriteHeader(status)
	if len(payload) > 0 {
		_, _ = w.Write(payload)
	}
}

func readAll(req *http.Request) ([]byte, error) {
	defer req.Body.Close()
	return io.ReadAll(req.Body)
}

func (e *Edge) respond(r Recorded) Scripted {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r.Path == "/healthz" {
		return e.defaultHealth
	}
	if e.rotateOnNextRequest {
		e.rotateOnNextRequest = false
		e.token = e.writeToken()
	}
	if e.rejectAllTokens || r.Header.Get(HeaderToken) != e.token {
		return Scripted{Status: 401}
	}
	if version := r.Header.Get(HeaderVersion); version != "1" {
		return Scripted{Status: 400, Body: map[string]any{"error": HeaderVersion + ` must be "1", got "` + version + `"`}}
	}
	switch r.Path {
	case "/v1/attest":
		return e.defaultAttest
	case "/v1/admit":
		var next Response
		if len(e.script) > 0 {
			next, e.script = e.script[0], e.script[1:]
		} else {
			next = e.defaultAdmit
		}
		return next.Respond(r)
	}
	return Scripted{Status: 404, Body: map[string]any{"error": "not found"}}
}
