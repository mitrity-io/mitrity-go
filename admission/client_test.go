package admission_test

// Conformance C1–C3, C6, C14, C15, C16, C17, C19: the wire client.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mitrity-io/mitrity-go/admission"
	"github.com/mitrity-io/mitrity-go/internal/edgetest"
)

var request = admission.Request{Surface: admission.SurfaceCustom, ToolName: "Bash", ToolInput: map[string]any{"command": "ls -la"}}

func newClient(t *testing.T, edge *edgetest.Edge, opts ...admission.Option) *admission.Client {
	t.Helper()
	base := []admission.Option{
		admission.WithAddr(edge.Addr()),
		admission.WithTokenFile(edge.TokenFile),
		admission.WithTimeout(500 * time.Millisecond),
		admission.WithHoldTimeout(2 * time.Second),
	}
	return admission.NewWithConfig(admission.Config{}, append(base, opts...)...)
}

func TestC1EveryRequestCarriesTokenVersionAndContentType(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	decision, err := client.Admit(t.Context(), request)
	if err != nil || !decision.Allowed() {
		t.Fatalf("admit: %v %+v", err, decision)
	}
	req := edge.Admits()[0]
	if got := req.Header.Get(edgetest.HeaderToken); got != edge.Token() {
		t.Errorf("token header = %q, want the file's contents", got)
	}
	if got := req.Header.Get(edgetest.HeaderVersion); got != admission.ProtocolVersion {
		t.Errorf("version header = %q", got)
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type = %q", got)
	}
	if req.Host != "mitrity-admission" {
		t.Errorf("host header = %q", req.Host)
	}
	want := map[string]any{"surface": "custom", "tool_name": "Bash", "tool_input": map[string]any{"command": "ls -la"}}
	if !reflect.DeepEqual(req.Body, want) {
		t.Errorf("body = %v, want %v", req.Body, want)
	}
}

func TestC19ProtocolVersionConstantIsWhatIsSent(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	if err := client.Attest(t.Context(), admission.Attestation{Framework: "custom", Adapter: "mitrity-go", AdapterVersion: "0.0.0"}); err != nil {
		t.Fatal(err)
	}
	if got := edge.Attests()[0].Header.Get(edgetest.HeaderVersion); got != admission.ProtocolVersion || admission.ProtocolVersion != "1" {
		t.Fatalf("version header = %q", got)
	}
}

func TestC2TokenIsRereadAndRetriedExactlyOnceOn401(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	stale := edge.Token()
	edge.SetRotateOnNextRequest(true)
	decision, err := client.Admit(t.Context(), request)
	if err != nil || !decision.Allowed() {
		t.Fatalf("admit: %v", err)
	}
	var presented []string
	for _, r := range edge.Admits() {
		presented = append(presented, r.Header.Get(edgetest.HeaderToken))
	}
	if want := []string{stale, edge.Token()}; !reflect.DeepEqual(presented, want) {
		t.Fatalf("presented tokens %v, want %v", presented, want)
	}
}

func TestC2Second401IsADeny(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	edge.SetRejectAllTokens(true)
	_, err := client.Admit(t.Context(), request)
	if !errors.Is(err, admission.ErrUnauthorized) {
		t.Fatalf("err = %v, want unauthorized", err)
	}
	if n := len(edge.Admits()); n != 2 {
		t.Fatalf("%d admits, want exactly 2", n)
	}
}

func TestC3RoutableAddressIsRefusedBeforeAnyIO(t *testing.T) {
	edge := edgetest.New(t)
	client := admission.NewWithConfig(admission.Config{Addr: "10.0.0.5:8777", TokenFile: edge.TokenFile})
	if _, err := client.Admit(t.Context(), request); !errors.Is(err, admission.ErrConfig) {
		t.Fatalf("err = %v, want config error", err)
	}
	verdict := client.Decide(t.Context(), request)
	if verdict.Allowed || !errors.Is(verdict.Err, admission.ErrConfig) {
		t.Fatalf("verdict = %+v", verdict)
	}
	if len(edge.Requests()) != 0 {
		t.Fatal("the fake edge saw a request")
	}
}

func TestMissingTokenFileIsUnreachable(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge, admission.WithTokenFile(filepath.Join(t.TempDir(), "absent.token")))
	_, err := client.Admit(t.Context(), request)
	if !errors.Is(err, admission.ErrUnreachable) {
		t.Fatalf("err = %v, want unreachable", err)
	}
	if len(edge.Requests()) != 0 {
		t.Fatal("the fake edge saw a request")
	}
}

func TestEmptyTokenFileIsUnreachable(t *testing.T) {
	edge := edgetest.New(t)
	empty := filepath.Join(t.TempDir(), "empty.token")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := newClient(t, edge, admission.WithTokenFile(empty))
	if _, err := client.Admit(t.Context(), request); !errors.Is(err, admission.ErrUnreachable) {
		t.Fatalf("err = %v, want unreachable", err)
	}
}

func TestNoTokenPathIsAConfigError(t *testing.T) {
	edge := edgetest.New(t)
	client := admission.NewWithConfig(admission.Config{Addr: edge.Addr()})
	if _, err := client.Admit(t.Context(), request); !errors.Is(err, admission.ErrConfig) {
		t.Fatalf("err = %v, want config error", err)
	}
}

func TestC6EveryNonDecisionIsTheMatchingError(t *testing.T) {
	cases := []struct {
		name     string
		scripted edgetest.Scripted
		want     error
	}{
		{"400", edgetest.Scripted{Status: 400, Body: map[string]any{"error": "unknown surface"}}, admission.ErrProtocol},
		{"503", edgetest.Scripted{Status: 503, Body: map[string]any{"decision": "deny", "reason": "no_profile"}}, admission.ErrNotReady},
		{"empty body", edgetest.Scripted{Status: 200, Body: []byte("")}, admission.ErrProtocol},
		{"not json", edgetest.Scripted{Status: 200, Body: []byte("not json")}, admission.ErrProtocol},
		{"unknown decision", edgetest.Scripted{Status: 200, Body: map[string]any{"decision": "maybe", "reason": "x"}}, admission.ErrProtocol},
		{"version 2", edgetest.Scripted{Status: 200, Body: edgetest.Allow(nil).Body, Version: "2"}, admission.ErrProtocol},
		{"no version header", edgetest.Scripted{Status: 200, Body: edgetest.Allow(nil).Body, OmitVersion: true}, admission.ErrProtocol},
		{"array body", edgetest.Scripted{Status: 200, Body: []byte("[1,2]")}, admission.ErrProtocol},
		{"500", edgetest.Scripted{Status: 500, Body: []byte("boom")}, admission.ErrProtocol},
		{"302", edgetest.Scripted{Status: 302, Body: []byte("")}, admission.ErrProtocol},
		{"risk_score bool", edgetest.Scripted{Status: 200, Body: map[string]any{"decision": "allow", "risk_score": true}}, admission.ErrProtocol},
		{"updated_input string", edgetest.Scripted{Status: 200, Body: map[string]any{"decision": "allow", "updated_input": "x"}}, admission.ErrProtocol},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			edge := edgetest.New(t)
			client := newClient(t, edge)
			edge.Script(c.scripted, c.scripted)
			_, err := client.Admit(t.Context(), request)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			verdict := client.Decide(t.Context(), request)
			if verdict.Allowed || verdict.Err == nil {
				t.Fatalf("decide should deny with the error set: %+v", verdict)
			}
		})
	}
}

func TestC6NotReadyCarriesTheEdgeReason(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	edge.Script(edgetest.Scripted{Status: 503, Body: map[string]any{"decision": "deny", "reason": "no_profile: not primed"}})
	_, err := client.Admit(t.Context(), request)
	if !errors.Is(err, admission.ErrNotReady) || !strings.Contains(err.Error(), "no_profile: not primed") {
		t.Fatalf("err = %v", err)
	}
}

func TestC14OversizedInputIsDeniedWithoutSending(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	huge := admission.Request{Surface: admission.SurfaceCustom, ToolName: "Write", ToolInput: map[string]any{"content": strings.Repeat("x", 70*1024)}}
	_, err := client.Admit(t.Context(), huge)
	if !errors.Is(err, admission.ErrPayloadTooLarge) || !errors.Is(err, admission.ErrProtocol) {
		t.Fatalf("err = %v, want payload too large (a protocol error)", err)
	}
	verdict := client.Decide(t.Context(), huge)
	if verdict.Allowed || !strings.Contains(verdict.Reason, "larger than MITRITY will judge") {
		t.Fatalf("verdict = %+v", verdict)
	}
	if len(edge.Requests()) != 0 {
		t.Fatal("the fake edge saw a request")
	}
}

func TestC15FailModeOpenChangesNothing(t *testing.T) {
	edge := edgetest.New(t)
	t.Setenv(admission.EnvFailMode, "open")
	t.Setenv(admission.EnvAddr, "unix:"+filepath.Join(t.TempDir(), "nobody-listens.sock"))
	t.Setenv(admission.EnvTokenFile, edge.TokenFile)
	client := admission.New()
	verdict := client.Decide(t.Context(), request)
	if verdict.Allowed || !errors.Is(verdict.Err, admission.ErrUnreachable) {
		t.Fatalf("verdict = %+v", verdict)
	}
}

func TestC16ConcurrentCallsAreIndependentRequests(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := request
			req.ToolUseID = fmt.Sprintf("toolu_%02d", i)
			if _, err := client.Admit(t.Context(), req); err != nil {
				t.Errorf("admit %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, r := range edge.Admits() {
		seen[r.Body["tool_use_id"].(string)] = true
	}
	if len(seen) != 10 {
		t.Fatalf("%d distinct tool_use_id values, want 10", len(seen))
	}
}

func TestC17TokenAndToolInputNeverReachTheLog(t *testing.T) {
	edge := edgetest.New(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	client := newClient(t, edge, admission.WithLogger(logger))
	marker := "SECRET-INPUT-7f3a"
	req := admission.Request{Surface: admission.SurfaceCustom, ToolName: "Bash", ToolInput: map[string]any{"command": marker}}
	if _, err := client.Admit(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	edge.Script(edgetest.Deny("rule denied " + marker))
	client.Decide(t.Context(), req)
	text := logs.String()
	if text == "" {
		t.Fatal("the client logs its decisions")
	}
	if strings.Contains(text, marker) {
		t.Fatalf("the tool input reached the log: %s", text)
	}
	if strings.Contains(text, edge.Token()) {
		t.Fatalf("the token reached the log: %s", text)
	}
}

func TestDecisionParsingKeepsEveryField(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	edge.Script(edgetest.Allow(map[string]any{
		"updated_input": map[string]any{"command": "mitrity-hook exec met_1"},
		"routed_to":     "governed_shell",
		"approval_id":   nil,
		"risk_score":    0.25,
		"admission_id":  "adm-7",
		"reason":        "allowed; routed to the governed shell",
	}))
	decision, err := client.Admit(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	want := admission.Decision{
		Decision:     admission.Allow,
		Reason:       "allowed; routed to the governed shell",
		AdmissionID:  "adm-7",
		RiskScore:    0.25,
		UpdatedInput: map[string]any{"command": "mitrity-hook exec met_1"},
		RoutedTo:     "governed_shell",
	}
	if !reflect.DeepEqual(decision, want) {
		t.Fatalf("decision = %+v, want %+v", decision, want)
	}
}

func TestRequestValidationHappensBeforeIO(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	negative := -1
	for _, req := range []admission.Request{
		{Surface: admission.SurfaceCustom, ToolName: "   "},
		{Surface: admission.SurfaceCustom, ToolName: "Bash", HoldTimeoutSeconds: &negative},
		{Surface: "nope", ToolName: "Bash"},
		{Surface: admission.SurfaceCustom, ToolName: "Bash", ToolInput: map[string]any{"ch": make(chan int)}},
	} {
		if _, err := client.Admit(t.Context(), req); !errors.Is(err, admission.ErrProtocol) {
			t.Errorf("Admit(%+v) = %v, want protocol error", req, err)
		}
	}
	if len(edge.Requests()) != 0 {
		t.Fatal("the fake edge saw a request")
	}
}

func TestEmptySurfaceAndNilInputAreSentAsCustomAndEmptyObject(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	if _, err := client.Admit(t.Context(), admission.Request{ToolName: "Bash"}); err != nil {
		t.Fatal(err)
	}
	body := edge.Admits()[0].Body
	if body["surface"] != "custom" || !reflect.DeepEqual(body["tool_input"], map[string]any{}) {
		t.Fatalf("body = %v", body)
	}
}

func TestAttestReturnsNilOn204(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	enabled := true
	att := admission.Attestation{
		Framework:      "custom",
		Adapter:        "mitrity-go",
		AdapterVersion: "0.0.0",
		HookedTools:    []string{"Bash"},
		Sandbox:        &admission.SandboxPosture{Enabled: &enabled},
		ConfigHash:     strings.Repeat("ab", 32),
	}
	if err := client.Attest(t.Context(), att); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"framework":       "custom",
		"adapter":         "mitrity-go",
		"adapter_version": "0.0.0",
		"hooked_tools":    []any{"Bash"},
		"sandbox":         map[string]any{"enabled": true, "allow_unsandboxed_commands": nil, "fail_if_unavailable": nil},
		"config_hash":     strings.Repeat("ab", 32),
	}
	if got := edge.Attests()[0].Body; !reflect.DeepEqual(got, want) {
		t.Fatalf("attest body = %v, want %v", got, want)
	}
}

func TestAttestAcceptsA204WithoutTheVersionHeader(t *testing.T) {
	// The edge answers /v1/attest with a bare 204; only a decision needs the header.
	edge := edgetest.New(t)
	client := newClient(t, edge)
	edge.SetDefaultAttest(edgetest.Scripted{Status: 204, OmitVersion: true})
	if err := client.Attest(t.Context(), admission.Attestation{Framework: "custom", Adapter: "mitrity-go", AdapterVersion: "0"}); err != nil {
		t.Fatal(err)
	}
	if len(edge.Attests()) != 1 {
		t.Fatal("no attest recorded")
	}
}

func TestHealthIsUnauthenticated(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	health, err := client.Health(t.Context())
	if err != nil || health["status"] != "ok" {
		t.Fatalf("health = %v, %v", health, err)
	}
	if edge.Requests()[0].Header.Get(edgetest.HeaderToken) != "" {
		t.Fatal("the health check carried the token")
	}
}

func TestTCPLoopbackAddressIsAcceptedAndDialed(t *testing.T) {
	// No TCP listener in the fake; a connection refused on loopback is the
	// unreachable path, which is the point: the address itself is accepted.
	edge := edgetest.New(t)
	for _, addr := range []string{"127.0.0.1:1", "localhost:1", "[::1]:1"} {
		client := admission.NewWithConfig(admission.Config{Addr: addr, TokenFile: edge.TokenFile, Timeout: 500 * time.Millisecond})
		if _, err := client.Admit(t.Context(), request); !errors.Is(err, admission.ErrUnreachable) {
			t.Errorf("%s: err = %v, want unreachable", addr, err)
		}
	}
}

func TestCanceledContextIsADeny(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := client.Admit(ctx, request)
	if !errors.Is(err, admission.ErrCanceled) {
		t.Fatalf("err = %v, want canceled", err)
	}
	verdict := client.Decide(ctx, request)
	if verdict.Allowed || verdict.Err == nil {
		t.Fatalf("verdict = %+v", verdict)
	}
}

func TestClientFromEnvDiscoversTheEdge(t *testing.T) {
	edge := edgetest.New(t)
	t.Setenv(admission.EnvAddr, edge.Addr())
	t.Setenv(admission.EnvTokenFile, edge.TokenFile)
	t.Setenv(admission.EnvTimeout, "250ms")
	t.Setenv(admission.EnvHoldTimeout, "1")
	client := admission.New()
	if cfg := client.Config(); cfg.Timeout != 250*time.Millisecond || cfg.HoldTimeout != time.Second {
		t.Fatalf("config = %+v", cfg)
	}
	decision, err := client.Admit(t.Context(), request)
	if err != nil || !decision.Allowed() {
		t.Fatalf("admit: %v", err)
	}
}

func TestKindOfAndErrorText(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	edge.Script(edgetest.Scripted{Status: 503, Body: map[string]any{"reason": "no_profile"}})
	_, err := client.Admit(t.Context(), request)
	if admission.KindOf(err) != admission.KindNotReady || admission.KindNotReady.String() != "not_ready" {
		t.Fatalf("kind = %v", admission.KindOf(err))
	}
	if admission.KindOf(errors.New("plain")) != 0 {
		t.Fatal("KindOf(plain error) should be 0")
	}
}
