package govern_test

// Conformance C7–C18 as they apply to a Go agent: the wrapper admits before
// the tool runs, blocks in Go's idiom (an error), honors updated_input, and
// attests what it governs.

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

	mitrity "github.com/mitrity-io/mitrity-go"
	"github.com/mitrity-io/mitrity-go/admission"
	"github.com/mitrity-io/mitrity-go/govern"
	"github.com/mitrity-io/mitrity-go/internal/edgetest"
)

// recorder is a tool that records what it was called with.
type recorder struct {
	mu     sync.Mutex
	calls  []map[string]any
	result string
}

func (r *recorder) Name() string { return "Bash" }

func (r *recorder) Call(_ context.Context, input map[string]any) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, input)
	return r.result, nil
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

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

func newGovernor(t *testing.T, edge *edgetest.Edge, opts ...govern.Option) *govern.Governor {
	t.Helper()
	return govern.New(append([]govern.Option{govern.WithClient(newClient(t, edge))}, opts...)...)
}

var input = map[string]any{"command": "rm -rf build", "description": "clean"}

func TestC7AllowRunsTheToolWithTheOriginalInput(t *testing.T) {
	edge := edgetest.New(t)
	g := newGovernor(t, edge)
	inner := &recorder{result: "ok"}
	tool := govern.Wrap[string](g, inner)
	if tool.Name() != "Bash" {
		t.Fatalf("name = %q", tool.Name())
	}
	out, err := tool.Call(t.Context(), input)
	if err != nil || out != "ok" {
		t.Fatalf("call: %v %q", err, out)
	}
	if inner.count() != 1 || !reflect.DeepEqual(inner.calls[0], input) {
		t.Fatalf("inner calls = %v", inner.calls)
	}
	if s := g.Stats(); s.Admitted != 1 || s.Allowed != 1 || s.Denied != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestC8DenyBlocksTheToolWithTheEdgeReasonVerbatim(t *testing.T) {
	edge := edgetest.New(t)
	g := newGovernor(t, edge)
	inner := &recorder{}
	tool := govern.Wrap[string](g, inner)
	edge.Script(edgetest.Deny(""))
	_, err := tool.Call(t.Context(), input)
	var denied *govern.DeniedError
	if !errors.As(err, &denied) || !errors.Is(err, govern.ErrDenied) {
		t.Fatalf("err = %v (%T), want *DeniedError", err, err)
	}
	if !denied.PolicyDenied() || denied.Unreachable() || denied.Held() || denied.Tool != "Bash" {
		t.Fatalf("denied = %+v", denied)
	}
	if want := "MITRITY denied this action: " + edgetest.DenyReason; denied.Error() != want {
		t.Fatalf("reason = %q, want %q", denied.Error(), want)
	}
	if denied.Decision() == nil || denied.Decision().Decision != admission.Deny {
		t.Fatalf("decision = %+v", denied.Decision())
	}
	if inner.count() != 0 {
		t.Fatal("the inner tool ran after a deny")
	}
	if s := g.Stats(); s.Denied != 1 || s.Allowed != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestUnreachableEdgeIsADenyThatSaysItIsNotAPolicyDecision(t *testing.T) {
	edge := edgetest.New(t)
	client := admission.NewWithConfig(admission.Config{
		Addr:      "unix:" + filepath.Join(t.TempDir(), "missing.sock"),
		TokenFile: edge.TokenFile,
		Timeout:   300 * time.Millisecond,
	})
	g := govern.New(govern.WithClient(client), govern.WithLogger(nil))
	inner := &recorder{}
	tool := govern.Wrap[string](g, inner)
	_, err := tool.Call(t.Context(), input)
	var denied *govern.DeniedError
	if !errors.As(err, &denied) || !denied.Unreachable() || denied.PolicyDenied() {
		t.Fatalf("err = %v", err)
	}
	if !errors.Is(err, admission.ErrUnreachable) {
		t.Fatalf("the admission error is not exposed: %v", err)
	}
	if !strings.Contains(err.Error(), "not a policy decision") {
		t.Fatalf("reason = %q", err.Error())
	}
	if denied.Decision() != nil || inner.count() != 0 {
		t.Fatalf("decision = %v, inner calls = %d", denied.Decision(), inner.count())
	}
	if s := g.Stats(); s.Unreachable != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestC9HoldWaitsThenRunsOnAllow(t *testing.T) {
	edge := edgetest.New(t)
	g := newGovernor(t, edge)
	inner := &recorder{}
	tool := govern.Wrap[string](g, inner)
	edge.SetDefaultAdmit(edgetest.HoldScript{Outcome: edgetest.Allow(nil), Wait: 50 * time.Millisecond})
	if _, err := tool.Call(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	var budgets []int
	for _, r := range edge.Admits() {
		budgets = append(budgets, r.HoldBudget())
	}
	if !reflect.DeepEqual(budgets, []int{0, 2}) || inner.count() != 1 {
		t.Fatalf("budgets = %v, inner calls = %d", budgets, inner.count())
	}
	if s := g.Stats(); s.Admitted != 1 || s.Allowed != 1 || s.Held != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestC9HoldDeniedOrUnansweredBlocks(t *testing.T) {
	cases := map[string]edgetest.Scripted{
		"denied after the wait": edgetest.Deny("approval apr-hold timed out"),
		"still held":            edgetest.Held("apr-hold"),
		"edge failed":           {Status: 503, Body: map[string]any{"reason": "no_profile"}},
	}
	for name, outcome := range cases {
		t.Run(name, func(t *testing.T) {
			edge := edgetest.New(t)
			g := newGovernor(t, edge)
			inner := &recorder{}
			tool := govern.Wrap[string](g, inner)
			edge.SetDefaultAdmit(edgetest.HoldScript{Outcome: outcome})
			_, err := tool.Call(t.Context(), input)
			var denied *govern.DeniedError
			if !errors.As(err, &denied) || !strings.Contains(err.Error(), "apr-hold") {
				t.Fatalf("err = %v", err)
			}
			if inner.count() != 0 {
				t.Fatal("the inner tool ran")
			}
			if len(edge.Admits()) != 2 {
				t.Fatalf("%d admits, want 2", len(edge.Admits()))
			}
		})
	}
}

func TestC10UpdatedInputRunsMergedAndRoutingIsRecorded(t *testing.T) {
	edge := edgetest.New(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	g := newGovernor(t, edge, govern.WithLogger(logger))
	inner := &recorder{}
	tool := govern.Wrap[string](g, inner)
	edge.Script(edgetest.Allow(map[string]any{
		"updated_input": map[string]any{"command": "mitrity-hook exec met_1"},
		"routed_to":     "governed_shell",
	}))
	original := map[string]any{"command": "rm -rf build", "description": "clean"}
	if _, err := tool.Call(t.Context(), original); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"command": "mitrity-hook exec met_1", "description": "clean"}
	if !reflect.DeepEqual(inner.calls[0], want) {
		t.Fatalf("inner input = %v, want %v", inner.calls[0], want)
	}
	if original["command"] != "rm -rf build" {
		t.Fatal("the caller's map was mutated")
	}
	if s := g.Stats(); s.Routed != 1 {
		t.Fatalf("stats = %+v", s)
	}
	if !strings.Contains(logs.String(), "governed_shell") {
		t.Fatalf("routing not logged: %s", logs.String())
	}
}

func TestC11FirstCallAttestsOncePerSession(t *testing.T) {
	edge := edgetest.New(t)
	g := newGovernor(t, edge, govern.WithSessionID("sess-1"))
	tool := govern.Wrap[string](g, &recorder{})
	for range 2 {
		if _, err := tool.Call(t.Context(), input); err != nil {
			t.Fatal(err)
		}
	}
	attests := edge.Attests()
	if len(attests) != 1 {
		t.Fatalf("%d attests, want 1", len(attests))
	}
	want := map[string]any{
		"framework":       "custom",
		"adapter":         "mitrity-go",
		"adapter_version": mitrity.Version,
		"hooked_tools":    []any{"Bash"},
		"config_hash":     g.Attestation().ConfigHash,
	}
	if !reflect.DeepEqual(attests[0].Body, want) {
		t.Fatalf("attest body = %v, want %v", attests[0].Body, want)
	}
	if attests[0].Header.Get(edgetest.HeaderToken) != edge.Token() {
		t.Fatal("attest without the token")
	}
	// The attestation precedes the first admission of the session.
	if reqs := edge.Requests(); reqs[0].Path != "/v1/attest" || reqs[1].Path != "/v1/admit" {
		t.Fatalf("order = %s, %s", reqs[0].Path, reqs[1].Path)
	}
}

func TestC11ANewSessionAttestsAgain(t *testing.T) {
	edge := edgetest.New(t)
	g := newGovernor(t, edge)
	tool := govern.Wrap[string](g, &recorder{})
	for _, session := range []string{"a", "a", "b"} {
		if _, err := tool.Call(govern.ContextWithSessionID(t.Context(), session), input); err != nil {
			t.Fatal(err)
		}
	}
	if len(edge.Attests()) != 2 {
		t.Fatalf("%d attests, want 2", len(edge.Attests()))
	}
	var sessions []string
	for _, r := range edge.Admits() {
		sessions = append(sessions, r.Body["session_id"].(string))
	}
	if !reflect.DeepEqual(sessions, []string{"a", "a", "b"}) {
		t.Fatalf("sessions = %v", sessions)
	}
}

func TestC12DeclaredGapsAreAttestedHonestly(t *testing.T) {
	edge := edgetest.New(t)
	g := newGovernor(t, edge,
		govern.WithUngoverned("Exec", "Exec"),
		govern.WithOtherMCPServers("slack"),
		govern.WithFramework("custom", "2.0.0"))
	g.Declare("Write")
	tool := govern.Wrap[string](g, &recorder{})
	if _, err := tool.Call(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	body := edge.Attests()[0].Body
	if !reflect.DeepEqual(body["hooked_tools"], []any{"Bash", "Write"}) {
		t.Errorf("hooked_tools = %v", body["hooked_tools"])
	}
	if !reflect.DeepEqual(body["unhooked_exec_tools"], []any{"Exec"}) {
		t.Errorf("unhooked_exec_tools = %v", body["unhooked_exec_tools"])
	}
	if !reflect.DeepEqual(body["other_mcp_servers"], []any{"slack"}) {
		t.Errorf("other_mcp_servers = %v", body["other_mcp_servers"])
	}
	if body["framework_version"] != "2.0.0" {
		t.Errorf("framework_version = %v", body["framework_version"])
	}
	if !reflect.DeepEqual(g.HookedTools(), []string{"Bash", "Write"}) {
		t.Errorf("HookedTools = %v", g.HookedTools())
	}
}

func TestC18ANewToolReattestsWithADifferentHash(t *testing.T) {
	edge := edgetest.New(t)
	g := newGovernor(t, edge, govern.WithSessionID("sess-1"))
	bash := govern.Wrap[string](g, &recorder{})
	if _, err := bash.Call(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	write := govern.WrapFunc(g, "Write", func(context.Context, map[string]any) (string, error) { return "", nil })
	if _, err := write.Call(t.Context(), map[string]any{"path": "a.txt", "content": "x"}); err != nil {
		t.Fatal(err)
	}
	attests := edge.Attests()
	if len(attests) != 2 {
		t.Fatalf("%d attests, want 2", len(attests))
	}
	if attests[0].Body["config_hash"] == attests[1].Body["config_hash"] {
		t.Fatal("the config hash did not change")
	}
	if !reflect.DeepEqual(attests[1].Body["hooked_tools"], []any{"Bash", "Write"}) {
		t.Fatalf("hooked_tools = %v", attests[1].Body["hooked_tools"])
	}
}

func TestC13RequestIsVerbatimWithSessionCwdAndToolUseID(t *testing.T) {
	edge := edgetest.New(t)
	g := newGovernor(t, edge, govern.WithSessionID("sess-1"), govern.WithCwd("/work"), govern.WithFramework("langchain", "0.3.1"))
	shell := govern.WrapFunc(g, "shell", func(context.Context, map[string]any) (int, error) { return 0, nil })
	ctx := govern.ContextWithToolUseID(t.Context(), "toolu_9")
	if _, err := shell.Call(ctx, map[string]any{"commands": "ls"}); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"surface":              "langchain",
		"framework_version":    "0.3.1",
		"session_id":           "sess-1",
		"cwd":                  "/work",
		"tool_name":            "shell",
		"tool_input":           map[string]any{"commands": "ls"},
		"tool_use_id":          "toolu_9",
		"hold_timeout_seconds": float64(0),
	}
	if got := edge.Admits()[0].Body; !reflect.DeepEqual(got, want) {
		t.Fatalf("body = %v, want %v", got, want)
	}
	if edge.Attests()[0].Body["framework"] != "langchain" {
		t.Fatalf("framework = %v", edge.Attests()[0].Body["framework"])
	}
}

func TestDefaultsAreCustomSurfaceProcessCwdAndGeneratedIDs(t *testing.T) {
	edge := edgetest.New(t)
	g := newGovernor(t, edge)
	tool := govern.Wrap[string](g, &recorder{})
	if _, err := tool.Call(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	body := edge.Admits()[0].Body
	cwd, _ := os.Getwd()
	if body["surface"] != "custom" || body["cwd"] != cwd {
		t.Fatalf("body = %v", body)
	}
	if id, _ := body["session_id"].(string); !strings.HasPrefix(id, "go-") {
		t.Fatalf("session_id = %v", body["session_id"])
	}
	if id, _ := body["tool_use_id"].(string); !strings.HasPrefix(id, "tu_") {
		t.Fatalf("tool_use_id = %v", body["tool_use_id"])
	}
	if _, present := body["framework_version"]; present {
		t.Fatal("framework_version sent without a framework")
	}
}

func TestC14OversizedInputIsDeniedLocally(t *testing.T) {
	edge := edgetest.New(t)
	g := newGovernor(t, edge)
	inner := &recorder{}
	tool := govern.Wrap[string](g, inner)
	_, err := tool.Call(t.Context(), map[string]any{"command": strings.Repeat("x", 70*1024)})
	if !errors.Is(err, admission.ErrPayloadTooLarge) || !errors.Is(err, govern.ErrDenied) {
		t.Fatalf("err = %v", err)
	}
	if len(edge.Admits()) != 0 || inner.count() != 0 {
		t.Fatal("the input was sent or run")
	}
}

func TestC16ConcurrentCallsGetDistinctToolUseIDs(t *testing.T) {
	edge := edgetest.New(t)
	g := newGovernor(t, edge)
	tool := govern.Wrap[string](g, &recorder{})
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := tool.Call(t.Context(), map[string]any{"command": fmt.Sprintf("echo %d", i)}); err != nil {
				t.Errorf("call %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, r := range edge.Admits() {
		seen[r.Body["tool_use_id"].(string)] = true
	}
	if len(seen) != 10 || g.Stats().Admitted != 10 {
		t.Fatalf("%d distinct tool_use_id values, stats %+v", len(seen), g.Stats())
	}
	if len(edge.Attests()) != 1 {
		t.Fatalf("%d attests, want 1", len(edge.Attests()))
	}
}

func TestC17NothingSensitiveReachesTheLog(t *testing.T) {
	edge := edgetest.New(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	g := govern.New(govern.WithClient(newClient(t, edge, admission.WithLogger(logger))), govern.WithLogger(logger))
	tool := govern.Wrap[string](g, &recorder{})
	marker := "SECRET-INPUT-7f3a"
	if _, err := tool.Call(t.Context(), map[string]any{"command": marker}); err != nil {
		t.Fatal(err)
	}
	edge.Script(edgetest.Deny("rule denied " + marker))
	if _, err := tool.Call(t.Context(), map[string]any{"command": marker}); err == nil {
		t.Fatal("expected a deny")
	}
	edge.SetDefaultAttest(edgetest.Scripted{Status: 500, Body: []byte("boom")})
	if _, err := tool.Call(govern.ContextWithSessionID(t.Context(), "other"), map[string]any{"command": marker}); err != nil {
		t.Fatal(err)
	}
	text := logs.String()
	if text == "" || strings.Contains(text, marker) || strings.Contains(text, edge.Token()) {
		t.Fatalf("log: %s", text)
	}
}

func TestAttestFailureNeverBlocksTheCallAndIsRetriedLater(t *testing.T) {
	edge := edgetest.New(t)
	var logs bytes.Buffer
	g := newGovernor(t, edge, govern.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
	edge.SetDefaultAttest(edgetest.Scripted{Status: 500})
	tool := govern.Wrap[string](g, &recorder{})
	for range 2 {
		if _, err := tool.Call(t.Context(), input); err != nil {
			t.Fatal(err)
		}
	}
	if len(edge.Attests()) != 1 {
		t.Fatalf("%d attests, want 1 (retries of a failed attestation are throttled)", len(edge.Attests()))
	}
	if !strings.Contains(logs.String(), "could not report the runtime posture") {
		t.Fatalf("no warning logged: %s", logs.String())
	}
	if g.Stats().Allowed != 2 {
		t.Fatalf("stats = %+v", g.Stats())
	}
}

func TestWrapCallerAdmitsMCPStyleCalls(t *testing.T) {
	edge := edgetest.New(t)
	g := newGovernor(t, edge)
	type call struct {
		tool string
		args map[string]any
	}
	var calls []call
	inner := govern.CallerFunc[string](func(_ context.Context, tool string, args map[string]any) (string, error) {
		calls = append(calls, call{tool, args})
		return "posted", nil
	})
	caller := govern.WrapCaller[string](g, inner)

	out, err := caller.Call(t.Context(), "slack_post", map[string]any{"text": "hi"})
	if err != nil || out != "posted" {
		t.Fatalf("call: %v %q", err, out)
	}
	body := edge.Admits()[0].Body
	if body["tool_name"] != "slack_post" || !reflect.DeepEqual(body["tool_input"], map[string]any{"text": "hi"}) {
		t.Fatalf("body = %v", body)
	}

	edge.Script(edgetest.Deny("no posting"))
	if _, err := caller.Call(t.Context(), "slack_post", map[string]any{"text": "hi"}); !errors.Is(err, govern.ErrDenied) {
		t.Fatalf("err = %v", err)
	}

	edge.Script(edgetest.Allow(map[string]any{"updated_input": map[string]any{"text": "[redacted]"}}))
	if _, err := caller.Call(t.Context(), "slack_post", map[string]any{"text": "secret", "channel": "c"}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !reflect.DeepEqual(calls[1].args, map[string]any{"text": "[redacted]", "channel": "c"}) {
		t.Fatalf("inner calls = %v", calls)
	}
	if !reflect.DeepEqual(g.HookedTools(), []string{"slack_post"}) {
		t.Fatalf("hooked = %v", g.HookedTools())
	}
}

func TestWrapAllPreservesOrderAndNames(t *testing.T) {
	edge := edgetest.New(t)
	g := newGovernor(t, edge)
	tools := govern.WrapAll(g, []govern.Tool[string]{
		govern.Func("Write", func(context.Context, map[string]any) (string, error) { return "w", nil }),
		&recorder{result: "b"},
	})
	if tools[0].Name() != "Write" || tools[1].Name() != "Bash" {
		t.Fatalf("names = %q %q", tools[0].Name(), tools[1].Name())
	}
	if !reflect.DeepEqual(g.HookedTools(), []string{"Bash", "Write"}) {
		t.Fatalf("hooked = %v", g.HookedTools())
	}
	if out, err := tools[0].Call(t.Context(), nil); err != nil || out != "w" {
		t.Fatalf("call: %v %q", err, out)
	}
}

func TestAdmitDirectlyReturnsTheInputToRun(t *testing.T) {
	edge := edgetest.New(t)
	g := newGovernor(t, edge)
	edge.Script(edgetest.Allow(map[string]any{"updated_input": map[string]any{"command": "ls"}}))
	admitted, err := g.Admit(t.Context(), "Bash", map[string]any{"command": "rm", "timeout": 5})
	if err != nil || !reflect.DeepEqual(admitted, map[string]any{"command": "ls", "timeout": 5}) {
		t.Fatalf("admit: %v %v", err, admitted)
	}
	if _, err := g.Admit(t.Context(), "Bash", nil); err != nil {
		t.Fatal(err)
	}
}
