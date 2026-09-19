package admission_test

// Conformance C4, C5, C9: the two-phase decision never fabricates an allow.

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mitrity-io/mitrity-go/admission"
	"github.com/mitrity-io/mitrity-go/internal/edgetest"
)

var destructive = admission.Request{Surface: admission.SurfaceCustom, ToolName: "Bash", ToolInput: map[string]any{"command": "rm -rf build"}}

func budgets(edge *edgetest.Edge) []int {
	var out []int
	for _, r := range edge.Admits() {
		out = append(out, r.HoldBudget())
	}
	return out
}

func TestC4UnreachableEdgeIsADenyWithinTheDeadline(t *testing.T) {
	edge := edgetest.New(t)
	client := admission.NewWithConfig(admission.Config{
		Addr:      "unix:" + filepath.Join(t.TempDir(), "missing.sock"),
		TokenFile: edge.TokenFile,
		Timeout:   500 * time.Millisecond,
	})
	started := time.Now()
	verdict := client.Decide(t.Context(), destructive)
	elapsed := time.Since(started)
	if verdict.Allowed || !errors.Is(verdict.Err, admission.ErrUnreachable) {
		t.Fatalf("verdict = %+v", verdict)
	}
	if !verdict.Unreachable() || verdict.PolicyDenied() {
		t.Fatalf("verdict flags: %+v", verdict)
	}
	if !strings.Contains(verdict.Reason, "not a policy decision") {
		t.Fatalf("reason = %q", verdict.Reason)
	}
	if elapsed > 600*time.Millisecond {
		t.Fatalf("took %v", elapsed)
	}
}

func TestC5LateAnswerIsDiscarded(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge, admission.WithTimeout(300*time.Millisecond))
	late := edgetest.Allow(nil)
	late.Delay = time.Second
	edge.Script(late)
	started := time.Now()
	verdict := client.Decide(t.Context(), destructive)
	elapsed := time.Since(started)
	if verdict.Allowed || !errors.Is(verdict.Err, admission.ErrTimeout) {
		t.Fatalf("verdict = %+v", verdict)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("took %v, want under deadline + 200 ms", elapsed)
	}
	if n := len(edge.Admits()); n != 1 {
		t.Fatalf("%d admits, want 1", n)
	}
}

func TestPolicyDenyCarriesTheReason(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	edge.Script(edgetest.Deny(""))
	verdict := client.Decide(t.Context(), destructive)
	if !verdict.PolicyDenied() || verdict.Err != nil {
		t.Fatalf("verdict = %+v", verdict)
	}
	want := "MITRITY denied this action: " + edgetest.DenyReason
	if verdict.Reason != want {
		t.Fatalf("reason = %q, want %q", verdict.Reason, want)
	}
	if got := budgets(edge); !reflect.DeepEqual(got, []int{0}) {
		t.Fatalf("budgets = %v", got)
	}
}

func TestAllowCarriesUpdatedInputAndRouting(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	edge.Script(edgetest.Allow(map[string]any{
		"updated_input": map[string]any{"command": "mitrity-hook exec met_1"},
		"routed_to":     "governed_shell",
	}))
	verdict := client.Decide(t.Context(), destructive)
	if !verdict.Allowed {
		t.Fatalf("verdict = %+v", verdict)
	}
	if !reflect.DeepEqual(verdict.UpdatedInput, map[string]any{"command": "mitrity-hook exec met_1"}) || verdict.RoutedTo != "governed_shell" {
		t.Fatalf("verdict = %+v", verdict)
	}
}

func TestC9HoldResubmitsWithTheBudgetAndRunsOnAllow(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	edge.SetDefaultAdmit(edgetest.HoldScript{Outcome: edgetest.Allow(nil), Wait: 50 * time.Millisecond})
	verdict := client.Decide(t.Context(), destructive)
	if !verdict.Allowed {
		t.Fatalf("verdict = %+v", verdict)
	}
	if got := budgets(edge); !reflect.DeepEqual(got, []int{0, 2}) {
		t.Fatalf("budgets = %v, want [0 2]", got)
	}
}

func TestC9HoldDeniedAfterWaitNamesTheApproval(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	edge.SetDefaultAdmit(edgetest.HoldScript{Outcome: edgetest.Deny("approval apr-hold timed out")})
	verdict := client.Decide(t.Context(), destructive)
	if !verdict.PolicyDenied() || !strings.Contains(verdict.Reason, "apr-hold") {
		t.Fatalf("verdict = %+v", verdict)
	}
}

func TestC9StillHeldAfterBudgetIsADeny(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	edge.SetDefaultAdmit(edgetest.HoldScript{Outcome: edgetest.Held("apr-hold")})
	verdict := client.Decide(t.Context(), destructive)
	if verdict.Allowed || !verdict.Held {
		t.Fatalf("verdict = %+v", verdict)
	}
	if !strings.Contains(verdict.Reason, "apr-hold") || !strings.Contains(verdict.Reason, "has not been approved") {
		t.Fatalf("reason = %q", verdict.Reason)
	}
}

func TestC9ZeroHoldBudgetSendsNoSecondRequest(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge, admission.WithHoldTimeout(0))
	edge.SetDefaultAdmit(edgetest.HoldScript{Outcome: edgetest.Allow(nil)})
	verdict := client.Decide(t.Context(), destructive)
	if verdict.Allowed || !verdict.Held {
		t.Fatalf("verdict = %+v", verdict)
	}
	if n := len(edge.Admits()); n != 1 {
		t.Fatalf("%d admits, want 1", n)
	}
}

func TestC9HoldBudgetIsClamped(t *testing.T) {
	client := admission.NewWithConfig(admission.Config{Addr: "unix:/x", TokenFile: "/t", HoldTimeout: 99999 * time.Second})
	if got := client.Config().HoldTimeout; got != 570*time.Second {
		t.Fatalf("hold timeout = %v, want 570s", got)
	}
}

func TestC9FailureWhileWaitingBlocks(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	edge.SetDefaultAdmit(edgetest.HoldScript{Outcome: edgetest.Scripted{Status: 503, Body: map[string]any{"reason": "no_profile"}}})
	verdict := client.Decide(t.Context(), destructive)
	if verdict.Allowed || !verdict.Held || !errors.Is(verdict.Err, admission.ErrNotReady) {
		t.Fatalf("verdict = %+v", verdict)
	}
	if !strings.Contains(verdict.Reason, "apr-hold") {
		t.Fatalf("reason = %q", verdict.Reason)
	}
}

func TestC9SecondCallWaitsPastTheDecisionDeadline(t *testing.T) {
	// The second call is bounded by the hold budget plus a margin, not by the
	// 500 ms decision deadline: a 700 ms wait on a 2 s budget is an allow.
	edge := edgetest.New(t)
	client := newClient(t, edge)
	edge.SetDefaultAdmit(edgetest.HoldScript{Outcome: edgetest.Allow(nil), Wait: 700 * time.Millisecond})
	verdict := client.Decide(t.Context(), destructive)
	if !verdict.Allowed {
		t.Fatalf("verdict = %+v", verdict)
	}
}

func TestDecideWithHoldBudgetCapsButNeverRaises(t *testing.T) {
	edge := edgetest.New(t)
	client := newClient(t, edge)
	edge.SetDefaultAdmit(edgetest.HoldScript{Outcome: edgetest.Allow(nil)})
	if verdict := client.DecideWithHoldBudget(t.Context(), destructive, time.Second); !verdict.Allowed {
		t.Fatalf("verdict = %+v", verdict)
	}
	if verdict := client.DecideWithHoldBudget(t.Context(), destructive, time.Hour); !verdict.Allowed {
		t.Fatalf("verdict = %+v", verdict)
	}
	if got := budgets(edge); !reflect.DeepEqual(got, []int{0, 1, 0, 2}) {
		t.Fatalf("budgets = %v, want [0 1 0 2]", got)
	}
}
