package govern

import (
	"errors"

	"github.com/mitrity-io/mitrity-go/admission"
)

// ErrDenied is the sentinel every *DeniedError matches with errors.Is.
var ErrDenied = errors.New("mitrity: action denied")

// DeniedError is returned in place of a tool result when the edge did not
// allow the call: a policy deny, a hold nobody answered, or a failure to
// obtain a decision (the edge unreachable, a timeout, a protocol error).
//
// Error() is the model-safe reason — the edge's reason verbatim on a policy
// deny, a sentence that says it was not a policy decision on an outage. It
// never contains the token or the tool input.
type DeniedError struct {
	// Tool is the tool_name that was admitted.
	Tool string
	// Verdict is the full outcome of the two-phase decision.
	Verdict admission.Verdict
}

func (e *DeniedError) Error() string { return e.Verdict.Reason }

// Is reports whether target is ErrDenied.
func (e *DeniedError) Is(target error) bool { return target == ErrDenied }

// Unwrap exposes the *admission.Error behind an adapter-side deny, so
// errors.Is(err, admission.ErrUnreachable) works through it. It is nil for a
// policy deny.
func (e *DeniedError) Unwrap() error { return e.Verdict.Err }

// PolicyDenied reports that the edge judged the call and said no.
func (e *DeniedError) PolicyDenied() bool { return e.Verdict.PolicyDenied() }

// Held reports that the call was held for a human and was not approved
// within the budget.
func (e *DeniedError) Held() bool { return e.Verdict.Held }

// Unreachable reports that the deny is the adapter's own fail-closed
// decision: the edge could not be reached or did not answer.
func (e *DeniedError) Unreachable() bool { return e.Verdict.Unreachable() }

// Decision returns the edge's decision when one arrived, else nil.
func (e *DeniedError) Decision() *admission.Decision { return e.Verdict.Decision }
