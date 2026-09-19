package admission

import "errors"

// Kind classifies a failure to obtain a decision.
//
// Every kind means the same thing at the call site: the tool call is denied.
// There is no failure the adapter turns into an allow. The kinds exist so a
// caller can say why — an outage reads differently from a policy decision in
// the model's context — never so it can pick one to ignore.
type Kind int

const (
	// KindConfig: the adapter's own configuration is unusable — a routable
	// admission address, no token file path. Raised before any I/O.
	KindConfig Kind = iota + 1
	// KindUnreachable: the edge could not be reached — no socket, connection
	// refused, token file absent or empty.
	KindUnreachable
	// KindTimeout: the edge did not answer inside the adapter's deadline.
	KindTimeout
	// KindCanceled: the caller's context was canceled before a decision arrived.
	KindCanceled
	// KindUnauthorized: the edge rejected the token after the one permitted
	// re-read and retry.
	KindUnauthorized
	// KindNotReady: the edge answered 503 — it has no mission profile to judge
	// against.
	KindNotReady
	// KindProtocol: the exchange did not follow the contract — a 400, a version
	// header the adapter does not speak, a body that is not JSON, a decision
	// value it does not recognize.
	KindProtocol
	// KindPayloadTooLarge: the request body exceeds the edge's 64 KiB cap;
	// denied without sending. A KindPayloadTooLarge error also matches
	// ErrProtocol, as the Python adapter's subclass does.
	KindPayloadTooLarge
)

var kindNames = map[Kind]string{
	KindConfig:          "config",
	KindUnreachable:     "unreachable",
	KindTimeout:         "timeout",
	KindCanceled:        "canceled",
	KindUnauthorized:    "unauthorized",
	KindNotReady:        "not_ready",
	KindProtocol:        "protocol",
	KindPayloadTooLarge: "payload_too_large",
}

// String returns the kind's stable name.
func (k Kind) String() string {
	if name, ok := kindNames[k]; ok {
		return name
	}
	return "unknown"
}

// Error is the error every failure to obtain a decision is reported through.
// Match it with errors.As, or its kind with errors.Is against the Err*
// sentinels (errors.Is(err, ErrTimeout)).
type Error struct {
	Kind    Kind
	Message string
	// Cause is the underlying error, when there is one (a net error, a JSON
	// error). It never carries the token or the tool input.
	Cause error
}

func (e *Error) Error() string { return e.Message }

// Unwrap exposes the cause for errors.Is / errors.As.
func (e *Error) Unwrap() error { return e.Cause }

// Is reports whether target is the sentinel for this error's kind. A
// KindPayloadTooLarge error matches both ErrPayloadTooLarge and ErrProtocol.
func (e *Error) Is(target error) bool {
	s, ok := target.(*sentinel)
	if !ok {
		return false
	}
	if e.Kind == s.kind {
		return true
	}
	return e.Kind == KindPayloadTooLarge && s.kind == KindProtocol
}

type sentinel struct {
	kind Kind
	text string
}

func (s *sentinel) Error() string { return s.text }

// Sentinels for errors.Is. They are never returned themselves; every returned
// error is an *Error whose Kind they match.
var (
	ErrConfig          error = &sentinel{KindConfig, "admission: configuration error"}
	ErrUnreachable     error = &sentinel{KindUnreachable, "admission: edge unreachable"}
	ErrTimeout         error = &sentinel{KindTimeout, "admission: deadline exceeded"}
	ErrCanceled        error = &sentinel{KindCanceled, "admission: canceled"}
	ErrUnauthorized    error = &sentinel{KindUnauthorized, "admission: token rejected"}
	ErrNotReady        error = &sentinel{KindNotReady, "admission: edge not ready"}
	ErrProtocol        error = &sentinel{KindProtocol, "admission: protocol error"}
	ErrPayloadTooLarge error = &sentinel{KindPayloadTooLarge, "admission: request too large"}
)

// KindOf returns the Kind of err when it is an *Error, and 0 otherwise.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return 0
}

func newError(kind Kind, message string) *Error {
	return &Error{Kind: kind, Message: message}
}

func wrapError(kind Kind, message string, cause error) *Error {
	return &Error{Kind: kind, Message: message, Cause: cause}
}
