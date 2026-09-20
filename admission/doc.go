// Package admission is the MITRITY admission client: one authenticated
// request to the co-located edge, and the two-phase decision built on it.
//
// Every failure — an unreachable socket, a token the edge rejects, a 503, a
// body that is not a decision, a deadline exceeded — is an *Error from Admit
// and a deny from Decide. There is no path through this package that produces
// an allow the edge did not send for this request.
//
// The edge is discovered the way mitrity-hook discovers it, from the same
// environment variables with the same defaults and ceilings (see Config), so
// one provisioning step serves both. The address must be a Unix socket or a
// loopback host:port; anything else is refused before any I/O.
//
// Contract: https://mitrity.com/docs/integrations/admission-api
// Adapter guarantees: https://mitrity.com/docs/integrations/adapters
package admission
