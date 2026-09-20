// Package mitrity is the MITRITY governance adapter for Go agents.
//
// The module connects a Go agent's tool execution to the co-located MITRITY
// edge: every tool the agent runs itself is admitted through the loopback
// admission API before it runs, MCP tools reach the agent through the MITRITY
// gateway, and the runtime's governance posture is attested so the control
// plane can render an honest coverage badge.
//
//   - Package admission is the wire client (POST /v1/admit, /v1/attest,
//     GET /healthz), with no dependency beyond the standard library.
//   - Package govern wraps tool invocations: admit, then run — a deny is a
//     typed error carrying the policy reason, a hold waits for the human, an
//     allow runs the (possibly rewritten) input.
//
// Contract: https://mitrity.com/docs/integrations/adapters
// Wire protocol: https://mitrity.com/docs/integrations/admission-api
package mitrity

// Version is the adapter version reported as adapter_version on every
// attestation. Semver; adopting a new admission protocol version is at least
// a MINOR bump (the adapter contract, "Versioning rule").
const Version = "0.1.0"
