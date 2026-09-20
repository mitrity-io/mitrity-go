// Package govern wraps a Go agent's tool invocations so that every one is
// judged by the co-located MITRITY edge before it runs.
//
// A Go agent has no hook system: the tools it executes itself — a shell
// function, a file write, an HTTP fetch, a call to an MCP server — are plain
// Go calls. What replaces the hook is a wrapper: Wrap takes a Tool and
// returns a Tool of the same shape whose Call admits the invocation first
// (POST /v1/admit through package admission), returns a *DeniedError carrying
// the edge's reason on a deny, waits for the human on a hold, and runs the
// inner tool with the edge's updated_input merged over the input on an allow.
// WrapCaller does the same for an MCP-client-shaped Call(ctx, tool, args)
// method.
//
// Coverage is exactly what you hand it. A tool that was not wrapped is
// invisible to the adapter and to the attestation the Governor sends at the
// first governed call of a session (and again whenever the governed
// configuration changes); declare the execution-capable tools you run outside
// the adapter with WithUngoverned so the attestation says so.
//
// If the edge cannot be reached, the call is denied. There is no fail-open
// mode, no cached decision and no local policy evaluation.
//
// Contract: https://mitrity.com/docs/integrations/adapters
package govern
