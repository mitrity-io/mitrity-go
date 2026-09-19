# mitrity-go

MITRITY governance adapter for Go agents: the admission client and the tool
wrappers that connect a Go agent's tool execution to the co-located MITRITY
edge (admission API and gateway).

The MITRITY gateway governs what an agent asks it to do over MCP. It cannot
see what the agent's own code does — the shell command a Go function runs,
the file it writes, the HTTP request it makes, the MCP server it calls
directly. This module closes that gap: every such call is admitted by the
co-located edge **before it runs**, with the same policy rules, command
analysis, DLP and holds an MCP call gets, and the same audit trail
(`surface=agent_hook`). If the edge cannot be reached, the call is denied —
there is no fail-open mode.

Contract: [iag-specs/sentinel/adapters.md](https://github.com/mitrity-io/iag-specs/blob/main/sentinel/adapters.md)
(wire protocol: [sentinel/admission-api.md](https://github.com/mitrity-io/iag-specs/blob/main/sentinel/admission-api.md)).

## Install

```bash
go get github.com/mitrity-io/mitrity-go@<ref>
```

Go ≥ 1.24. No dependency beyond the standard library. Until the first tagged
release, pin a commit; while the repository is private, set
`GOPRIVATE=github.com/mitrity-io` so the Go tool fetches it over git.

## Prerequisite: a co-located edge

The adapter talks to a `mitrity-gateway` (or `mitrity-mcp-sidecar`) running
next to the agent with an `admission` block:

```yaml
admission:
  enabled: true
  listen_addr: "unix:/run/mitrity/admission.sock"
  token_file: "/run/mitrity/admission.token"
```

The adapter finds it through the same environment variables `mitrity-hook`
uses, with the same defaults:

| Variable | Default | Meaning |
| --- | --- | --- |
| `MITRITY_ADMISSION_ADDR` | `unix:/run/mitrity/admission.sock` (`127.0.0.1:8777` on Windows) | The edge's admission listener. Must be a Unix socket or loopback; anything else is refused before any I/O. |
| `MITRITY_ADMISSION_TOKEN_FILE` | `/run/mitrity/admission.token` (`%PROGRAMDATA%\Mitrity\admission.token` on Windows) | The per-process token the edge writes at startup. Read on every attempt. |
| `MITRITY_HOOK_TIMEOUT` | `500ms` (max `30s`) | Deadline for one decision. |
| `MITRITY_HOOK_HOLD_TIMEOUT` | `540s` (max `570s`) | Longest to wait on a human approval; `0` disables waiting. |
| `MITRITY_HOOK_FAIL_MODE` | — | Ignored. Adapters have no fail-open mode. |

## Governing your tools

A Go agent has no hook system; what replaces the hook is a wrapper. Give
`govern.Wrap` (or `WrapFunc`) the tools you execute yourself, and every call
is judged first:

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/mitrity-io/mitrity-go/govern"
)

func main() {
	g := govern.New() // discovers the edge from the environment

	shell := govern.WrapFunc(g, "Bash", func(ctx context.Context, in map[string]any) (string, error) {
		cmd, _ := in["command"].(string)
		out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
		return string(out), err
	})

	out, err := shell.Call(context.Background(), map[string]any{"command": "rm -rf build"})
	var denied *govern.DeniedError
	if errors.As(err, &denied) {
		fmt.Println("blocked:", denied.Error()) // the edge's reason, safe to show the model
		return
	}
	fmt.Print(out)
}
```

What the wrapper does on each call:

- **Admits first.** `POST /v1/admit` with the tool's name and input, verbatim
  (`tool_name: "Bash"`, `tool_input: {"command": …}`); the edge evaluates it
  as `builtin:bash`. An allow returns the inner tool's result unchanged.
- **Denies in Go's idiom.** A policy deny, a hold nobody answered and an
  unreachable edge each return a `*govern.DeniedError` (also
  `errors.Is(err, govern.ErrDenied)`); its `Error()` is the reason the model
  should see. `denied.PolicyDenied()`, `Held()` and `Unreachable()` say which,
  and `errors.Is(err, admission.ErrUnreachable)` (or `ErrTimeout`, …) reaches
  the underlying admission error. The inner tool never runs.
- **Waits on holds.** A held call asks again with the hold budget
  (`MITRITY_HOOK_HOLD_TIMEOUT`) so the edge long-polls the approval, inside
  `Call`; a hold that nobody approves is a deny naming the `approval_id`.
- **Runs `updated_input`.** When the edge rewrites the input, the inner tool
  receives the rewrite merged key by key over the original (keys the edge did
  not touch keep their values). The caller's map is never mutated.
- **Attests.** The first governed call of a session sends `POST /v1/attest`
  with the tools this governor wraps; a tool wrapped later re-attests with a
  new `config_hash`.

Any `Tool[T]` — a `Name()` and a `Call(ctx, map[string]any) (T, error)` —
can be wrapped with `govern.Wrap`; `govern.WrapAll` wraps a slice. A tool
whose shape fits neither can call `g.Admit(ctx, name, input)` directly and
run only what it returns.

### MCP-shaped clients

An MCP client is `Call(ctx, tool, args)` — the `ToolClient` shape of
`iag-agents/shared/agentkit`, which its `gateway.Client` implements for the
co-located `mitrity-gateway`. `govern.WrapCaller` admits each call with the
tool name and arguments verbatim:

```go
// direct reaches an MCP server without the gateway in between.
admitted := govern.WrapCaller[agentkit.ToolResult](g, direct)
res, err := admitted.Call(ctx, "slack_post", map[string]any{"channel": "#ops", "text": "…"})
```

To keep the whole `ToolClient` shape (so `List` passes through), embed the
client and route `Call` through the wrapper:

```go
type governedTools struct {
	agentkit.ToolClient
	admitted govern.Caller[agentkit.ToolResult]
}

func (t governedTools) Call(ctx context.Context, tool string, args map[string]any) (agentkit.ToolResult, error) {
	return t.admitted.Call(ctx, tool, args)
}

deps.Tools = governedTools{ToolClient: direct, admitted: govern.WrapCaller[agentkit.ToolResult](g, direct)}
```

Do **not** wrap a client that talks to the MITRITY gateway: the gateway's
own pipeline already judges those calls as `mcp:<tool>`, and admitting them
again would audit one action twice. `WrapCaller` is for a client that reaches
an MCP server directly — otherwise an ungoverned tool path. A call admitted
this way is judged by the admission API like any other adapter call, as
`builtin:<lowercased tool>` with audit `surface=agent_hook`, so a policy for
it is written as `builtin:slack_post`, not `mcp:slack_post`. Either way,
declare the server with `govern.WithOtherMCPServers("name")` so the
attestation is complete.

### What the attestation says

`POST /v1/attest` carries `framework` (`custom` unless you name one with
`govern.WithFramework(name, version)`), `adapter: mitrity-go`,
`adapter_version`, `hooked_tools` (every name wrapped or declared), and what
you declare with `WithUngoverned(...)` (execution-capable tools you run
without wrapping → `unhooked_exec_tools`) and `WithOtherMCPServers(...)`.
`g.Attestation()` returns the object; `g.Stats()` counts admitted / allowed /
denied / held / unreachable / routed calls.

Coverage is exactly what you hand it: a tool that did not go through `Wrap`
is invisible to the adapter and to the attestation unless you declare it.

### Routed Bash (governed shell)

When the agent's policy sets `builtin_exec_routing: governed_shell`, an
allowed `Bash` comes back with `updated_input` rewriting the command to
`mitrity-hook exec <ticket>`. The wrapper hands that to your tool in place of
the model's command; run it as you would run any command, and the gateway
executes the judged bytes in its own sandbox. This needs the `mitrity-hook`
binary on `PATH` and a gateway with `exec.enabled: true`.

### Two approval records per hold

The adapter asks twice for a held action: once without waiting (so an
unreachable edge is noticed in milliseconds), then again with the hold budget.
The edge creates an approval for each; resolve whichever is pending. The
stale one times out on its own. This matches `mitrity-hook` and the other
adapters.

### Session and call ids

`session_id` is, in order: `govern.WithSessionID`, the value carried by
`govern.ContextWithSessionID(ctx, id)`, or one id per `Governor`. `cwd` is
`govern.WithCwd` or the process working directory at call time.
`tool_use_id` is `govern.ContextWithToolUseID(ctx, id)` or a random id per
call.

## The wire client

`govern` sits on `admission.Client`, which you can use for any shape of
agent:

```go
client := admission.New() // discovers the edge from the environment
verdict := client.Decide(ctx, admission.Request{
	ToolName:  "Bash",
	ToolInput: map[string]any{"command": "rm -rf build"},
})
if !verdict.Allowed {
	return errors.New(verdict.Reason)
}
```

`Decide` never fails: it returns a `Verdict` whose `Reason` is safe to show
the model and whose `Err` is set when the deny is the adapter's own (the edge
could not be reached) rather than a policy decision. `Admit` is the single
round trip and returns an `*admission.Error` on any failure, with a `Kind`
and a matching sentinel for `errors.Is`: `ErrConfig`, `ErrUnreachable`,
`ErrTimeout`, `ErrCanceled`, `ErrUnauthorized`, `ErrNotReady`, `ErrProtocol`,
`ErrPayloadTooLarge`. `Attest` and `Health` complete the API.
`admission.ConfigHash` implements the RFC 8785 hash of `config_hash`.

Every call takes a `context.Context`; the adapter applies its own deadline
inside it, and a context that ends first is a deny, never an allow.

## What is not governed

- Tools you did not wrap. Declare them with `WithUngoverned`; the MITRITY
  dashboard shows the gap.
- The agent's own code: an `exec.Command` in your application that never
  passes a wrapped tool boundary. On Linux hosts the MITRITY observer reports
  it after the fact.
- Removing the adapter. It is your code; the control plane detects the
  missing attestation and the silent admission counters, it cannot prevent
  the edit.

## Development

```bash
go vet ./... && golangci-lint run && go test ./... -race
```

Tests run against an in-process fake edge over a Unix socket
(`internal/edgetest`); no MITRITY account and no network are needed. The
conformance tests are numbered after the contract (`C1`–`C20`, and the Go
rows of the wave-2 table).

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities to soc@mitrity.com.

## License

Apache-2.0. Copyright 2026 MITRITY AB.
