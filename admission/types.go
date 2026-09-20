package admission

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Surface names the calling framework, as the request names it. It is not
// the audit surface (always "agent_hook" for every call on this API).
type Surface string

const (
	SurfaceClaudeCode     Surface = "claude_code"
	SurfaceClaudeAgentSDK Surface = "claude_agent_sdk"
	SurfaceLangChain      Surface = "langchain"
	SurfaceOpenAIAgents   Surface = "openai_agents"
	SurfaceCrewAI         Surface = "crewai"
	// SurfaceCustom is the surface of a Go agent: no framework surface is
	// defined for Go, so the request says "custom" and the attestation names
	// the framework the developer declares (the adapter contract, "Go").
	SurfaceCustom Surface = "custom"
)

// FrameworkForSurface maps a request surface (underscores) to the
// RuntimeAttestation.framework spelling (hyphens). An implementation must map
// between them rather than pass either through.
var FrameworkForSurface = map[Surface]string{
	SurfaceClaudeCode:     "claude-code",
	SurfaceClaudeAgentSDK: "claude-agent-sdk",
	SurfaceLangChain:      "langchain",
	SurfaceOpenAIAgents:   "openai-agents",
	SurfaceCrewAI:         "crewai",
	SurfaceCustom:         "custom",
}

// ExecCapableTools are the Claude Code / Agent SDK built-in tools that can
// change something outside the model's context: the inventory
// unhooked_exec_tools is measured against. Read, Glob and Grep are
// deliberately absent, as in the hook.
var ExecCapableTools = []string{"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch"}

// AdapterName is what this module reports as RuntimeAttestation.adapter.
const AdapterName = "mitrity-go"

// DecisionKind is the edge's answer: allow, deny or held.
type DecisionKind string

const (
	Allow DecisionKind = "allow"
	Deny  DecisionKind = "deny"
	Held  DecisionKind = "held"
)

// Request is one POST /v1/admit body.
//
// ToolName and ToolInput are the framework's, verbatim: nothing is renamed or
// dropped, so a policy that matches a key on the MCP entrance matches the
// same key here. (JSON object members have no order on the wire; the edge
// flattens them by name.)
type Request struct {
	// ToolName is the framework's name for the tool, case preserved.
	ToolName string
	// ToolInput is the framework's input object. A nil map is sent as {}.
	ToolInput map[string]any
	// Surface is the calling framework; empty means SurfaceCustom.
	Surface Surface
	// FrameworkVersion, SessionID, Cwd and ToolUseID are omitted when empty.
	FrameworkVersion string
	SessionID        string
	Cwd              string
	ToolUseID        string
	// HoldTimeoutSeconds is the caller's time budget for a hold. nil omits the
	// field (the edge waits as long as it is configured to); 0 means "do not
	// wait". Decide sets it; a direct Admit caller may.
	HoldTimeoutSeconds *int
}

// wire validates the request and returns its JSON object.
func (r Request) wire() (map[string]any, error) {
	surface := r.Surface
	if surface == "" {
		surface = SurfaceCustom
	}
	if _, ok := FrameworkForSurface[surface]; !ok {
		return nil, newError(KindProtocol, fmt.Sprintf("unknown surface %q", string(surface)))
	}
	if strings.TrimSpace(r.ToolName) == "" {
		return nil, newError(KindProtocol, "tool_name is required")
	}
	input := r.ToolInput
	if input == nil {
		input = map[string]any{}
	}
	body := map[string]any{
		"surface":    string(surface),
		"tool_name":  r.ToolName,
		"tool_input": input,
	}
	if r.FrameworkVersion != "" {
		body["framework_version"] = r.FrameworkVersion
	}
	if r.SessionID != "" {
		body["session_id"] = r.SessionID
	}
	if r.Cwd != "" {
		body["cwd"] = r.Cwd
	}
	if r.ToolUseID != "" {
		body["tool_use_id"] = r.ToolUseID
	}
	if r.HoldTimeoutSeconds != nil {
		if *r.HoldTimeoutSeconds < 0 {
			return nil, newError(KindProtocol, "hold_timeout_seconds must not be negative")
		}
		body["hold_timeout_seconds"] = *r.HoldTimeoutSeconds
	}
	return body, nil
}

func (r Request) withHold(seconds int) Request {
	r.HoldTimeoutSeconds = &seconds
	return r
}

// Decision is one POST /v1/admit response.
//
// Held is not an allow: the caller blocks the tool call and either waits
// (Client.Decide) or gives up. UpdatedInput is present only on allow and MUST
// be what runs.
type Decision struct {
	Decision    DecisionKind
	Reason      string
	AdmissionID string
	RiskScore   float64
	// ApprovalID is set when the decision is held, and on a deny whose reason
	// is that the budget expired with the approval still open.
	ApprovalID string
	// UpdatedInput is the rewritten tool input, nil when absent. Keys not
	// present keep their original value: it is merged over the framework's
	// input.
	UpdatedInput map[string]any
	// RoutedTo is "governed_shell" when UpdatedInput routes the call there.
	RoutedTo string
}

// Allowed reports whether the edge allowed the call.
func (d Decision) Allowed() bool { return d.Decision == Allow }

// parseDecision parses a response body, refusing anything that is not a
// decision. An unrecognized decision value is not a decision: refusing it here
// is what keeps a future protocol change from being read as an allow.
func parseDecision(body []byte) (Decision, error) {
	var data any
	if err := json.Unmarshal(body, &data); err != nil {
		return Decision{}, wrapError(KindProtocol, "admission response was not valid JSON", err)
	}
	object, ok := data.(map[string]any)
	if !ok {
		return Decision{}, newError(KindProtocol, "admission response was not a JSON object")
	}
	kind, _ := object["decision"].(string)
	switch DecisionKind(kind) {
	case Allow, Deny, Held:
	default:
		return Decision{}, newError(KindProtocol, fmt.Sprintf("admission returned an unrecognized decision %q", kind))
	}
	d := Decision{Decision: DecisionKind(kind)}
	d.Reason, _ = object["reason"].(string)
	d.AdmissionID, _ = object["admission_id"].(string)
	d.ApprovalID, _ = object["approval_id"].(string)
	d.RoutedTo, _ = object["routed_to"].(string)
	if raw, present := object["risk_score"]; present {
		score, ok := raw.(float64)
		if !ok {
			return Decision{}, newError(KindProtocol, "risk_score was not a number")
		}
		d.RiskScore = score
	}
	if raw, present := object["updated_input"]; present && raw != nil {
		updated, ok := raw.(map[string]any)
		if !ok {
			return Decision{}, newError(KindProtocol, "updated_input was not an object")
		}
		d.UpdatedInput = updated
	}
	return d, nil
}

// Verdict is the outcome of the two-phase decision (Client.Decide). Never an
// error value: a failure is a deny with Err set.
//
// Allowed is the only field a framework integration needs to branch on.
// Reason is the message for the model, phrased so an outage is
// distinguishable from a policy decision. Err is set when the deny is the
// adapter's own (the edge could not be reached or did not answer in time); it
// is nil for a policy deny.
type Verdict struct {
	Allowed bool
	Reason  string
	// Decision is the edge's answer, nil when none arrived.
	Decision *Decision
	// Err is the *Error behind an adapter-side deny.
	Err error
	// UpdatedInput and RoutedTo are copied from an allow's Decision.
	UpdatedInput map[string]any
	RoutedTo     string
	// Held is true when the call was held and the hold did not resolve to an
	// allow inside the budget.
	Held bool
}

// PolicyDenied reports that the edge judged the call and said no (as opposed
// to not answering).
func (v Verdict) PolicyDenied() bool { return !v.Allowed && v.Err == nil && !v.Held }

// Unreachable reports that the deny is the adapter's own fail-closed
// decision.
func (v Verdict) Unreachable() bool { return v.Err != nil }

// SandboxPosture is the runtime's OS-sandbox configuration, each key nil
// when not known. A nil is evaluated by the control plane as the unsafe
// default, so silence never suppresses a finding.
type SandboxPosture struct {
	Enabled                  *bool
	AllowUnsandboxedCommands *bool
	FailIfUnavailable        *bool
}

func (s SandboxPosture) wire() map[string]any {
	return map[string]any{
		"enabled":                    nullableBool(s.Enabled),
		"allow_unsandboxed_commands": nullableBool(s.AllowUnsandboxedCommands),
		"fail_if_unavailable":        nullableBool(s.FailIfUnavailable),
	}
}

func nullableBool(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

// Attestation is a RuntimeAttestation: the runtime's self-report of its
// governance posture. Self-asserted, and honest by construction: the lists
// come from the configuration the adapter installed, not from what it
// intended.
type Attestation struct {
	Framework        string
	FrameworkVersion string
	Adapter          string
	AdapterVersion   string
	HookedTools      []string
	// UnhookedExecTools are execution-capable tools the runtime has that the
	// adapter does not intercept.
	UnhookedExecTools []string
	DisallowedTools   []string
	OtherMCPServers   []string
	PermissionMode    string
	Sandbox           *SandboxPosture
	// ConfigHash is the SHA-256 hex of the RFC 8785 serialization of the
	// governed configuration (see ConfigHash).
	ConfigHash string
}

// wire returns the JSON object of POST /v1/attest: empty lists and strings
// are omitted, as the Python adapter omits them.
func (a Attestation) wire() map[string]any {
	body := map[string]any{
		"framework":       a.Framework,
		"adapter":         a.Adapter,
		"adapter_version": a.AdapterVersion,
	}
	if a.FrameworkVersion != "" {
		body["framework_version"] = a.FrameworkVersion
	}
	for key, value := range map[string][]string{
		"hooked_tools":        a.HookedTools,
		"unhooked_exec_tools": a.UnhookedExecTools,
		"disallowed_tools":    a.DisallowedTools,
		"other_mcp_servers":   a.OtherMCPServers,
	} {
		if len(value) > 0 {
			body[key] = value
		}
	}
	if a.PermissionMode != "" {
		body["permission_mode"] = a.PermissionMode
	}
	if a.Sandbox != nil {
		body["sandbox"] = a.Sandbox.wire()
	}
	if a.ConfigHash != "" {
		body["config_hash"] = a.ConfigHash
	}
	return body
}
