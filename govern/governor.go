package govern

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"maps"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	mitrity "github.com/mitrity-io/mitrity-go"
	"github.com/mitrity-io/mitrity-go/admission"
)

const attestRetryInterval = 30 * time.Second

// Governor is the shared state of a set of governed tools: the client, the
// session, the framework identity, the tool inventory and the attestation.
// One Governor per agent process is the norm; it is safe for concurrent use.
type Governor struct {
	client           *admission.Client
	surface          admission.Surface
	framework        string
	frameworkVersion string
	sessionID        string
	processSession   string
	cwd              string
	logger           *slog.Logger
	otherMCPServers  []string

	mu              sync.Mutex
	hooked          []string
	ungoverned      []string
	attested        map[string]string
	attestAttempted map[string]time.Time

	stats stats
}

// Option configures a Governor.
type Option func(*Governor)

// WithClient sets the admission client (default: admission.New(), which
// discovers the edge from the environment).
func WithClient(c *admission.Client) Option { return func(g *Governor) { g.client = c } }

// WithSessionID fixes the session_id sent on every request. Without it the
// session comes from the context (ContextWithSessionID), else one id per
// Governor, generated when it is built.
func WithSessionID(id string) Option { return func(g *Governor) { g.sessionID = id } }

// WithCwd fixes the cwd sent on every request (default: the process working
// directory at call time).
func WithCwd(dir string) Option { return func(g *Governor) { g.cwd = dir } }

// WithLogger sets the logger for the governor's own lines (a warning when an
// attestation fails, an info line when a call is routed). nil disables them.
func WithLogger(l *slog.Logger) Option { return func(g *Governor) { g.logger = l } }

// WithFramework names the agent framework the adapter is wrapping, for the
// attestation's framework and framework_version ("custom" and "" when
// unset). The request surface stays "custom" unless the name is one of the
// surfaces the edge defines (admission.FrameworkForSurface).
func WithFramework(name, version string) Option {
	return func(g *Governor) {
		g.framework = name
		g.frameworkVersion = version
		g.surface = admission.SurfaceCustom
		for surface, framework := range admission.FrameworkForSurface {
			if framework == name {
				g.surface = surface
			}
		}
	}
}

// WithOtherMCPServers declares the MCP servers the agent talks to other than
// the MITRITY gateway, for the attestation's other_mcp_servers. Each is an
// ungoverned tool path unless its calls are wrapped with WrapCaller.
func WithOtherMCPServers(names ...string) Option {
	return func(g *Governor) { g.otherMCPServers = append(g.otherMCPServers, names...) }
}

// WithUngoverned declares execution-capable tools the agent runs without
// wrapping them, for the attestation's unhooked_exec_tools. Naming them is
// what keeps the coverage badge honest.
func WithUngoverned(names ...string) Option {
	return func(g *Governor) { g.ungoverned = append(g.ungoverned, names...) }
}

// New builds a Governor.
func New(opts ...Option) *Governor {
	g := &Governor{
		surface:         admission.SurfaceCustom,
		framework:       "custom",
		logger:          slog.Default(),
		attested:        map[string]string{},
		attestAttempted: map[string]time.Time{},
	}
	for _, opt := range opts {
		opt(g)
	}
	if g.client == nil {
		g.client = admission.New()
	}
	g.processSession = "go-" + randomHex(16)
	g.hooked = dedupe(nil, g.hooked)
	g.ungoverned = dedupe(nil, g.ungoverned)
	g.otherMCPServers = dedupe(nil, g.otherMCPServers)
	return g
}

// Client returns the admission client.
func (g *Governor) Client() *admission.Client { return g.client }

// HookedTools returns the names of the tools admitted through this governor
// so far, sorted.
func (g *Governor) HookedTools() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Sorted(slices.Values(g.hooked))
}

// Declare registers tool names as governed ahead of their first call, so
// the attestation names them before they run. Wrap and WrapCaller register
// names on their own; Declare is for tools wrapped lazily.
func (g *Governor) Declare(names ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.hooked = dedupe(g.hooked, names)
}

// register adds a tool name and reports whether it was new.
func (g *Governor) register(name string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if slices.Contains(g.hooked, name) {
		return false
	}
	g.hooked = append(g.hooked, name)
	return true
}

// Attestation is what the control plane is told: the governed configuration
// as installed, with its config_hash.
func (g *Governor) Attestation() admission.Attestation {
	hooked := g.HookedTools()
	ungoverned := slices.Sorted(slices.Values(g.ungoverned))
	other := slices.Sorted(slices.Values(g.otherMCPServers))
	hashed := map[string]any{
		"adapter":             admission.AdapterName,
		"adapter_version":     mitrity.Version,
		"framework":           g.framework,
		"framework_version":   nullableString(g.frameworkVersion),
		"hooked_tools":        hooked,
		"unhooked_exec_tools": ungoverned,
		"disallowed_tools":    []string{},
		"other_mcp_servers":   other,
	}
	// The hashed document holds only strings and lists of strings, so the
	// canonicalization cannot fail; a failure here would be a bug worth a
	// loud attestation without a hash rather than a silent one.
	hash, _ := admission.ConfigHash(hashed)
	return admission.Attestation{
		Framework:         g.framework,
		FrameworkVersion:  g.frameworkVersion,
		Adapter:           admission.AdapterName,
		AdapterVersion:    mitrity.Version,
		HookedTools:       hooked,
		UnhookedExecTools: ungoverned,
		OtherMCPServers:   other,
		ConfigHash:        hash,
	}
}

// Stats are the governor's counters, for a dashboard or a test.
type Stats struct {
	// Admitted is the number of governed calls; each is one admission
	// request, or two under a hold.
	Admitted    int64
	Allowed     int64
	Denied      int64
	Held        int64
	Unreachable int64
	Routed      int64
}

type stats struct {
	admitted, allowed, denied, held, unreachable, routed atomic.Int64
}

// Stats returns a snapshot of the counters.
func (g *Governor) Stats() Stats {
	return Stats{
		Admitted:    g.stats.admitted.Load(),
		Allowed:     g.stats.allowed.Load(),
		Denied:      g.stats.denied.Load(),
		Held:        g.stats.held.Load(),
		Unreachable: g.stats.unreachable.Load(),
		Routed:      g.stats.routed.Load(),
	}
}

// Admit judges one invocation of toolName with input and returns the input
// the tool must run: the original, or the edge's updated_input merged over
// it. A deny, a hold nobody answered and a failure to obtain a decision are
// each returned as a *DeniedError; the tool must not run then.
//
// Wrap and WrapCaller call this; an agent whose tool shape fits neither can
// call it directly before executing anything.
func (g *Governor) Admit(ctx context.Context, toolName string, input map[string]any) (map[string]any, error) {
	session := g.sessionFor(ctx)
	g.register(toolName)
	g.ensureAttested(ctx, session)

	req := admission.Request{
		Surface:          g.surface,
		FrameworkVersion: g.frameworkVersion,
		SessionID:        session,
		Cwd:              g.cwdFor(),
		ToolName:         toolName,
		ToolInput:        input,
		ToolUseID:        toolUseIDFor(ctx),
	}
	g.stats.admitted.Add(1)
	verdict := g.client.Decide(ctx, req)
	switch {
	case verdict.Allowed:
		g.stats.allowed.Add(1)
	case verdict.Unreachable():
		g.stats.unreachable.Add(1)
		if verdict.Held {
			g.stats.held.Add(1)
		}
	case verdict.Held:
		g.stats.held.Add(1)
	default:
		g.stats.denied.Add(1)
	}
	if !verdict.Allowed {
		return nil, &DeniedError{Tool: toolName, Verdict: verdict}
	}
	if verdict.RoutedTo != "" {
		g.stats.routed.Add(1)
		if g.logger != nil {
			g.logger.Info("MITRITY routed a tool call", "tool", toolName, "routed_to", verdict.RoutedTo)
		}
	}
	return mergeInput(input, verdict.UpdatedInput), nil
}

// mergeInput applies updated_input key by key over the framework's input
// (G5): keys absent from updated keep the model's values. The result is a
// new map; the caller's map is never mutated.
func mergeInput(input, updated map[string]any) map[string]any {
	merged := make(map[string]any, len(input)+len(updated))
	maps.Copy(merged, input)
	maps.Copy(merged, updated)
	return merged
}

func (g *Governor) sessionFor(ctx context.Context) string {
	if g.sessionID != "" {
		return g.sessionID
	}
	if id := SessionIDFrom(ctx); id != "" {
		return id
	}
	return g.processSession
}

func (g *Governor) cwdFor() string {
	if g.cwd != "" {
		return g.cwd
	}
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return dir
}

func (g *Governor) shouldAttest(session, hash string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.attested[session] == hash {
		return false
	}
	now := time.Now()
	// Throttle retries of a FAILED attestation only; a changed hash on an
	// attested session is re-sent at once.
	if last, ok := g.attestAttempted[session]; ok {
		if _, done := g.attested[session]; !done && now.Sub(last) < attestRetryInterval {
			return false
		}
	}
	g.attestAttempted[session] = now
	return true
}

// ensureAttested sends the attestation for session once, and again whenever
// the config hash changes. Attestation is best effort: a failure is logged,
// never a reason to stop the session, because its absence is the signal the
// control plane is built to notice. A failed admit is a deny; the two must
// not be confused.
func (g *Governor) ensureAttested(ctx context.Context, session string) {
	att := g.Attestation()
	if !g.shouldAttest(session, att.ConfigHash) {
		return
	}
	if err := g.client.Attest(ctx, att); err != nil {
		if g.logger != nil {
			g.logger.Warn("MITRITY: could not report the runtime posture", "error", err.Error())
		}
		return
	}
	g.mu.Lock()
	g.attested[session] = att.ConfigHash
	g.mu.Unlock()
}

type contextKey int

const (
	sessionKey contextKey = iota + 1
	toolUseKey
)

// ContextWithSessionID returns a context carrying the session_id for the
// governed calls made with it. A Governor built with WithSessionID ignores
// it.
func ContextWithSessionID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, sessionKey, id)
}

// SessionIDFrom returns the session_id carried by ctx, or "".
func SessionIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(sessionKey).(string)
	return id
}

// ContextWithToolUseID returns a context carrying the tool_use_id for the
// next governed call — the framework's own id for the call, so a reviewer
// can line the decision up against the transcript. Without one the governor
// generates a random id per call.
func ContextWithToolUseID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, toolUseKey, id)
}

func toolUseIDFor(ctx context.Context) string {
	if id, _ := ctx.Value(toolUseKey).(string); id != "" {
		return id
	}
	return "tu_" + randomHex(8)
}

func randomHex(n int) string {
	raw := make([]byte, n)
	// crypto/rand.Read never returns an error on the supported platforms; it
	// terminates the program instead of returning weak bytes.
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)
}

// nullableString is the hashed value of an optional string: null when unset
// (the adapter contract, "Config hash": absent values are null).
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func dedupe(existing, names []string) []string {
	out := existing
	for _, name := range names {
		if name != "" && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}
