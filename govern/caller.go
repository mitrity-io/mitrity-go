package govern

import "context"

// Caller is the shape of an MCP tool client: Call(ctx, tool, args). R is the
// client's result type.
type Caller[R any] interface {
	Call(ctx context.Context, tool string, args map[string]any) (R, error)
}

// CallerFunc adapts a function to Caller.
type CallerFunc[R any] func(ctx context.Context, tool string, args map[string]any) (R, error)

// Call implements Caller.
func (f CallerFunc[R]) Call(ctx context.Context, tool string, args map[string]any) (R, error) {
	return f(ctx, tool, args)
}

// WrapCaller returns a Caller whose every Call is admitted by the MITRITY
// edge first, with tool as the tool_name and args as the tool_input, verbatim.
// A deny returns the zero R and a *DeniedError; an allow calls inner with the
// edge's updated_input merged over args. Tool names are registered with the
// governor as they are first called, so the attestation names what was
// actually governed; Governor.Declare names them ahead of time.
//
// Do not wrap a client that talks to the MITRITY gateway: the gateway's own
// pipeline already judges those calls as mcp:<tool>, and admitting them again
// would audit one action twice. WrapCaller is for a client that reaches an
// MCP server directly, which is otherwise an ungoverned tool path (declare
// the server with WithOtherMCPServers either way). The edge evaluates a call
// admitted here as builtin:<lowercased tool>, like any admitted tool.
func WrapCaller[R any](g *Governor, inner Caller[R]) Caller[R] {
	return &governedCaller[R]{g: g, inner: inner}
}

type governedCaller[R any] struct {
	g     *Governor
	inner Caller[R]
}

func (c *governedCaller[R]) Call(ctx context.Context, tool string, args map[string]any) (R, error) {
	admitted, err := c.g.Admit(ctx, tool, args)
	if err != nil {
		var zero R
		return zero, err
	}
	return c.inner.Call(ctx, tool, admitted)
}
