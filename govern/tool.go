package govern

import "context"

// Tool is one tool the agent executes itself: a name, and the call that
// runs it with a JSON-shaped input. T is whatever the tool returns.
//
// Name is the tool_name the edge judges (verbatim, case preserved: a policy
// on builtin:bash matches a tool named "Bash"); the input's keys are the
// tool's own argument names, never renamed to help a policy match (G11).
type Tool[T any] interface {
	Name() string
	Call(ctx context.Context, input map[string]any) (T, error)
}

// Func builds a Tool from a name and a function.
func Func[T any](name string, fn func(ctx context.Context, input map[string]any) (T, error)) Tool[T] {
	return &funcTool[T]{name: name, fn: fn}
}

type funcTool[T any] struct {
	name string
	fn   func(ctx context.Context, input map[string]any) (T, error)
}

func (f *funcTool[T]) Name() string { return f.name }

func (f *funcTool[T]) Call(ctx context.Context, input map[string]any) (T, error) {
	return f.fn(ctx, input)
}

// Wrap returns a Tool with the same name whose Call is admitted by the
// MITRITY edge before the inner tool runs: a deny (or a hold nobody
// answered, or an unreachable edge) returns the zero T and a *DeniedError;
// an allow runs the inner tool with the edge's updated_input merged over the
// input. The name is registered with the governor for the attestation.
func Wrap[T any](g *Governor, tool Tool[T]) Tool[T] {
	g.Declare(tool.Name())
	return &governed[T]{g: g, inner: tool}
}

// WrapFunc is Wrap over Func.
func WrapFunc[T any](g *Governor, name string, fn func(ctx context.Context, input map[string]any) (T, error)) Tool[T] {
	return Wrap(g, Func(name, fn))
}

// WrapAll wraps every tool in the slice with one governor, preserving order.
func WrapAll[T any](g *Governor, tools []Tool[T]) []Tool[T] {
	out := make([]Tool[T], len(tools))
	for i, tool := range tools {
		out[i] = Wrap(g, tool)
	}
	return out
}

type governed[T any] struct {
	g     *Governor
	inner Tool[T]
}

func (t *governed[T]) Name() string { return t.inner.Name() }

func (t *governed[T]) Call(ctx context.Context, input map[string]any) (T, error) {
	admitted, err := t.g.Admit(ctx, t.inner.Name(), input)
	if err != nil {
		var zero T
		return zero, err
	}
	return t.inner.Call(ctx, admitted)
}
