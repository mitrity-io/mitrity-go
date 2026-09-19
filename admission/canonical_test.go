package admission_test

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/mitrity-io/mitrity-go/admission"
)

func canonical(t *testing.T, v any) string {
	t.Helper()
	out, err := admission.CanonicalJSON(v)
	if err != nil {
		t.Fatalf("CanonicalJSON(%v): %v", v, err)
	}
	return string(out)
}

func TestCanonicalJSONSortsMembersAndDropsWhitespace(t *testing.T) {
	value := map[string]any{"b": 1, "a": []any{true, nil, "x\n", map[string]any{"z": false, "y": 0}}}
	if got := canonical(t, value); got != `{"a":[true,null,"x\n",{"y":0,"z":false}],"b":1}` {
		t.Fatalf("got %s", got)
	}
}

func TestCanonicalJSONKeepsUnicodeLiteralAndEscapesControlCharacters(t *testing.T) {
	if got := canonical(t, map[string]any{"k": "é\x1f\"\\"}); got != `{"k":"é\u001f\"\\"}` {
		t.Fatalf("got %s", got)
	}
	if got := canonical(t, " \x7f\b\f\r\t"); got != "\" \x7f\\b\\f\\r\\t\"" {
		t.Fatalf("got %s", got)
	}
}

func TestCanonicalJSONOrdersKeysByUTF16CodeUnits(t *testing.T) {
	// U+1D11E (a surrogate pair in UTF-16) sorts before U+FF5E under JCS,
	// though it sorts after by code point.
	if got := canonical(t, map[string]any{"～": 1, "\U0001d11e": 2}); got != "{\"\U0001d11e\":2,\"～\":1}" {
		t.Fatalf("got %s", got)
	}
}

func TestCanonicalJSONRefusesNonIntegralFloatsAndBytes(t *testing.T) {
	for _, v := range []any{map[string]any{"risk": 0.5}, []byte("hi"), map[string]any{"n": json.Number("1.5")}, float32(2.5)} {
		if _, err := admission.CanonicalJSON(v); err == nil {
			t.Errorf("CanonicalJSON(%v) succeeded, want an error", v)
		}
	}
}

func TestCanonicalJSONWritesIntegralFloatsAndNumbersAsIntegers(t *testing.T) {
	// encoding/json decodes JSON integers into float64; JCS prints them as integers.
	var decoded any
	if err := json.Unmarshal([]byte(`{"n": 42, "z": -0, "big": 9007199254740992}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if got := canonical(t, decoded); got != `{"big":9007199254740992,"n":42,"z":0}` {
		t.Fatalf("got %s", got)
	}
	if got := canonical(t, map[string]any{"a": json.Number("-0"), "b": json.Number("1e2"), "c": uint8(7), "d": int64(-3)}); got != `{"a":0,"b":100,"c":7,"d":-3}` {
		t.Fatalf("got %s", got)
	}
}

func TestCanonicalJSONNormalizesStructsAndTypedSlices(t *testing.T) {
	type doc struct {
		Tools   []string          `json:"hooked_tools"`
		Adapter string            `json:"adapter"`
		Meta    map[string]string `json:"meta,omitempty"`
		Count   int               `json:"count"`
	}
	value := doc{Tools: []string{"Write", "Bash"}, Adapter: "mitrity-go", Meta: map[string]string{"b": "<2>", "a": "&"}, Count: 3}
	if got := canonical(t, value); got != `{"adapter":"mitrity-go","count":3,"hooked_tools":["Write","Bash"],"meta":{"a":"&","b":"<2>"}}` {
		t.Fatalf("got %s", got)
	}
}

func TestConfigHashIsSHA256Hex(t *testing.T) {
	digest, err := admission.ConfigHash(map[string]any{"hooked_tools": []string{"Bash"}, "adapter": "mitrity-go"})
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(digest) {
		t.Fatalf("digest = %q", digest)
	}
	same, _ := admission.ConfigHash(map[string]any{"adapter": "mitrity-go", "hooked_tools": []any{"Bash"}})
	other, _ := admission.ConfigHash(map[string]any{"adapter": "mitrity-go", "hooked_tools": []string{"Write"}})
	if digest != same || digest == other {
		t.Fatalf("hashes: %s %s %s", digest, same, other)
	}
	if _, err := admission.ConfigHash(map[string]any{"f": 1.5}); err == nil {
		t.Fatal("ConfigHash of a float succeeded")
	}
}

func TestConfigHashMatchesThePythonAdapterForTheSpecExample(t *testing.T) {
	// The adapters.md example, hashed identically by every adapter: the
	// canonical bytes are checked here, so a divergence is a failing test
	// rather than a drift alarm in production.
	example := map[string]any{
		"adapter":           "mitrity-python",
		"adapter_version":   "0.1.0",
		"disallowed_tools":  []any{},
		"framework":         "claude-agent-sdk",
		"framework_version": "0.2.157",
		"hooked_tools":      []any{"Bash", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch", "Write"},
		"mcp_servers":       []any{"mitrity"},
		"other_mcp_servers": []any{},
		"permission_mode":   "default",
		"sandbox":           map[string]any{"allow_unsandboxed_commands": false, "enabled": true, "fail_if_unavailable": true},
		"setting_sources":   []any{},
		"strict_mcp_config": true,
	}
	want := `{"adapter":"mitrity-python","adapter_version":"0.1.0","disallowed_tools":[],"framework":"claude-agent-sdk","framework_version":"0.2.157","hooked_tools":["Bash","Edit","MultiEdit","NotebookEdit","WebFetch","WebSearch","Write"],"mcp_servers":["mitrity"],"other_mcp_servers":[],"permission_mode":"default","sandbox":{"allow_unsandboxed_commands":false,"enabled":true,"fail_if_unavailable":true},"setting_sources":[],"strict_mcp_config":true}`
	if got := canonical(t, example); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
