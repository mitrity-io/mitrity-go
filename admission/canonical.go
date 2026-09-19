package admission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"unicode/utf16"
)

// RFC 8785 (JSON Canonicalization Scheme) for the values an attestation
// hashes.
//
// Two independent implementations hash the same configuration — this adapter
// and whatever later checks a runtime against it — so the byte sequence has
// to be pinned rather than left to a JSON library's defaults. The subset here
// is what a governed configuration contains: strings, booleans, integers,
// null, lists and objects. Non-integral floats are refused on purpose:
// nothing in the hashed document is a float, and JCS float formatting is the
// one part worth not getting subtly wrong. An integral float (what
// encoding/json decodes a JSON integer into) is serialized as the integer it
// is, which is also what JCS prescribes for it.

var integerLiteral = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// CanonicalJSON serializes value per RFC 8785: members sorted by the UTF-16
// code units of their names, no whitespace, minimal escapes, UTF-8.
//
// value may be any JSON-shaped Go value: map[string]any, []any, string, bool,
// nil, the integer types, json.Number, or anything encoding/json can marshal
// (a struct with json tags, a typed slice or map), which is normalized through
// encoding/json first.
func CanonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := canonical(&buf, value, true); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ConfigHash is the SHA-256, hex-encoded, of the canonical serialization of
// value — the RuntimeAttestation.config_hash rule.
func ConfigHash(value any) (string, error) {
	data, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func canonical(buf *bytes.Buffer, value any, normalize bool) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeEscaped(buf, v)
	case int:
		buf.WriteString(strconv.FormatInt(int64(v), 10))
	case int8:
		buf.WriteString(strconv.FormatInt(int64(v), 10))
	case int16:
		buf.WriteString(strconv.FormatInt(int64(v), 10))
	case int32:
		buf.WriteString(strconv.FormatInt(int64(v), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(v, 10))
	case uint:
		buf.WriteString(strconv.FormatUint(uint64(v), 10))
	case uint8:
		buf.WriteString(strconv.FormatUint(uint64(v), 10))
	case uint16:
		buf.WriteString(strconv.FormatUint(uint64(v), 10))
	case uint32:
		buf.WriteString(strconv.FormatUint(uint64(v), 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(v, 10))
	case float32:
		return writeFloat(buf, float64(v))
	case float64:
		return writeFloat(buf, v)
	case json.Number:
		return writeNumber(buf, v)
	case []byte:
		return fmt.Errorf("canonical JSON does not serialize bytes")
	case map[string]any:
		return writeObject(buf, v)
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonical(buf, item, normalize); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []string:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeEscaped(buf, item)
		}
		buf.WriteByte(']')
	default:
		if !normalize {
			return fmt.Errorf("canonical JSON does not serialize %T", value)
		}
		generic, err := roundTrip(value)
		if err != nil {
			return err
		}
		return canonical(buf, generic, false)
	}
	return nil
}

// roundTrip normalizes an arbitrary value through encoding/json into the
// generic shape (maps, slices, strings, json.Number). Strings survive the trip
// unchanged, so the HTML escaping encoding/json applies on the way out never
// reaches the canonical bytes.
func roundTrip(value any) (any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonical JSON does not serialize %T: %w", value, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	return generic, nil
}

func writeObject(buf *bytes.Buffer, object map[string]any) error {
	type member struct {
		key   string
		units []uint16
	}
	members := make([]member, 0, len(object))
	for key := range object {
		members = append(members, member{key: key, units: utf16.Encode([]rune(key))})
	}
	// JCS orders members by the UTF-16 code units of their names.
	sort.Slice(members, func(i, j int) bool { return lessUTF16(members[i].units, members[j].units) })
	buf.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeEscaped(buf, m.key)
		buf.WriteByte(':')
		if err := canonical(buf, object[m.key], true); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func lessUTF16(a, b []uint16) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func writeFloat(buf *bytes.Buffer, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("canonical JSON does not serialize NaN or Inf")
	}
	if f != math.Trunc(f) || math.Abs(f) > 1<<53 {
		return fmt.Errorf("canonical JSON does not serialize the non-integral float %v", f)
	}
	buf.WriteString(strconv.FormatInt(int64(f), 10)) // -0 becomes 0, as ES6 prints it
	return nil
}

func writeNumber(buf *bytes.Buffer, n json.Number) error {
	text := n.String()
	if integerLiteral.MatchString(text) {
		if text == "-0" {
			text = "0"
		}
		buf.WriteString(text)
		return nil
	}
	f, err := n.Float64()
	if err != nil {
		return fmt.Errorf("canonical JSON does not serialize the number %q", text)
	}
	return writeFloat(buf, f)
}

var shortEscapes = map[rune]string{
	'\b': `\b`,
	'\t': `\t`,
	'\n': `\n`,
	'\f': `\f`,
	'\r': `\r`,
	'"':  `\"`,
	'\\': `\\`,
}

// writeEscaped writes a JSON string with only the escapes RFC 8259 requires:
// the short forms for the seven characters that have one, \u00XX for the
// other control characters, and everything else literal.
func writeEscaped(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		if short, ok := shortEscapes[r]; ok {
			buf.WriteString(short)
		} else if r < 0x20 {
			fmt.Fprintf(buf, `\u%04x`, r)
		} else {
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}
