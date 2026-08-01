// Package a9trust implements the exact cryptographic transcripts, key
// validation, and canonical encodings in the production A9 v1 adapter. It
// intentionally depends only on the Go standard library.
package a9trust

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxIJSONInteger uint64 = 9007199254740991

var (
	ErrDuplicateKey = errors.New("duplicate JSON key")
	ErrNonIJSON     = errors.New("value is outside the v1 I-JSON profile")
)

// ParseStrictJSON parses a single JSON value, preserving integer spellings and
// rejecting duplicate object names at every nesting level.
func ParseStrictJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("%w: invalid UTF-8", ErrNonIJSON)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := parseJSONValue(dec)
	if err != nil {
		return nil, err
	}
	if token, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("trailing JSON token %v", token)
	}
	return value, nil
}

func parseJSONValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch v := token.(type) {
	case json.Delim:
		switch v {
		case '{':
			object := make(map[string]any)
			for dec.More() {
				nameToken, err := dec.Token()
				if err != nil {
					return nil, err
				}
				name, ok := nameToken.(string)
				if !ok {
					return nil, errors.New("JSON object name is not a string")
				}
				if _, exists := object[name]; exists {
					return nil, fmt.Errorf("%w: %q", ErrDuplicateKey, name)
				}
				child, err := parseJSONValue(dec)
				if err != nil {
					return nil, err
				}
				object[name] = child
			}
			end, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if end != json.Delim('}') {
				return nil, errors.New("unterminated JSON object")
			}
			return object, nil
		case '[':
			var array []any
			for dec.More() {
				child, err := parseJSONValue(dec)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			end, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if end != json.Delim(']') {
				return nil, errors.New("unterminated JSON array")
			}
			return array, nil
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter %q", v)
		}
	case nil, bool, string, json.Number:
		return v, nil
	default:
		return nil, fmt.Errorf("unexpected JSON token type %T", token)
	}
}

// Canonicalize implements the deliberately narrow JCS profile used by the v1
// contract: ASCII strings and object names, booleans/null, arrays, and
// non-negative integers no larger than 2^53-1.
func Canonicalize(value any) ([]byte, error) {
	var out bytes.Buffer
	if err := appendCanonical(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func appendCanonical(out *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		if err := appendASCIIString(out, v); err != nil {
			return err
		}
	case json.Number:
		canonical, err := canonicalInteger(string(v))
		if err != nil {
			return err
		}
		out.WriteString(canonical)
	case int:
		if v < 0 {
			return fmt.Errorf("%w: negative integer", ErrNonIJSON)
		}
		return appendCanonical(out, json.Number(strconv.FormatInt(int64(v), 10)))
	case int64:
		if v < 0 {
			return fmt.Errorf("%w: negative integer", ErrNonIJSON)
		}
		return appendCanonical(out, json.Number(strconv.FormatInt(v, 10)))
	case uint:
		return appendCanonical(out, json.Number(strconv.FormatUint(uint64(v), 10)))
	case uint32:
		return appendCanonical(out, json.Number(strconv.FormatUint(uint64(v), 10)))
	case uint64:
		return appendCanonical(out, json.Number(strconv.FormatUint(v, 10)))
	case float32, float64:
		return fmt.Errorf("%w: floating-point number", ErrNonIJSON)
	case []any:
		out.WriteByte('[')
		for i, child := range v {
			if i != 0 {
				out.WriteByte(',')
			}
			if err := appendCanonical(out, child); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		names := make([]string, 0, len(v))
		for name := range v {
			if !isASCII(name) {
				return fmt.Errorf("%w: non-ASCII object name", ErrNonIJSON)
			}
			names = append(names, name)
		}
		sort.Strings(names)
		out.WriteByte('{')
		for i, name := range names {
			if i != 0 {
				out.WriteByte(',')
			}
			if err := appendASCIIString(out, name); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := appendCanonical(out, v[name]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("%w: unsupported Go type %T", ErrNonIJSON, value)
	}
	return nil
}

func canonicalInteger(raw string) (string, error) {
	if raw == "" || raw == "-0" || strings.ContainsAny(raw, ".eE+-") {
		return "", fmt.Errorf("%w: non-integer JSON number %q", ErrNonIJSON, raw)
	}
	if raw != "0" && raw[0] == '0' {
		return "", fmt.Errorf("%w: leading zero in %q", ErrNonIJSON, raw)
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("%w: non-integer JSON number %q", ErrNonIJSON, raw)
		}
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || n > maxIJSONInteger {
		return "", fmt.Errorf("%w: integer range %q", ErrNonIJSON, raw)
	}
	return strconv.FormatUint(n, 10), nil
}

func appendASCIIString(out *bytes.Buffer, value string) error {
	if !isASCII(value) {
		return fmt.Errorf("%w: non-ASCII string", ErrNonIJSON)
	}
	out.WriteByte('"')
	for i := 0; i < len(value); i++ {
		switch c := value[i]; c {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteByte(c)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if c < 0x20 {
				const hex = "0123456789abcdef"
				out.WriteString(`\u00`)
				out.WriteByte(hex[c>>4])
				out.WriteByte(hex[c&0x0f])
			} else {
				out.WriteByte(c)
			}
		}
	}
	out.WriteByte('"')
	return nil
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func cloneObject(object map[string]any) map[string]any {
	cloned := make(map[string]any, len(object))
	for key, value := range object {
		cloned[key] = value
	}
	return cloned
}
