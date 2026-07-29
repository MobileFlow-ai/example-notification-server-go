package schema

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

type corpus struct {
	positive  map[string]any
	negatives map[string]map[string]any
}

func TestEveryPositiveObjectPassesItsClosedSchema(t *testing.T) {
	vectors := loadCorpus(t)
	rotation := object(t, vectors.positive["online_signer_rotation"])
	boundary := object(t, vectors.positive["topic_epoch_boundary"])
	positiveCases := []struct {
		name  string
		kind  Kind
		value any
	}{
		{"assertion", AssertionKind, nestedValue(t, vectors.positive["assertion"])},
		{"control", ControlEventKind, nestedValue(t, vectors.positive["control_upsert"])},
		{"watermark", WatermarkKind, nestedValue(t, vectors.positive["watermark_current"])},
		{"keyset", KeysetKind, nestedValue(t, vectors.positive["keyset"])},
		{"online transition keyset", KeysetKind, nestedValue(t, rotation["transition_keyset"])},
		{"online cutover keyset", KeysetKind, nestedValue(t, rotation["cutover_keyset"])},
		{"topic transition keyset", KeysetKind, nestedValue(t, boundary["transition_keyset"])},
		{"old epoch assertion", AssertionKind, nestedValue(t, boundary["old_epoch_assertion"])},
		{"new epoch assertion", AssertionKind, nestedValue(t, boundary["new_epoch_assertion"])},
		{"subscription replacement", SubscriptionsReplaceKind, nestedValue(t, vectors.positive["subscription_replace"])},
		{"vault CAS result", ResultKind, vectors.positive["vault_cas_result"]},
	}
	for _, testCase := range positiveCases {
		t.Run(testCase.name, func(t *testing.T) {
			raw := marshal(t, testCase.value)
			decoded, err := Decode(testCase.kind, raw)
			if err != nil {
				t.Fatalf("Decode(%s): %v", testCase.kind, err)
			}
			protocol, ok := decoded["protocol"].(string)
			if !ok {
				t.Fatal("decoded protocol is not a string")
			}
			if gotKind, ok := KindForProtocol(protocol); !ok || gotKind != testCase.kind {
				t.Fatalf("KindForProtocol(%q) = %q, %v; want %q", protocol, gotKind, ok, testCase.kind)
			}
		})
	}
}

func TestPublishedSchemaNegativeVectors(t *testing.T) {
	vectors := loadCorpus(t)
	testCases := []struct {
		id   string
		kind Kind
		base func(*testing.T) any
	}{
		{"assertion_unsigned_one_byte", AssertionKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["assertion"])
		}},
		{"duplicate_json_key", AssertionKind, nil},
		{"unknown_assertion_field", AssertionKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["assertion"])
		}},
		{"padded_signature", AssertionKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["assertion"])
		}},
		{"wrong_length_base64url", AssertionKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["assertion"])
		}},
		{"noncanonical_uuid", SubscriptionsReplaceKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["subscription_replace"])
		}},
		{"wrong_environment_spelling", AssertionKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["assertion"])
		}},
		{"wrong_audience", AssertionKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["assertion"])
		}},
		{"welcome_purpose", AssertionKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["assertion"])
		}},
		{"noncanonical_timestamp", AssertionKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["assertion"])
		}},
		{"integer_as_float", AssertionKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["assertion"])
		}},
		{"integer_overflow", AssertionKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["assertion"])
		}},
		{"control_upsert_shape_mismatch", ControlEventKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["control_upsert"])
		}},
		{"noncanonical_transport_id_uppercase", SubscriptionsReplaceKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["subscription_replace"])
		}},
		{"topic_wrong_length", SubscriptionsReplaceKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["subscription_replace"])
		}},
		{"welcome_topic_kind", SubscriptionsReplaceKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["subscription_replace"])
		}},
		{"duplicate_subscription", SubscriptionsReplaceKind, func(t *testing.T) any {
			return nestedValue(t, vectors.positive["subscription_replace"])
		}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.id, func(t *testing.T) {
			vector, ok := vectors.negatives[testCase.id]
			if !ok {
				t.Fatalf("negative vector %q is absent", testCase.id)
			}
			mutation := object(t, vector["mutation"])
			var raw []byte
			if testCase.id == "duplicate_json_key" {
				raw = []byte(stringValue(t, mutation["raw_utf8"]))
			} else {
				base := clone(t, testCase.base(t))
				applyPatch(t, base, mutation)
				raw = marshal(t, base)
			}
			_, err := Decode(testCase.kind, raw)
			assertVectorFailure(t, vector, err)
		})
	}
}

func TestStrictJSONRejectsAmbiguityAndTrailingBytes(t *testing.T) {
	testCases := []struct {
		name   string
		raw    []byte
		reason Reason
	}{
		{"BOM", append([]byte{0xef, 0xbb, 0xbf}, []byte(`{}`)...), ReasonFieldDomain},
		{"invalid UTF-8", []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}, ReasonFieldDomain},
		{"unpaired high surrogate", []byte(`{"x":"\ud800"}`), ReasonFieldDomain},
		{"unpaired low surrogate", []byte(`{"x":"\udfff"}`), ReasonFieldDomain},
		{"nested duplicate", []byte(`{"x":{"same":1,"same":2}}`), ReasonDuplicateKey},
		{"float", []byte(`{"x":1.0}`), ReasonNonIJSONNumber},
		{"exponent", []byte(`{"x":1e0}`), ReasonNonIJSONNumber},
		{"negative zero", []byte(`{"x":-0}`), ReasonNonIJSONNumber},
		{"unsafe integer", []byte(`{"x":9007199254740992}`), ReasonIntegerRange},
		{"trailing whitespace", []byte("{}\n"), ReasonFieldDomain},
		{"trailing token", []byte(`{} []`), ReasonFieldDomain},
		{"trailing text", []byte(`{} attacker-data`), ReasonFieldDomain},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Parse(testCase.raw)
			terminal, reason, ok := Verdict(err)
			if !ok || terminal != TerminalInvalid || reason != testCase.reason {
				t.Fatalf("Parse error = %v (%s/%s, %v), want INVALID/%s", err, terminal, reason, ok, testCase.reason)
			}
		})
	}
	if _, err := Parse([]byte(`{"nested":[0,true,null,"valid"]}`)); err != nil {
		t.Fatalf("strict valid JSON rejected: %v", err)
	}
}

func TestValidationErrorsNeverEchoAttackerMemberNames(t *testing.T) {
	const secretName = "apns-token-do-not-echo-0123456789"
	t.Run("invalid value", func(t *testing.T) {
		raw := []byte(`{"` + secretName + `":1.0}`)
		_, err := Parse(raw)
		if err == nil {
			t.Fatal("non-integer member accepted")
		}
		if strings.Contains(err.Error(), secretName) {
			t.Fatalf("value failure echoed attacker member name: %q", err)
		}
	})

	t.Run("duplicate", func(t *testing.T) {
		raw := []byte(`{"` + secretName + `":1,"` + secretName + `":2}`)
		_, err := Parse(raw)
		if err == nil {
			t.Fatal("duplicate member accepted")
		}
		if strings.Contains(err.Error(), secretName) {
			t.Fatalf("duplicate failure echoed attacker member name: %q", err)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		vectors := loadCorpus(t)
		assertion := object(t, clone(t, nestedValue(t, vectors.positive["assertion"])))
		assertion[secretName] = true
		_, err := Decode(AssertionKind, marshal(t, assertion))
		if err == nil {
			t.Fatal("unknown member accepted")
		}
		if strings.Contains(err.Error(), secretName) {
			t.Fatalf("unknown-field failure echoed attacker member name: %q", err)
		}
	})
}

func loadCorpus(t *testing.T) corpus {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve schema test path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", ".."))
	read := func(name string, target any) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(
			root,
			"contracts",
			"xmtp_push",
			"a9_adapter",
			"v1",
			"vectors",
			name,
		))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(target); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
	}

	var positive map[string]any
	read("positive.json", &positive)
	var negativeRoot struct {
		Vectors []map[string]any `json:"vectors"`
	}
	read("negative.json", &negativeRoot)
	negatives := make(map[string]map[string]any, len(negativeRoot.Vectors))
	for _, vector := range negativeRoot.Vectors {
		id := stringValue(t, vector["id"])
		if _, duplicate := negatives[id]; duplicate {
			t.Fatalf("duplicate negative ID %q", id)
		}
		negatives[id] = vector
	}
	return corpus{positive: positive, negatives: negatives}
}

func nestedValue(t *testing.T, value any) any {
	t.Helper()
	return object(t, value)["value"]
}

func clone(t *testing.T, value any) any {
	t.Helper()
	raw := marshal(t, value)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var cloned any
	if err := decoder.Decode(&cloned); err != nil {
		t.Fatalf("clone: %v", err)
	}
	return cloned
}

func applyPatch(t *testing.T, root any, mutation map[string]any) {
	t.Helper()
	op := stringValue(t, mutation["op"])
	if op != "replace" && op != "add" {
		t.Fatalf("unsupported mutation operation %q", op)
	}
	rawPath := stringValue(t, mutation["path"])
	parts := strings.Split(strings.TrimPrefix(rawPath, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		t.Fatalf("invalid mutation path %q", rawPath)
	}
	var parent = root
	for _, rawPart := range parts[:len(parts)-1] {
		part := unescapePointer(rawPart)
		switch node := parent.(type) {
		case map[string]any:
			parent = node[part]
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(node) {
				t.Fatalf("invalid mutation path %q", rawPath)
			}
			parent = node[index]
		default:
			t.Fatalf("invalid mutation parent %T for %q", parent, rawPath)
		}
	}

	last := unescapePointer(parts[len(parts)-1])
	switch node := parent.(type) {
	case map[string]any:
		node[last] = mutation["value"]
	case []any:
		index, err := strconv.Atoi(last)
		if err != nil || index < 0 || index > len(node) {
			t.Fatalf("invalid mutation array index in %q", rawPath)
		}
		if op == "add" {
			node = append(node, nil)
			copy(node[index+1:], node[index:])
			node[index] = mutation["value"]
			setArrayAtPath(t, root, parts[:len(parts)-1], node)
			return
		}
		if index == len(node) {
			t.Fatalf("replace index out of range in %q", rawPath)
		}
		node[index] = mutation["value"]
	default:
		t.Fatalf("invalid mutation parent %T for %q", parent, rawPath)
	}
}

func setArrayAtPath(t *testing.T, root any, parentParts []string, replacement []any) {
	t.Helper()
	if len(parentParts) == 0 {
		t.Fatal("root-array mutation is not supported")
	}
	var parent = root
	for _, rawPart := range parentParts[:len(parentParts)-1] {
		part := unescapePointer(rawPart)
		switch node := parent.(type) {
		case map[string]any:
			parent = node[part]
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(node) {
				t.Fatal("invalid parent array path")
			}
			parent = node[index]
		default:
			t.Fatalf("invalid parent path type %T", parent)
		}
	}
	last := unescapePointer(parentParts[len(parentParts)-1])
	switch node := parent.(type) {
	case map[string]any:
		node[last] = replacement
	case []any:
		index, err := strconv.Atoi(last)
		if err != nil || index < 0 || index >= len(node) {
			t.Fatal("invalid parent array index")
		}
		node[index] = replacement
	default:
		t.Fatalf("invalid array owner %T", parent)
	}
}

func unescapePointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~1", "/"), "~0", "~")
}

func assertVectorFailure(t *testing.T, vector map[string]any, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("negative vector %q was accepted", stringValue(t, vector["id"]))
	}
	terminal, reason, ok := Verdict(err)
	if !ok {
		t.Fatalf("negative vector %q returned non-schema error %v", stringValue(t, vector["id"]), err)
	}
	expected := object(t, vector["expected"])
	if string(terminal) != stringValue(t, expected["terminal"]) ||
		string(reason) != stringValue(t, expected["reason"]) {
		t.Fatalf(
			"negative vector %q verdict = %s/%s, want %s/%s",
			stringValue(t, vector["id"]),
			terminal,
			reason,
			stringValue(t, expected["terminal"]),
			stringValue(t, expected["reason"]),
		)
	}
}

func object(t *testing.T, value any) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value has type %T, want object", value)
	}
	return result
}

func stringValue(t *testing.T, value any) string {
	t.Helper()
	result, ok := value.(string)
	if !ok {
		t.Fatalf("value has type %T, want string", value)
	}
	return result
}

func marshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %T: %v", value, err)
	}
	return raw
}
