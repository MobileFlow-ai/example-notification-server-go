package a9conformance

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const (
	wantPositiveSHA256 = "5f5259665e6fceab723ffd08c5ce1360dd1ef1874b801fce6ef5f9f949630b54"
	wantNegativeSHA256 = "c20c0243314bdaa686cf090cee90671fa79808973ff0df1a8c2f5b37ac86ee95"
	wantNegativeCount  = 54
)

type vectorManifest struct {
	Contract            string   `json:"contract"`
	GeneratedBy         string   `json:"generated_by"`
	NegativeSHA256      string   `json:"negative_sha256"`
	NegativeVectorCount int      `json:"negative_vector_count"`
	PositiveSHA256      string   `json:"positive_sha256"`
	SchemaDialect       string   `json:"schema_dialect"`
	TerminalVerdicts    []string `json:"terminal_verdicts"`
	Welcome             string   `json:"welcome"`
}

type negativeVectors struct {
	Contract string `json:"contract"`
	Rule     string `json:"rule"`
	Vectors  []struct {
		ID       string `json:"id"`
		Expected struct {
			Terminal string `json:"terminal"`
			Reason   string `json:"reason"`
		} `json:"expected"`
	} `json:"vectors"`
}

type fixedVerdict struct {
	terminal string
	reason   string
	owner    string
}

func TestPublishedArtifactIntegrityManifest(t *testing.T) {
	root := contractRoot(t)
	checksums := readChecksums(t, filepath.Join(root, "SHA256SUMS"))
	if len(checksums) != 11 {
		t.Fatalf("SHA256SUMS entries = %d, want 11", len(checksums))
	}

	expectedFiles := map[string]bool{"SHA256SUMS": true}
	for relative, want := range checksums {
		expectedFiles[relative] = true
		path := filepath.Join(root, filepath.FromSlash(relative))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read checksummed file %s: %v", relative, err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("%s SHA-256 = %s, want %s", relative, got, want)
		}
	}

	var actualFiles []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			t.Fatalf("artifact contains symlink %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		actualFiles = append(actualFiles, filepath.ToSlash(relative))
		return nil
	}); err != nil {
		t.Fatalf("walk artifact: %v", err)
	}
	sort.Strings(actualFiles)
	if len(actualFiles) != len(expectedFiles) {
		t.Fatalf("artifact file count = %d, want %d; files=%v", len(actualFiles), len(expectedFiles), actualFiles)
	}
	for _, relative := range actualFiles {
		if !expectedFiles[relative] {
			t.Fatalf("artifact has unmanifested file %q", relative)
		}
	}
}

func TestVectorManifestPinsPublishedDigestsAndClosedScope(t *testing.T) {
	root := contractRoot(t)
	var manifest vectorManifest
	readJSON(t, filepath.Join(root, "vectors", "manifest.json"), &manifest)

	if manifest.Contract != "hytch.xmtp-push.a9-adapter.v1" {
		t.Fatalf("contract = %q", manifest.Contract)
	}
	if manifest.GeneratedBy != "generate_vectors.py" {
		t.Fatalf("generated_by = %q", manifest.GeneratedBy)
	}
	if manifest.PositiveSHA256 != wantPositiveSHA256 {
		t.Fatalf("positive digest = %s, want %s", manifest.PositiveSHA256, wantPositiveSHA256)
	}
	if manifest.NegativeSHA256 != wantNegativeSHA256 {
		t.Fatalf("negative digest = %s, want %s", manifest.NegativeSHA256, wantNegativeSHA256)
	}
	if manifest.NegativeVectorCount != wantNegativeCount {
		t.Fatalf("negative count = %d, want %d", manifest.NegativeVectorCount, wantNegativeCount)
	}
	if manifest.SchemaDialect != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema dialect = %q", manifest.SchemaDialect)
	}
	if manifest.Welcome != "CLOSED" {
		t.Fatalf("welcome = %q, want CLOSED", manifest.Welcome)
	}
	wantTerminals := []string{"ELIGIBLE", "INVALID", "STALE", "REVOKED", "INCONCLUSIVE"}
	if strings.Join(manifest.TerminalVerdicts, "\x00") != strings.Join(wantTerminals, "\x00") {
		t.Fatalf("terminal verdicts = %v, want %v", manifest.TerminalVerdicts, wantTerminals)
	}

	assertFileDigest(t, filepath.Join(root, "vectors", "positive.json"), wantPositiveSHA256)
	assertFileDigest(t, filepath.Join(root, "vectors", "negative.json"), wantNegativeSHA256)
}

func TestEveryFixedNegativeVerdictHasOneConformanceOwner(t *testing.T) {
	root := contractRoot(t)
	var negatives negativeVectors
	readJSON(t, filepath.Join(root, "vectors", "negative.json"), &negatives)
	if negatives.Contract != "hytch.xmtp-push.a9-adapter.v1" {
		t.Fatalf("negative contract = %q", negatives.Contract)
	}
	if len(negatives.Vectors) != wantNegativeCount {
		t.Fatalf("negative vector count = %d, want %d", len(negatives.Vectors), wantNegativeCount)
	}

	fixed := fixedNegativeVerdicts()
	if len(fixed) != wantNegativeCount {
		t.Fatalf("fixed verdict registry count = %d, want %d", len(fixed), wantNegativeCount)
	}
	seen := make(map[string]bool, len(negatives.Vectors))
	ownerCounts := make(map[string]int)
	for _, vector := range negatives.Vectors {
		if seen[vector.ID] {
			t.Fatalf("duplicate negative vector ID %q", vector.ID)
		}
		seen[vector.ID] = true
		want, ok := fixed[vector.ID]
		if !ok {
			t.Fatalf("negative vector %q has no independent conformance owner", vector.ID)
		}
		if want.owner != "schema" && want.owner != "crypto" && want.owner != "state" {
			t.Fatalf("negative vector %q has invalid owner %q", vector.ID, want.owner)
		}
		ownerCounts[want.owner]++
		if vector.Expected.Terminal != want.terminal || vector.Expected.Reason != want.reason {
			t.Fatalf(
				"%s verdict = %s/%s, want %s/%s",
				vector.ID,
				vector.Expected.Terminal,
				vector.Expected.Reason,
				want.terminal,
				want.reason,
			)
		}
	}
	for id := range fixed {
		if !seen[id] {
			t.Fatalf("fixed verdict registry contains absent vector %q", id)
		}
	}
	for _, owner := range []string{"schema", "crypto", "state"} {
		if ownerCounts[owner] == 0 {
			t.Fatalf("conformance owner %q has no vectors", owner)
		}
	}
}

func fixedNegativeVerdicts() map[string]fixedVerdict {
	type entry struct {
		id       string
		terminal string
		reason   string
		owner    string
	}
	entries := []entry{
		{"assertion_signature_one_byte", "INVALID", "BAD_SIGNATURE", "crypto"},
		{"wrong_signature_domain", "INVALID", "BAD_SIGNATURE", "crypto"},
		{"assertion_unsigned_one_byte", "INVALID", "FIELD_DOMAIN", "schema"},
		{"duplicate_json_key", "INVALID", "DUPLICATE_KEY", "schema"},
		{"unknown_assertion_field", "INVALID", "UNKNOWN_FIELD_RAW_ROSTER_FORBIDDEN", "schema"},
		{"padded_signature", "INVALID", "NONCANONICAL_BASE64URL", "schema"},
		{"wrong_length_base64url", "INVALID", "NONCANONICAL_BASE64URL", "schema"},
		{"noncanonical_uuid", "INVALID", "FIELD_DOMAIN", "schema"},
		{"wrong_environment_spelling", "INVALID", "FIELD_DOMAIN", "schema"},
		{"wrong_audience", "INVALID", "WRONG_AUDIENCE", "schema"},
		{"welcome_purpose", "INVALID", "WELCOME_CLOSED", "schema"},
		{"noncanonical_timestamp", "INVALID", "NONCANONICAL_TIME", "schema"},
		{"integer_as_float", "INVALID", "NON_IJSON_NUMBER", "schema"},
		{"integer_overflow", "INVALID", "INTEGER_RANGE", "schema"},
		{"wrong_topic_binding", "INVALID", "TOPIC_BINDING_MISMATCH", "crypto"},
		{"wrong_roster_commitment", "INVALID", "ROSTER_COMMITMENT_MISMATCH", "crypto"},
		{"wrong_tuple_commitment", "INVALID", "TUPLE_COMMITMENT_MISMATCH", "crypto"},
		{"tuple_source_account_mutation", "INVALID", "TUPLE_COMMITMENT_MISMATCH", "crypto"},
		{"stale_topic_key_epoch", "INVALID", "TOPIC_KEY_EPOCH", "crypto"},
		{"unknown_signer", "INVALID", "KEY_STATE", "crypto"},
		{"signer_not_yet_valid", "INVALID", "KEY_STATE", "crypto"},
		{"signer_expired", "INVALID", "KEY_STATE", "crypto"},
		{"expired_assertion", "INVALID", "EXPIRED", "crypto"},
		{"control_upsert_shape_mismatch", "INVALID", "FIELD_DOMAIN", "schema"},
		{"control_gap_upsert", "INCONCLUSIVE", "CONTROL_GAP", "state"},
		{"control_sequence_regression", "STALE", "CONTROL_SEQUENCE_REGRESSION", "state"},
		{"revoke_across_gap", "REVOKED", "DENY_APPLIES_AND_UNCERTAINTY_LATCHES", "state"},
		{"idempotency_key_different_body", "INCONCLUSIVE", "IDEMPOTENCY_CONFLICT", "state"},
		{"upsert_after_tombstone", "REVOKED", "TOMBSTONE_WINS", "state"},
		{"revoke_refresh_race", "REVOKED", "TOMBSTONE_WINS", "state"},
		{"watermark_expired", "INCONCLUSIVE", "WATERMARK_EXPIRED", "state"},
		{"watermark_max_seen_with_gap", "INCONCLUSIVE", "WATERMARK_GAP", "state"},
		{"watermark_sequence_rollback", "INCONCLUSIVE", "WATERMARK_ROLLBACK", "state"},
		{"watermark_uncertain", "INCONCLUSIVE", "SOURCE_UNAVAILABLE", "state"},
		{"sequencer_epoch_change", "INCONCLUSIVE", "EPOCH_MISMATCH", "state"},
		{"restart_ambiguity", "INCONCLUSIVE", "REPLICA_AMBIGUITY", "state"},
		{"cross_installation_assertion", "INVALID", "INSTALLATION_MISMATCH", "crypto"},
		{"cross_topic_assertion_hash", "INVALID", "ASSERTION_HASH_MISMATCH", "crypto"},
		{"noncanonical_transport_id_uppercase", "INVALID", "TOPIC_RESOLVER", "schema"},
		{"topic_wrong_length", "INVALID", "TOPIC_RESOLVER", "schema"},
		{"transport_topic_mismatch", "INVALID", "TOPIC_RESOLVER", "crypto"},
		{"welcome_topic_kind", "INVALID", "WELCOME_CLOSED", "schema"},
		{"sender_hmac_period_duplicate", "INVALID", "HMAC_PERIOD_DUPLICATE", "state"},
		{"duplicate_subscription", "INVALID", "DUPLICATE_SUBSCRIPTION", "schema"},
		{"unsorted_subscriptions", "INVALID", "SUBSCRIPTION_ORDER", "state"},
		{"route_key_epoch_rollback", "STALE", "ROUTE_KEY_EPOCH", "state"},
		{"partial_cas_failure", "INCONCLUSIVE", "ATOMIC_ROLLBACK_NO_CHANGE", "state"},
		{"vault_commit_ambiguous", "INCONCLUSIVE", "VAULT_COMMIT_AMBIGUOUS", "state"},
		{"jwt_wrong_audience", "INVALID", "SERVICE_AUTH", "crypto"},
		{"jwt_wrong_path", "INVALID", "SERVICE_AUTH", "crypto"},
		{"jwt_wrong_body_hash", "INVALID", "SERVICE_AUTH", "crypto"},
		{"jwt_reused_jti", "INVALID", "SERVICE_AUTH_REPLAY", "crypto"},
		{"keyset_sequence_rollback", "INCONCLUSIVE", "KEYSET_ROLLBACK", "crypto"},
		{"gate6_independent_deny", "INCONCLUSIVE", "GATE6_DENY", "state"},
	}

	result := make(map[string]fixedVerdict, len(entries))
	for _, item := range entries {
		if _, exists := result[item.id]; exists {
			panic("duplicate fixed verdict " + item.id)
		}
		result[item.id] = fixedVerdict{
			terminal: item.terminal,
			reason:   item.reason,
			owner:    item.owner,
		}
	}
	return result
}

func readChecksums(t *testing.T, path string) map[string]string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("close %s: %v", path, closeErr)
		}
	}()

	checksums := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()
		parts := strings.Split(line, "  ")
		if len(parts) != 2 {
			t.Fatalf("SHA256SUMS line %d is not canonical", lineNumber)
		}
		digest, relative := parts[0], parts[1]
		if len(digest) != 64 || strings.ToLower(digest) != digest {
			t.Fatalf("SHA256SUMS line %d has invalid digest %q", lineNumber, digest)
		}
		if decoded, decodeErr := hex.DecodeString(digest); decodeErr != nil || len(decoded) != sha256.Size {
			t.Fatalf("SHA256SUMS line %d has invalid SHA-256 %q", lineNumber, digest)
		}
		if relative == "" || filepath.IsAbs(relative) ||
			filepath.ToSlash(filepath.Clean(relative)) != relative ||
			strings.HasPrefix(relative, "../") {
			t.Fatalf("SHA256SUMS line %d has unsafe path %q", lineNumber, relative)
		}
		if _, duplicate := checksums[relative]; duplicate {
			t.Fatalf("SHA256SUMS repeats %q", relative)
		}
		checksums[relative] = digest
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return checksums
}

func assertFileDigest(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("%s digest = %s, want %s", path, got, want)
	}
}

func contractRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve conformance test path")
	}
	return filepath.Clean(filepath.Join(
		filepath.Dir(currentFile),
		"..",
		"..",
		"contracts",
		"xmtp_push",
		"a9_adapter",
		"v1",
	))
}

func readJSON(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}
