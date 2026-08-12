package a3trust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type memoryWitnessStore struct {
	mu       sync.Mutex
	accepted map[uint64]WitnessAcceptance
	last     WitnessProposal
	err      error
	clock    func() time.Time
}

func (store *memoryWitnessStore) AcceptDirectoryTreeHead(
	_ context.Context,
	proposal WitnessProposal,
	privateKey ed25519.PrivateKey,
	keyID string,
) (WitnessAcceptance, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.err != nil {
		return WitnessAcceptance{}, store.err
	}
	if store.accepted == nil {
		store.accepted = make(map[uint64]WitnessAcceptance)
	}
	if accepted, ok := store.accepted[proposal.Head.TreeSize]; ok {
		accepted.Replay = true
		return accepted, nil
	}
	clock := store.clock
	if clock == nil {
		clock = time.Now
	}
	if !proposalTimeValid(proposal, clock().UTC()) {
		return WitnessAcceptance{}, ErrUnavailable
	}
	signature := ed25519.Sign(privateKey, proposal.CanonicalHead)
	var accepted WitnessAcceptance
	accepted.KeyID = keyID
	copy(accepted.Signature[:], signature)
	store.accepted[proposal.Head.TreeSize] = accepted
	store.last = proposal
	return accepted, nil
}

func TestCanonicalTreeHeadMatchesModernContract(t *testing.T) {
	vectors := loadA3GoldenVectors(t)
	canonical, err := CanonicalTreeHead(vectors.TreeHead.Head)
	require.NoError(t, err)
	expected, err := base64.StdEncoding.Strict().DecodeString(
		vectors.TreeHead.ExpectedCanonicalBase64,
	)
	require.NoError(t, err)
	require.Equal(t, expected, canonical)
}

type a3GoldenVectors struct {
	Association struct {
		ContextASCII           string   `json:"context_ascii"`
		InboxID                string   `json:"inbox_id"`
		InstallationPublicKeys []string `json:"installation_public_keys"`
		SeenSignaturesBase64   []string `json:"seen_signatures_base64"`
		TargetInstallationID   string   `json:"target_installation_id"`
		ExpectedDigestLowerHex string   `json:"expected_digest_lowerhex"`
	} `json:"association_state_digest_v1"`
	TreeHead struct {
		Head                    TreeHead `json:"head"`
		ExpectedCanonicalBase64 string   `json:"expected_canonical_base64"`
	} `json:"tree_head_v1"`
	Consistency struct {
		PriorTreeSize uint64   `json:"prior_tree_size"`
		TreeSize      uint64   `json:"tree_size"`
		PriorRootHash string   `json:"prior_root_hash"`
		RootHash      string   `json:"root_hash"`
		Proof         []string `json:"proof"`
	} `json:"rfc6962_consistency_3_to_5"`
}

func loadA3GoldenVectors(t *testing.T) a3GoldenVectors {
	t.Helper()
	raw, err := os.ReadFile("../../contracts/xmtp_directory/a3_trust_v1_vectors.json")
	require.NoError(t, err)
	var vectors a3GoldenVectors
	require.NoError(t, json.Unmarshal(raw, &vectors))
	return vectors
}

func TestVerifyWitnessExtensionRFC6962(t *testing.T) {
	leafZero := merkleLeafHash([]byte("zero"))
	leafOne := merkleLeafHash([]byte("one"))
	rootTwo := merkleNodeHash(leafZero, leafOne)
	head := TreeHead{
		Domain: treeHeadDomain, Environment: "dev", Protocol: 1,
		PriorTreeSize: 1, TreeSize: 2,
		PriorRootHash: hex.EncodeToString(leafZero[:]),
		RootHash:      hex.EncodeToString(rootTwo[:]), TimestampMS: 1,
	}
	require.True(t, VerifyWitnessExtension(head, [][32]byte{leafOne}))
	require.False(t, VerifyWitnessExtension(head, nil))
	bad := leafOne
	bad[0] ^= 1
	require.False(t, VerifyWitnessExtension(head, [][32]byte{bad}))
}

func TestVerifyWitnessExtensionRFC6962RecursiveGoldenVector(t *testing.T) {
	vector := loadA3GoldenVectors(t).Consistency
	proof := make([][32]byte, 0, len(vector.Proof))
	for _, encoded := range vector.Proof {
		decoded, err := hex.DecodeString(encoded)
		require.NoError(t, err)
		require.Len(t, decoded, sha256.Size)
		var node [32]byte
		copy(node[:], decoded)
		proof = append(proof, node)
	}
	head := TreeHead{
		Domain: treeHeadDomain, Environment: "dev", Protocol: 1,
		PriorTreeSize: vector.PriorTreeSize, TreeSize: vector.TreeSize,
		PriorRootHash: vector.PriorRootHash, RootHash: vector.RootHash,
		TimestampMS: 1,
	}
	require.True(t, VerifyWitnessExtension(head, proof))

	reordered := append([][32]byte(nil), proof...)
	reordered[1], reordered[2] = reordered[2], reordered[1]
	require.False(t, VerifyWitnessExtension(head, reordered))
	extra := append(append([][32]byte(nil), proof...), proof[0])
	require.False(t, VerifyWitnessExtension(head, extra))
	require.False(t, VerifyWitnessExtension(head, proof[:len(proof)-1]))
}

func TestWitnessHandlerStrictAuthenticatedSuccess(t *testing.T) {
	now := time.UnixMilli(1750000000123).UTC()
	witnessPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	sequencerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	store := &memoryWitnessStore{}
	handler := newTestWitnessHandler(t, now, witnessPrivate, sequencerPrivate, store)
	body := testWitnessBody(t, testFirstTreeHead(now), sequencerPrivate)

	request := httptest.NewRequest(http.MethodPost, WitnessPath, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testOpaqueBearer(0x41))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	var response map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	require.Equal(t, WitnessKeyID(witnessPrivate.Public().(ed25519.PublicKey)), response["witness_key_id"])
	signature, err := base64.StdEncoding.DecodeString(response["signature_base64"].(string))
	require.NoError(t, err)
	require.True(t, ed25519.Verify(witnessPrivate.Public().(ed25519.PublicKey), store.last.CanonicalHead, signature))
}

func TestWitnessHandlerRejectsMalformedBoundary(t *testing.T) {
	now := time.UnixMilli(1750000000123).UTC()
	witnessPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	sequencerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	handler := newTestWitnessHandler(t, now, witnessPrivate, sequencerPrivate, &memoryWitnessStore{})
	valid := testWitnessBody(t, testFirstTreeHead(now), sequencerPrivate)
	tests := map[string]struct {
		method      string
		target      string
		contentType string
		accept      string
		token       string
		body        []byte
	}{
		"method":         {http.MethodGet, WitnessPath, "application/json", "application/json", testOpaqueBearer(0x41), valid},
		"query":          {http.MethodPost, WitnessPath + "?x=1", "application/json", "application/json", testOpaqueBearer(0x41), valid},
		"escaped target": {http.MethodPost, "/%69nternal/v1/xmtp-directory/tree-heads:cosign", "application/json", "application/json", testOpaqueBearer(0x41), valid},
		"content type":   {http.MethodPost, WitnessPath, "application/json; charset=utf-8", "application/json", testOpaqueBearer(0x41), valid},
		"accept":         {http.MethodPost, WitnessPath, "application/json", "*/*", testOpaqueBearer(0x41), valid},
		"token":          {http.MethodPost, WitnessPath, "application/json", "application/json", testOpaqueBearer(0x42), valid},
		"duplicate":      {http.MethodPost, WitnessPath, "application/json", "application/json", testOpaqueBearer(0x41), bytes.Replace(valid, []byte(`"consistency_proof":`), []byte(`"consistency_proof":[],"consistency_proof":`), 1)},
		"oversize":       {http.MethodPost, WitnessPath, "application/json", "application/json", testOpaqueBearer(0x41), bytes.Repeat([]byte("x"), maxWitnessBodyBytes+1)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, bytes.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer "+test.token)
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("Accept", test.accept)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			require.NotEqual(t, http.StatusOK, recorder.Code)
			require.JSONEq(t, `{"error":"unavailable"}`, recorder.Body.String())
		})
	}
	for _, header := range []string{"Authorization", "Content-Type", "Accept"} {
		t.Run("duplicate "+header, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, WitnessPath, bytes.NewReader(valid))
			request.Header.Set("Authorization", "Bearer "+testOpaqueBearer(0x41))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json")
			request.Header.Add(header, request.Header.Get(header))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			require.Equal(t, http.StatusUnauthorized, recorder.Code)
		})
	}
}

func TestWitnessHandlerRejectsWrongPayloadAndSequencerSignature(t *testing.T) {
	now := time.UnixMilli(1750000000123).UTC()
	witnessPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	sequencerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, ed25519.SeedSize))
	handler := newTestWitnessHandler(t, now, witnessPrivate, sequencerPrivate, &memoryWitnessStore{})
	for name, mutate := range map[string]func(map[string]any){
		"payload": func(value map[string]any) {
			value["signature_payload_base64"] = base64.StdEncoding.EncodeToString([]byte("arbitrary"))
		},
		"signature": func(value map[string]any) {
			value["sequencer_signature_base64"] = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		},
		"environment": func(value map[string]any) { value["head"].(map[string]any)["environment"] = "production" },
		"proof":       func(value map[string]any) { value["consistency_proof"] = []any{strings.Repeat("0", 64)} },
	} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			require.NoError(t, json.Unmarshal(testWitnessBody(t, testFirstTreeHead(now), sequencerPrivate), &value))
			mutate(value)
			body, err := json.Marshal(value)
			require.NoError(t, err)
			request := httptest.NewRequest(http.MethodPost, WitnessPath, bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+testOpaqueBearer(0x41))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			require.Equal(t, http.StatusUnauthorized, recorder.Code)
		})
	}
}

func TestWitnessHandlerContainsStorePanic(t *testing.T) {
	now := time.UnixMilli(1750000000123).UTC()
	witnessPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	sequencerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	store := &panicWitnessStore{}
	handler := newTestWitnessHandler(t, now, witnessPrivate, sequencerPrivate, store)
	request := httptest.NewRequest(http.MethodPost, WitnessPath, bytes.NewReader(testWitnessBody(t, testFirstTreeHead(now), sequencerPrivate)))
	request.Header.Set("Authorization", "Bearer "+testOpaqueBearer(0x41))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	recorder := httptest.NewRecorder()
	require.NotPanics(t, func() { handler.ServeHTTP(recorder, request) })
	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
}

func TestWitnessHandlerReturnsStoredReceiptForExactStaleReplay(t *testing.T) {
	now := time.UnixMilli(1750000000123).UTC()
	current := now
	witnessPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	sequencerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{10}, ed25519.SeedSize))
	sequencerPublic := sequencerPrivate.Public().(ed25519.PublicKey)
	store := &memoryWitnessStore{clock: func() time.Time { return current }}
	handler, err := NewWitnessHandler(WitnessOptions{
		Enabled: true, Environment: "dev", BearerToken: testOpaqueBearer(0x41),
		Store: store, PrivateKey: witnessPrivate,
		KeyID:          WitnessKeyID(witnessPrivate.Public().(ed25519.PublicKey)),
		MaxConcurrency: 2, RatePerSecond: 100, RateBurst: 100,
		RequestTimeout: time.Second, Clock: func() time.Time { return current },
		MaximumClockSkew: time.Minute, MaximumHeadAge: time.Hour,
		SequencerKeys: map[string]ed25519.PublicKey{WitnessKeyID(sequencerPublic): sequencerPublic},
	})
	require.NoError(t, err)
	body := testWitnessBody(t, testFirstTreeHead(now), sequencerPrivate)
	request := func() *http.Request {
		value := httptest.NewRequest(http.MethodPost, WitnessPath, bytes.NewReader(body))
		value.Header.Set("Authorization", "Bearer "+testOpaqueBearer(0x41))
		value.Header.Set("Content-Type", "application/json")
		value.Header.Set("Accept", "application/json")
		return value
	}
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, request())
	require.Equal(t, http.StatusOK, first.Code)
	current = now.Add(2 * time.Hour)
	replayed := httptest.NewRecorder()
	handler.ServeHTTP(replayed, request())
	require.Equal(t, http.StatusOK, replayed.Code)
	require.Equal(t, first.Body.Bytes(), replayed.Body.Bytes())
}

type panicWitnessStore struct{}

func (*panicWitnessStore) AcceptDirectoryTreeHead(context.Context, WitnessProposal, ed25519.PrivateKey, string) (WitnessAcceptance, error) {
	panic("test panic")
}

func newTestWitnessHandler(
	t *testing.T,
	now time.Time,
	witnessPrivate ed25519.PrivateKey,
	sequencerPrivate ed25519.PrivateKey,
	store WitnessStore,
) *WitnessHandler {
	t.Helper()
	if memoryStore, ok := store.(*memoryWitnessStore); ok &&
		memoryStore.clock == nil {
		memoryStore.clock = func() time.Time { return now }
	}
	sequencerPublic := sequencerPrivate.Public().(ed25519.PublicKey)
	handler, err := NewWitnessHandler(WitnessOptions{
		Enabled: true, Environment: "dev", BearerToken: testOpaqueBearer(0x41),
		Store: store, PrivateKey: witnessPrivate,
		KeyID:          WitnessKeyID(witnessPrivate.Public().(ed25519.PublicKey)),
		MaxConcurrency: 2, RatePerSecond: 100, RateBurst: 100,
		RequestTimeout: time.Second, Clock: func() time.Time { return now },
		MaximumClockSkew: time.Minute, MaximumHeadAge: time.Hour,
		SequencerKeys: map[string]ed25519.PublicKey{WitnessKeyID(sequencerPublic): sequencerPublic},
	})
	require.NoError(t, err)
	return handler
}

func testFirstTreeHead(now time.Time) TreeHead {
	return TreeHead{
		Domain: treeHeadDomain, Environment: "dev",
		PriorRootHash: hex.EncodeToString(sha256.New().Sum(nil)), PriorTreeSize: 0,
		Protocol: 1, RootHash: strings.Repeat("0", 63) + "1",
		TimestampMS: uint64(now.UnixMilli()), TreeSize: 1,
	}
}

func testWitnessBody(t *testing.T, head TreeHead, sequencerPrivate ed25519.PrivateKey) []byte {
	t.Helper()
	canonical, err := CanonicalTreeHead(head)
	require.NoError(t, err)
	sequencerPublic := sequencerPrivate.Public().(ed25519.PublicKey)
	body, err := json.Marshal(map[string]any{
		"head": head, "signature_payload_base64": base64.StdEncoding.EncodeToString(canonical),
		"sequencer_key_id":           WitnessKeyID(sequencerPublic),
		"sequencer_signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(sequencerPrivate, canonical)),
		"consistency_proof":          []string{},
	})
	require.NoError(t, err)
	return body
}

func merkleLeafHash(value []byte) [32]byte {
	return sha256.Sum256(append([]byte{0}, value...))
}

func TestValidOpaqueBearerRequiresCanonicalRandomByteShape(t *testing.T) {
	require.True(t, ValidOpaqueBearer(testOpaqueBearer(0x41)))
	require.False(t, ValidOpaqueBearer(strings.Repeat("a", 48)))
	require.False(t, ValidOpaqueBearer(base64.RawURLEncoding.EncodeToString(
		bytes.Repeat([]byte{1}, minimumBearerBytes),
	)))
	require.False(t, ValidOpaqueBearer(base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{1}, minimumBearerBytes),
	)))
}

func testOpaqueBearer(seed byte) string {
	raw := make([]byte, minimumBearerBytes)
	for index := range raw {
		raw[index] = seed + byte(index*17)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
