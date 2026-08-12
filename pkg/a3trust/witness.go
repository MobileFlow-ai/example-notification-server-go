// Package a3trust implements the default-dark XMTP directory association and
// independent transparency-witness boundaries consumed by modern-api.
package a3trust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

const (
	AssociationPath = "/internal/v1/xmtp-directory/installation-associations:read"
	WitnessPath     = "/internal/v1/xmtp-directory/tree-heads:cosign"

	treeHeadDomain       = "hytch.directory.tree-head/v1"
	treeHeadContext      = "hytch-directory-tree-head-v1\x00"
	maxExactJSONInteger  = uint64(9007199254740991)
	maxWitnessBodyBytes  = 16 * 1024
	maxConsistencyProof  = 64
	minimumBearerBytes   = 32
	maximumBearerBytes   = 64
	minimumBearerSymbols = 16
)

var (
	ErrConfiguration = errors.New("a3 trust configuration invalid")
	ErrUnavailable   = errors.New("a3 trust unavailable")
	ErrFork          = errors.New("a3 witness fork")

	lowerHex32Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	positionPattern   = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
)

type TreeHead struct {
	Domain        string `json:"domain"`
	Environment   string `json:"environment"`
	PriorRootHash string `json:"prior_root_hash"`
	PriorTreeSize uint64 `json:"prior_tree_size"`
	Protocol      uint64 `json:"protocol_version"`
	RootHash      string `json:"root_hash"`
	TimestampMS   uint64 `json:"timestamp_ms"`
	TreeSize      uint64 `json:"tree_size"`
}

type WitnessProposal struct {
	Head             TreeHead
	CanonicalHead    []byte
	ConsistencyProof [][32]byte
	NotBefore        time.Time
	NotAfter         time.Time
}

type WitnessAcceptance struct {
	KeyID     string
	Signature [ed25519.SignatureSize]byte
	Replay    bool
}

type WitnessStore interface {
	AcceptDirectoryTreeHead(context.Context, WitnessProposal, ed25519.PrivateKey, string) (WitnessAcceptance, error)
}

type WitnessOptions struct {
	Enabled          bool
	Environment      string
	BearerToken      string
	Store            WitnessStore
	PrivateKey       ed25519.PrivateKey
	KeyID            string
	MaxConcurrency   int
	RatePerSecond    int
	RateBurst        int
	RequestTimeout   time.Duration
	Clock            func() time.Time
	MaximumClockSkew time.Duration
	MaximumHeadAge   time.Duration
	SequencerKeys    map[string]ed25519.PublicKey
}

type WitnessHandler struct {
	enabled          bool
	environment      string
	bearer           []byte
	store            WitnessStore
	privateKey       ed25519.PrivateKey
	keyID            string
	concurrency      chan struct{}
	limiter          *fixedTokenBucket
	requestTimeout   time.Duration
	clock            func() time.Time
	maximumClockSkew time.Duration
	maximumHeadAge   time.Duration
	sequencerKeys    map[string]ed25519.PublicKey
}

func NewWitnessHandler(options WitnessOptions) (*WitnessHandler, error) {
	if !options.Enabled {
		return &WitnessHandler{}, nil
	}
	if !validOpaqueBearer(options.BearerToken) || options.Store == nil ||
		(options.Environment != "dev" && options.Environment != "production") ||
		len(options.PrivateKey) != ed25519.PrivateKeySize ||
		options.MaxConcurrency < 1 || options.MaxConcurrency > 64 ||
		options.RatePerSecond < 1 || options.RatePerSecond > 1000 ||
		options.RateBurst < 1 || options.RateBurst > 1000 ||
		options.RequestTimeout < time.Second || options.RequestTimeout > 30*time.Second ||
		options.MaximumClockSkew < 0 || options.MaximumClockSkew > time.Hour ||
		options.MaximumHeadAge < time.Second || options.MaximumHeadAge > 24*time.Hour ||
		len(options.SequencerKeys) == 0 || len(options.SequencerKeys) > 8 {
		return nil, ErrConfiguration
	}
	publicKey, ok := options.PrivateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize || allZero(publicKey) {
		return nil, ErrConfiguration
	}
	computedKeyID := WitnessKeyID(publicKey)
	if options.KeyID != computedKeyID {
		return nil, ErrConfiguration
	}
	sequencerKeys := make(map[string]ed25519.PublicKey, len(options.SequencerKeys))
	for keyID, key := range options.SequencerKeys {
		if len(key) != ed25519.PublicKeySize || allZero(key) ||
			WitnessKeyID(key) != keyID ||
			bytes.Equal(key, publicKey) {
			return nil, ErrConfiguration
		}
		sequencerKeys[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	return &WitnessHandler{
		enabled:          true,
		environment:      options.Environment,
		bearer:           []byte(options.BearerToken),
		store:            options.Store,
		privateKey:       append(ed25519.PrivateKey(nil), options.PrivateKey...),
		keyID:            computedKeyID,
		concurrency:      make(chan struct{}, options.MaxConcurrency),
		limiter:          newFixedTokenBucket(options.RatePerSecond, options.RateBurst, clock),
		requestTimeout:   options.RequestTimeout,
		clock:            clock,
		maximumClockSkew: options.MaximumClockSkew,
		maximumHeadAge:   options.MaximumHeadAge,
		sequencerKeys:    sequencerKeys,
	}, nil
}

func (handler *WitnessHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	defer func() {
		if recover() != nil {
			writeFixedJSONError(writer, http.StatusServiceUnavailable)
		}
	}()
	if handler == nil || !handler.enabled {
		writeFixedJSONError(writer, http.StatusNotFound)
		return
	}
	if !canonicalRequestTarget(request, WitnessPath) ||
		request.Method != http.MethodPost ||
		!singleHeaderEquals(request.Header, "Content-Type", "application/json") ||
		!singleHeaderEquals(request.Header, "Accept", "application/json") {
		writeFixedJSONError(writer, http.StatusUnauthorized)
		return
	}
	authorization, ok := singleHeader(request.Header, "Authorization")
	if !ok || !handler.authorized(authorization) {
		writeFixedJSONError(writer, http.StatusUnauthorized)
		return
	}
	if !handler.limiter.Allow(handler.clock().UTC()) {
		writeFixedJSONError(writer, http.StatusServiceUnavailable)
		return
	}
	select {
	case handler.concurrency <- struct{}{}:
		defer func() { <-handler.concurrency }()
	default:
		writeFixedJSONError(writer, http.StatusServiceUnavailable)
		return
	}

	proposal, ok := parseWitnessRequest(
		request.Body,
		handler.maximumClockSkew,
		handler.maximumHeadAge,
		handler.sequencerKeys,
		handler.environment,
	)
	if !ok {
		writeFixedJSONError(writer, http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.requestTimeout)
	defer cancel()
	accepted, err := handler.store.AcceptDirectoryTreeHead(
		ctx,
		proposal,
		handler.privateKey,
		handler.keyID,
	)
	if err != nil || (!proposalTimeValid(proposal, handler.clock().UTC()) &&
		!accepted.Replay) ||
		accepted.KeyID != handler.keyID ||
		!ed25519.Verify(handler.privateKey.Public().(ed25519.PublicKey), proposal.CanonicalHead, accepted.Signature[:]) {
		writeFixedJSONError(writer, http.StatusServiceUnavailable)
		return
	}
	response := struct {
		WitnessKeyID    string `json:"witness_key_id"`
		SignatureBase64 string `json:"signature_base64"`
	}{
		WitnessKeyID:    accepted.KeyID,
		SignatureBase64: base64.StdEncoding.EncodeToString(accepted.Signature[:]),
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		writeFixedJSONError(writer, http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}

func (handler *WitnessHandler) authorized(value string) bool {
	const prefix = "Bearer "
	if len(value) <= len(prefix) || value[:len(prefix)] != prefix {
		return false
	}
	candidate := []byte(value[len(prefix):])
	return len(candidate) == len(handler.bearer) &&
		subtle.ConstantTimeCompare(candidate, handler.bearer) == 1
}

func (handler *WitnessHandler) Close() {
	if handler == nil {
		return
	}
	clear(handler.bearer)
	clear(handler.privateKey)
	for _, key := range handler.sequencerKeys {
		clear(key)
	}
	handler.enabled = false
}

func parseWitnessRequest(
	body io.Reader,
	maximumClockSkew time.Duration,
	maximumHeadAge time.Duration,
	sequencerKeys map[string]ed25519.PublicKey,
	expectedEnvironment string,
) (WitnessProposal, bool) {
	raw, err := io.ReadAll(io.LimitReader(body, maxWitnessBodyBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxWitnessBodyBytes {
		return WitnessProposal{}, false
	}
	parsed, err := a9trust.ParseStrictJSON(raw)
	root, ok := parsed.(map[string]any)
	if err != nil || !ok || !exactObjectFields(
		root,
		"consistency_proof",
		"head",
		"sequencer_key_id",
		"sequencer_signature_base64",
		"signature_payload_base64",
	) {
		return WitnessProposal{}, false
	}
	headObject, ok := root["head"].(map[string]any)
	if !ok || !exactObjectFields(headObject,
		"domain", "environment", "prior_root_hash", "prior_tree_size",
		"protocol_version", "root_hash", "timestamp_ms", "tree_size") {
		return WitnessProposal{}, false
	}
	head, ok := parseTreeHead(headObject)
	if !ok || head.Environment != expectedEnvironment {
		return WitnessProposal{}, false
	}
	canonical, err := CanonicalTreeHead(head)
	if err != nil {
		return WitnessProposal{}, false
	}
	payload, ok := stringValue(root["signature_payload_base64"])
	decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(payload)
	if !ok || decodeErr != nil || base64.StdEncoding.EncodeToString(decoded) != payload ||
		!bytes.Equal(decoded, canonical) {
		return WitnessProposal{}, false
	}
	sequencerKeyID, keyIDOK := stringValue(root["sequencer_key_id"])
	sequencerKey, knownKey := sequencerKeys[sequencerKeyID]
	sequencerSignatureValue, signatureOK := stringValue(
		root["sequencer_signature_base64"],
	)
	sequencerSignature, signatureErr := base64.StdEncoding.Strict().DecodeString(
		sequencerSignatureValue,
	)
	if !keyIDOK || !knownKey || !signatureOK || signatureErr != nil ||
		len(sequencerSignature) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(sequencerSignature) != sequencerSignatureValue ||
		!ed25519.Verify(sequencerKey, canonical, sequencerSignature) {
		return WitnessProposal{}, false
	}
	proofValues, ok := root["consistency_proof"].([]any)
	if !ok || len(proofValues) > maxConsistencyProof {
		return WitnessProposal{}, false
	}
	proof := make([][32]byte, len(proofValues))
	for index, value := range proofValues {
		encoded, stringOK := stringValue(value)
		decoded, decodeErr := hex.DecodeString(encoded)
		if !stringOK || decodeErr != nil || len(decoded) != sha256.Size ||
			hex.EncodeToString(decoded) != encoded {
			return WitnessProposal{}, false
		}
		copy(proof[index][:], decoded)
	}
	if !VerifyWitnessExtension(head, proof) {
		return WitnessProposal{}, false
	}
	proposal := WitnessProposal{
		Head: head, CanonicalHead: canonical, ConsistencyProof: proof,
		NotBefore: time.UnixMilli(int64(head.TimestampMS)).UTC().Add(-maximumClockSkew),
		NotAfter:  time.UnixMilli(int64(head.TimestampMS)).UTC().Add(maximumHeadAge),
	}
	return proposal, true
}

func parseTreeHead(value map[string]any) (TreeHead, bool) {
	domain, domainOK := stringValue(value["domain"])
	environment, environmentOK := stringValue(value["environment"])
	priorRoot, priorRootOK := stringValue(value["prior_root_hash"])
	root, rootOK := stringValue(value["root_hash"])
	priorSize, priorSizeOK := uintValue(value["prior_tree_size"])
	protocol, protocolOK := uintValue(value["protocol_version"])
	timestamp, timestampOK := uintValue(value["timestamp_ms"])
	treeSize, treeSizeOK := uintValue(value["tree_size"])
	head := TreeHead{
		Domain: domain, Environment: environment, PriorRootHash: priorRoot,
		PriorTreeSize: priorSize, Protocol: protocol, RootHash: root,
		TimestampMS: timestamp, TreeSize: treeSize,
	}
	return head, domainOK && environmentOK && priorRootOK && rootOK &&
		priorSizeOK && protocolOK && timestampOK && treeSizeOK && validTreeHead(head)
}

func validTreeHead(head TreeHead) bool {
	return head.Domain == treeHeadDomain && head.Protocol == 1 &&
		(head.Environment == "dev" || head.Environment == "production") &&
		head.TreeSize > 0 && head.TreeSize <= maxExactJSONInteger &&
		head.PriorTreeSize < head.TreeSize &&
		head.TimestampMS <= maxExactJSONInteger &&
		lowerHex32Pattern.MatchString(head.RootHash) &&
		lowerHex32Pattern.MatchString(head.PriorRootHash)
}

func CanonicalTreeHead(head TreeHead) ([]byte, error) {
	if !validTreeHead(head) {
		return nil, ErrUnavailable
	}
	body := map[string]any{
		"domain": head.Domain, "environment": head.Environment,
		"prior_root_hash": head.PriorRootHash, "prior_tree_size": head.PriorTreeSize,
		"protocol_version": head.Protocol, "root_hash": head.RootHash,
		"timestamp_ms": head.TimestampMS, "tree_size": head.TreeSize,
	}
	canonical, err := a9trust.Canonicalize(body)
	if err != nil || len(canonical) > int(^uint32(0)) {
		return nil, ErrUnavailable
	}
	out := make([]byte, 0, len(treeHeadContext)+4+len(canonical))
	out = append(out, treeHeadContext...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(canonical)))
	out = append(out, canonical...)
	return out, nil
}

func VerifyWitnessExtension(head TreeHead, proof [][32]byte) bool {
	oldRoot, oldErr := decodeHash(head.PriorRootHash)
	newRoot, newErr := decodeHash(head.RootHash)
	if oldErr != nil || newErr != nil {
		return false
	}
	if head.PriorTreeSize == 0 {
		empty := sha256.Sum256(nil)
		return len(proof) == 0 && bytes.Equal(oldRoot, empty[:])
	}
	return verifyConsistency(head.PriorTreeSize, head.TreeSize, oldRoot, newRoot, proof)
}

func verifyConsistency(oldSize, newSize uint64, oldRoot, newRoot []byte, proof [][32]byte) bool {
	if oldSize == newSize {
		return len(proof) == 0 && bytes.Equal(oldRoot, newRoot)
	}
	if oldSize == 0 {
		return true
	}
	if oldSize > newSize || len(proof) == 0 {
		return false
	}
	index := 0
	var verify func(uint64, uint64, bool) ([32]byte, [32]byte, bool)
	verify = func(oldCount, newCount uint64, leftmost bool) ([32]byte, [32]byte, bool) {
		if oldCount == newCount {
			if leftmost {
				var root [32]byte
				copy(root[:], oldRoot)
				return root, root, true
			}
			if index >= len(proof) {
				return [32]byte{}, [32]byte{}, false
			}
			value := proof[index]
			index++
			return value, value, true
		}
		k := largestPowerOfTwoLessThan(newCount)
		if k == 0 {
			return [32]byte{}, [32]byte{}, false
		}
		if oldCount <= k {
			oldLeft, newLeft, ok := verify(oldCount, k, leftmost)
			if !ok || index >= len(proof) {
				return [32]byte{}, [32]byte{}, false
			}
			right := proof[index]
			index++
			return oldLeft, merkleNodeHash(newLeft, right), true
		}
		oldRight, newRight, ok := verify(oldCount-k, newCount-k, false)
		if !ok || index >= len(proof) {
			return [32]byte{}, [32]byte{}, false
		}
		left := proof[index]
		index++
		return merkleNodeHash(left, oldRight), merkleNodeHash(left, newRight), true
	}
	computedOld, computedNew, ok := verify(oldSize, newSize, true)
	return ok && index == len(proof) && bytes.Equal(computedOld[:], oldRoot) && bytes.Equal(computedNew[:], newRoot)
}

func largestPowerOfTwoLessThan(value uint64) uint64 {
	if value <= 1 {
		return 0
	}
	result := uint64(1)
	for result*2 < value {
		result *= 2
	}
	return result
}

func merkleNodeHash(left, right [32]byte) [32]byte {
	input := make([]byte, 1+sha256.Size*2)
	input[0] = 1
	copy(input[1:], left[:])
	copy(input[1+sha256.Size:], right[:])
	return sha256.Sum256(input)
}

func decodeHash(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return nil, ErrUnavailable
	}
	return decoded, nil
}

func exactObjectFields(value map[string]any, names ...string) bool {
	if len(value) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := value[name]; !ok {
			return false
		}
	}
	return true
}

func stringValue(value any) (string, bool) {
	result, ok := value.(string)
	return result, ok
}

func uintValue(value any) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	raw := string(number)
	if raw == "" || (len(raw) > 1 && raw[0] == '0') {
		return 0, false
	}
	parsed, err := strconv.ParseUint(raw, 10, 64)
	return parsed, err == nil && parsed <= maxExactJSONInteger
}

func proposalTimeValid(proposal WitnessProposal, now time.Time) bool {
	return !now.IsZero() && !proposal.NotBefore.IsZero() &&
		!proposal.NotAfter.IsZero() && !now.Before(proposal.NotBefore) &&
		!now.After(proposal.NotAfter)
}

// ValidOpaqueBearer accepts only canonical unpadded Base64url tokens carrying
// 32 through 64 bytes. Byte-diversity checks reject obvious low-entropy test
// values; operators must still generate the decoded bytes with a CSPRNG.
func ValidOpaqueBearer(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) < minimumBearerBytes ||
		len(decoded) > maximumBearerBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		return false
	}
	var counts [256]uint8
	distinct := 0
	maximumCount := 0
	for _, symbol := range decoded {
		if counts[symbol] == 0 {
			distinct++
		}
		counts[symbol]++
		if int(counts[symbol]) > maximumCount {
			maximumCount = int(counts[symbol])
		}
	}
	return distinct >= minimumBearerSymbols && maximumCount*4 <= len(decoded)
}

func validOpaqueBearer(value string) bool { return ValidOpaqueBearer(value) }

func singleHeader(header http.Header, name string) (string, bool) {
	values, present := header[http.CanonicalHeaderKey(name)]
	if !present || len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func singleHeaderEquals(header http.Header, name, expected string) bool {
	value, ok := singleHeader(header, name)
	return ok && value == expected
}

func canonicalRequestTarget(request *http.Request, expectedPath string) bool {
	return request != nil && request.URL != nil &&
		request.URL.Path == expectedPath && request.URL.RawPath == "" &&
		request.URL.Opaque == "" && request.URL.RawQuery == "" &&
		!request.URL.ForceQuery && request.URL.Fragment == "" &&
		request.RequestURI == expectedPath
}

func allZero(value []byte) bool {
	var combined byte
	for index := range value {
		combined |= value[index]
	}
	return combined == 0
}

// WitnessKeyID returns the key identifier required by modern-api's strict
// Ed25519 witness response contract.
func WitnessKeyID(publicKey ed25519.PublicKey) string {
	if len(publicKey) != ed25519.PublicKeySize || allZero(publicKey) {
		return ""
	}
	digest := sha256.Sum256(publicKey)
	return "ed25519-sha256:" + hex.EncodeToString(digest[:])
}

func writeFixedJSONError(writer http.ResponseWriter, status int) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, `{"error":"unavailable"}`)
}

type fixedTokenBucket struct {
	mu       sync.Mutex
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
}

func newFixedTokenBucket(
	ratePerSecond int,
	burst int,
	clock func() time.Time,
) *fixedTokenBucket {
	now := clock().UTC()
	return &fixedTokenBucket{
		rate:     float64(ratePerSecond),
		capacity: float64(burst),
		tokens:   float64(burst),
		last:     now,
	}
}

func (limiter *fixedTokenBucket) Allow(now time.Time) bool {
	if limiter == nil {
		return false
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if now.Before(limiter.last) {
		now = limiter.last
	}
	elapsed := now.Sub(limiter.last).Seconds()
	limiter.tokens += elapsed * limiter.rate
	if limiter.tokens > limiter.capacity {
		limiter.tokens = limiter.capacity
	}
	limiter.last = now
	if limiter.tokens < 1 {
		return false
	}
	limiter.tokens--
	return true
}
