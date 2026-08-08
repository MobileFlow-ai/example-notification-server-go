package a9trust

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sort"
	"sync"
	"time"
)

// ErrConfiguration is intentionally content-free because A9 configuration
// contains root material and secret topic-commitment keys.
var ErrConfiguration = errors.New("a9 trust configuration invalid")

const maxRetirementClockRecheck = time.Second

// RootPin is the out-of-band trust anchor for root-signed keysets.
type RootPin struct {
	KeyID     string
	PublicKey [32]byte
}

// ParseRootPin validates the canonical public-key encoding and requires the
// configured key ID to be derived from those exact bytes.
func ParseRootPin(
	publicKeyBase64URL string,
	keyID string,
) (RootPin, error) {
	publicKey, err := DecodeBase64URL(publicKeyBase64URL, len(RootPin{}.PublicKey))
	if err != nil {
		return RootPin{}, ErrConfiguration
	}
	recomputed, err := Ed25519KeyID(publicKey)
	if err != nil || recomputed != keyID {
		return RootPin{}, ErrConfiguration
	}
	var pin RootPin
	pin.KeyID = keyID
	copy(pin.PublicKey[:], publicKey)
	return pin, nil
}

// TopicKeyDescriptor identifies one out-of-band topic-commitment secret
// without exposing the key itself.
type TopicKeyDescriptor struct {
	KeyID         string
	TopicKeyEpoch uint32
	NotBefore     time.Time
	NotAfter      time.Time
}

// TopicBindingCandidate is a secret-free lookup commitment for one topic-key
// epoch. Candidate lists are ordered with the current epoch first and the
// immediately previous epoch second when the exact overlap permits it.
type TopicBindingCandidate struct {
	TopicKeyEpoch uint32
	TopicBinding  [32]byte
}

type topicKeyRecord struct {
	descriptor   TopicKeyDescriptor
	key          []byte
	retireAt     time.Time
	hardRetireAt time.Time
}

// TopicKeySet owns only the TOPIC commitment secrets required by the bridge.
// ROSTER and TUPLE secrets remain exclusively with modern-api.
type TopicKeySet struct {
	mu          sync.RWMutex
	environment string
	records     []topicKeyRecord
	retireEpoch uint32
	retireAt    time.Time
	retireTimer *time.Timer
	clock       func() time.Time
	steadyClock func() time.Time
	recheck     time.Duration
	retired     TopicKeyDescriptor
	hasRetired  bool
	closed      bool
}

var topicKeyRecordFields = map[string]struct{}{
	"environment":     {},
	"purpose":         {},
	"key_id":          {},
	"topic_key_epoch": {},
	"key_base64url":   {},
	"not_before":      {},
	"not_after":       {},
}

const (
	topicKeySecretField       = "key_base64url"
	redactedTopicKeyBase64URL = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// ParseTopicKeySetBytes consumes and clears raw before returning. Production
// callers must transfer ownership of a mutable source buffer and release any
// provider-side source copy as soon as parsing succeeds.
func ParseTopicKeySetBytes(
	raw []byte,
	environment string,
) (*TopicKeySet, error) {
	return parseTopicKeySetBytes(raw, environment, time.Now)
}

func parseTopicKeySetBytes(
	raw []byte,
	environment string,
	clock func() time.Time,
) (*TopicKeySet, error) {
	defer clear(raw)
	if environment != "dev" && environment != "production" {
		return nil, ErrConfiguration
	}
	if clock == nil {
		return nil, ErrConfiguration
	}
	keys, ok := extractAndRedactTopicKeys(raw)
	if !ok {
		return nil, ErrConfiguration
	}
	defer wipeExtractedTopicKeys(keys)
	value, err := ParseStrictJSON(raw)
	if err != nil {
		return nil, ErrConfiguration
	}
	items, ok := value.([]any)
	if !ok || len(items) < 1 || len(items) > 2 ||
		len(keys) != len(items) {
		return nil, ErrConfiguration
	}

	records := make([]topicKeyRecord, 0, len(items))
	seenEpochs := make(map[uint32]bool, len(items))
	seenKeyIDs := make(map[string]bool, len(items))
	for index, item := range items {
		record, ok := parseTopicKeyRecord(
			item,
			environment,
			keys[index],
		)
		if !ok ||
			seenEpochs[record.descriptor.TopicKeyEpoch] ||
			seenKeyIDs[record.descriptor.KeyID] {
			clear(record.key)
			wipeTopicRecords(records)
			return nil, ErrConfiguration
		}
		seenEpochs[record.descriptor.TopicKeyEpoch] = true
		seenKeyIDs[record.descriptor.KeyID] = true
		records = append(records, record)
		keys[index] = nil
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].descriptor.TopicKeyEpoch <
			records[j].descriptor.TopicKeyEpoch
	})
	if len(records) == 2 &&
		records[1].descriptor.TopicKeyEpoch !=
			records[0].descriptor.TopicKeyEpoch+1 {
		wipeTopicRecords(records)
		return nil, ErrConfiguration
	}
	set := &TopicKeySet{
		environment: environment,
		records:     records,
		clock:       clock,
		steadyClock: time.Now,
		recheck:     maxRetirementClockRecheck,
	}
	set.startRetirement(set.now())
	return set, nil
}

func parseTopicKeyRecord(
	item any,
	environment string,
	key []byte,
) (topicKeyRecord, bool) {
	if len(key) != 32 {
		return topicKeyRecord{}, false
	}
	object, ok := item.(map[string]any)
	if !ok || !hasExactFields(object, topicKeyRecordFields) ||
		objectString(object, "environment") != environment ||
		objectString(object, "purpose") != "TOPIC" ||
		objectString(object, topicKeySecretField) !=
			redactedTopicKeyBase64URL {
		return topicKeyRecord{}, false
	}
	epochValue, verdict := positiveInteger(object["topic_key_epoch"])
	if !verdict.IsEligible() || epochValue > uint64(^uint32(0)) {
		return topicKeyRecord{}, false
	}
	keyID := objectString(object, "key_id")
	recomputed, err := HMACKeyID(key)
	if err != nil || recomputed != keyID {
		return topicKeyRecord{}, false
	}
	notBefore, ok := parseWireTime(objectString(object, "not_before"))
	if !ok {
		return topicKeyRecord{}, false
	}
	notAfter, ok := parseWireTime(objectString(object, "not_after"))
	if !ok || !notAfter.After(notBefore) {
		return topicKeyRecord{}, false
	}
	record := topicKeyRecord{
		descriptor: TopicKeyDescriptor{
			KeyID:         keyID,
			TopicKeyEpoch: uint32(epochValue),
			NotBefore:     notBefore,
			NotAfter:      notAfter,
		},
		key: key,
	}
	return record, true
}

// extractAndRedactTopicKeys lexes the owned JSON buffer before generic JSON
// decoding. Every canonical 32-byte Base64url value must belong to the exact
// secret field, and that value is replaced in place with the encoding of an
// all-zero key. ParseStrictJSON therefore never creates immutable strings that
// contain a configured topic secret.
func extractAndRedactTopicKeys(
	raw []byte,
) ([][]byte, bool) {
	keys := make([][]byte, 0, 2)
	for index := 0; index < len(raw); {
		if raw[index] != '"' {
			index++
			continue
		}
		end, escaped, ok := jsonStringEnd(raw, index)
		if !ok || escaped {
			wipeExtractedTopicKeys(keys)
			return nil, false
		}
		token := raw[index+1 : end]
		next := skipJSONSpace(raw, end+1)
		if next >= len(raw) || raw[next] != ':' {
			if topicSecretLike(token) {
				wipeExtractedTopicKeys(keys)
				return nil, false
			}
			index = end + 1
			continue
		}
		if topicSecretLike(token) {
			wipeExtractedTopicKeys(keys)
			return nil, false
		}

		valueStart := skipJSONSpace(raw, next+1)
		isTopicSecret := bytes.Equal(
			token,
			[]byte(topicKeySecretField),
		)
		if valueStart >= len(raw) || raw[valueStart] != '"' {
			if isTopicSecret {
				wipeExtractedTopicKeys(keys)
				return nil, false
			}
			index = end + 1
			continue
		}
		valueEnd, valueEscaped, ok := jsonStringEnd(raw, valueStart)
		if !ok || valueEscaped {
			wipeExtractedTopicKeys(keys)
			return nil, false
		}
		value := raw[valueStart+1 : valueEnd]
		key, secretLike := decodeTopicSecret(value)
		switch {
		case isTopicSecret && secretLike &&
			len(value) == len(redactedTopicKeyBase64URL):
			copy(value, redactedTopicKeyBase64URL)
			keys = append(keys, key)
			if len(keys) > 2 {
				wipeExtractedTopicKeys(keys)
				return nil, false
			}
		case isTopicSecret || secretLike:
			clear(key)
			wipeExtractedTopicKeys(keys)
			return nil, false
		default:
			clear(key)
		}
		index = valueEnd + 1
	}
	if len(keys) == 0 {
		return nil, false
	}
	return keys, true
}

func jsonStringEnd(
	raw []byte,
	start int,
) (int, bool, bool) {
	if start >= len(raw) || raw[start] != '"' {
		return 0, false, false
	}
	escaped := false
	for index := start + 1; index < len(raw); index++ {
		switch raw[index] {
		case '\\':
			escaped = true
			index++
			if index >= len(raw) {
				return 0, escaped, false
			}
		case '"':
			return index, escaped, true
		}
	}
	return 0, escaped, false
}

func skipJSONSpace(raw []byte, start int) int {
	for start < len(raw) {
		switch raw[start] {
		case ' ', '\t', '\r', '\n':
			start++
		default:
			return start
		}
	}
	return start
}

func decodeTopicSecret(
	encoded []byte,
) ([]byte, bool) {
	key := make([]byte, 32)
	var (
		count int
		err   error
	)
	switch len(encoded) {
	case len(redactedTopicKeyBase64URL):
		count, err = base64.RawURLEncoding.Strict().Decode(
			key,
			encoded,
		)
	case len(redactedTopicKeyBase64URL) + 1:
		count, err = base64.URLEncoding.Strict().Decode(
			key,
			encoded,
		)
	default:
		clear(key)
		return nil, false
	}
	if err != nil || count != len(key) {
		clear(key)
		return nil, false
	}
	return key, true
}

func topicSecretLike(encoded []byte) bool {
	key, ok := decodeTopicSecret(encoded)
	clear(key)
	return ok
}

func wipeExtractedTopicKeys(keys [][]byte) {
	for index := range keys {
		clear(keys[index])
		keys[index] = nil
	}
	clear(keys)
}

func (set *TopicKeySet) Environment() string {
	if set == nil {
		return ""
	}
	set.mu.RLock()
	defer set.mu.RUnlock()
	if set.closed {
		return ""
	}
	return set.environment
}

// Descriptors returns a secret-free copy of the configured records.
func (set *TopicKeySet) Descriptors() []TopicKeyDescriptor {
	if set == nil {
		return nil
	}
	set.mu.Lock()
	defer set.mu.Unlock()
	set.eraseRetiredLocked(set.now())
	if set.closed || len(set.records) == 0 {
		return nil
	}
	descriptors := make([]TopicKeyDescriptor, len(set.records))
	for index := range set.records {
		descriptors[index] = set.records[index].descriptor
	}
	return descriptors
}

// currentEpochUsable reports whether the exact root-signed current TOPIC
// descriptor still has its matching local secret. It is deliberately
// read-only: readiness must not advance retirement, derive a persisted
// commitment, or latch trust state.
func (set *TopicKeySet) currentEpochUsable(
	at time.Time,
	signed []CommitmentKey,
) bool {
	if set == nil || at.IsZero() {
		return false
	}
	at = at.UTC()
	epoch := TopicEpoch(at)
	var accepted *CommitmentKey
	for index := range signed {
		descriptor := &signed[index]
		if descriptor.Purpose != "TOPIC" ||
			descriptor.TopicKeyEpoch == nil ||
			*descriptor.TopicKeyEpoch != epoch {
			continue
		}
		if accepted != nil {
			return false
		}
		accepted = descriptor
	}
	if accepted == nil ||
		at.Before(accepted.NotBefore) ||
		!at.Before(accepted.NotAfter) {
		return false
	}

	set.mu.RLock()
	defer set.mu.RUnlock()
	if set.closed {
		return false
	}
	var local *topicKeyRecord
	for index := range set.records {
		record := &set.records[index]
		if record.descriptor.TopicKeyEpoch != epoch {
			continue
		}
		if local != nil {
			return false
		}
		local = record
	}
	if local == nil ||
		!topicKeyDescriptorEqual(local.descriptor, *accepted) ||
		at.Before(local.descriptor.NotBefore) ||
		!at.Before(local.descriptor.NotAfter) {
		return false
	}
	recomputed, err := HMACKeyID(local.key)
	return err == nil && recomputed == local.descriptor.KeyID
}

// Reconcile requires every locally provisioned secret to match root-signed
// public metadata. At and after the mandatory erasure deadline, the signed
// keyset may still retain the immediately previous public descriptor, but a
// missing current or future local secret always fails closed.
func (set *TopicKeySet) Reconcile(
	keyset map[string]any,
	now time.Time,
) Verdict {
	if set == nil {
		return Inconclusive("KEY_STATE")
	}
	set.mu.Lock()
	defer set.mu.Unlock()
	set.eraseRetiredLocked(now.UTC())
	if set.closed {
		return Inconclusive("KEY_STATE")
	}
	descriptors, ok := parseCommitmentKeys(keyset["commitment_keys"])
	if !ok {
		return Inconclusive("KEY_STATE")
	}
	var topicDescriptors []CommitmentKey
	for _, descriptor := range descriptors {
		if descriptor.Purpose == "TOPIC" {
			topicDescriptors = append(topicDescriptors, descriptor)
		}
	}
	matched := make([]bool, len(set.records))
	currentEpoch := TopicEpoch(now)
	currentHeld := false
	retiredDescriptorSeen := false
	for _, descriptor := range topicDescriptors {
		if descriptor.TopicKeyEpoch == nil {
			return Inconclusive("KEY_STATE")
		}
		found := false
		for index := range set.records {
			record := &set.records[index]
			if record.descriptor.TopicKeyEpoch != *descriptor.TopicKeyEpoch {
				continue
			}
			if record.descriptor.KeyID != descriptor.KeyID ||
				!record.descriptor.NotBefore.Equal(descriptor.NotBefore) ||
				!record.descriptor.NotAfter.Equal(descriptor.NotAfter) ||
				matched[index] {
				return Inconclusive("KEY_STATE")
			}
			recomputed, err := HMACKeyID(record.key)
			if err != nil || recomputed != descriptor.KeyID {
				return Inconclusive("KEY_STATE")
			}
			matched[index] = true
			found = true
			if record.descriptor.TopicKeyEpoch == currentEpoch {
				currentHeld = true
			}
			break
		}
		if !found {
			allowRetiredDescriptor := currentEpoch > 0 &&
				*descriptor.TopicKeyEpoch == currentEpoch-1 &&
				!now.Before(
					TopicEpochBoundary(currentEpoch).
						Add(60*time.Second),
				) &&
				set.hasRetired &&
				topicKeyDescriptorEqual(
					set.retired,
					descriptor,
				) &&
				!retiredDescriptorSeen
			if !allowRetiredDescriptor {
				return Inconclusive("KEY_STATE")
			}
			retiredDescriptorSeen = true
		}
	}
	for _, found := range matched {
		if !found {
			return Inconclusive("KEY_STATE")
		}
	}
	if !currentHeld {
		return Inconclusive("KEY_STATE")
	}
	return Eligible()
}

// BindingForEpoch recomputes the lookup commitment without returning the raw
// topic key. The previous epoch is available only for an already accepted,
// still-unexpired assertion during the exact 60-second overlap.
func (set *TopicKeySet) BindingForEpoch(
	topic []byte,
	epoch uint32,
	now time.Time,
	assertionExpiresAt time.Time,
	alreadyAccepted bool,
) ([]byte, Verdict) {
	if set == nil {
		return nil, Inconclusive("KEY_STATE")
	}
	set.mu.Lock()
	defer set.mu.Unlock()
	set.eraseRetiredLocked(now)
	if set.closed {
		return nil, Inconclusive("KEY_STATE")
	}
	for index := range set.records {
		record := &set.records[index]
		if record.descriptor.TopicKeyEpoch != epoch {
			continue
		}
		if now.Before(record.descriptor.NotBefore) ||
			!now.Before(record.descriptor.NotAfter) {
			return nil, Invalid("KEY_STATE")
		}
		currentEpoch := TopicEpoch(now)
		switch {
		case epoch == currentEpoch:
		case PreviousTopicEpochVerificationUsable(
			epoch,
			now,
			assertionExpiresAt,
			alreadyAccepted,
		):
		default:
			return nil, Invalid("TOPIC_KEY_EPOCH")
		}
		binding, err := TopicBinding(record.key, topic)
		if err != nil {
			return nil, Invalid("TOPIC_RESOLVER")
		}
		return binding, Eligible()
	}
	return nil, Invalid("TOPIC_KEY_EPOCH")
}

// candidateTopicBindings returns the current lookup commitment followed by
// the immediately previous commitment during the exact 60-second overlap.
// Unlike assertion verification, route lookup has no assertion-expiry state
// and therefore does not fabricate one to reuse BindingForEpoch.
func (set *TopicKeySet) candidateTopicBindings(
	topic []byte,
	at time.Time,
) ([]TopicBindingCandidate, Verdict) {
	if set == nil || at.IsZero() {
		return nil, Inconclusive("KEY_STATE")
	}
	set.mu.Lock()
	defer set.mu.Unlock()
	at = at.UTC()
	set.eraseRetiredLocked(at)
	if set.closed {
		return nil, Inconclusive("KEY_STATE")
	}

	currentEpoch := TopicEpoch(at)
	epochs := [2]uint32{currentEpoch, 0}
	epochCount := 1
	if currentEpoch > 0 &&
		at.Before(TopicEpochBoundary(currentEpoch).Add(60*time.Second)) {
		epochs[1] = currentEpoch - 1
		epochCount = 2
	}

	candidates := make([]TopicBindingCandidate, 0, epochCount)
	for epochIndex := 0; epochIndex < epochCount; epochIndex++ {
		epoch := epochs[epochIndex]
		found := false
		for recordIndex := range set.records {
			record := &set.records[recordIndex]
			if record.descriptor.TopicKeyEpoch != epoch {
				continue
			}
			found = true
			if at.Before(record.descriptor.NotBefore) ||
				!at.Before(record.descriptor.NotAfter) {
				return nil, Inconclusive("KEY_STATE")
			}
			var candidate TopicBindingCandidate
			binding, err := TopicBinding(record.key, topic)
			if err != nil || len(binding) != len(candidate.TopicBinding) {
				clear(binding)
				return nil, Invalid("TOPIC_RESOLVER")
			}
			candidate.TopicKeyEpoch = epoch
			copy(candidate.TopicBinding[:], binding)
			clear(binding)
			candidates = append(candidates, candidate)
			break
		}
		if epochIndex == 0 && !found {
			return nil, Inconclusive("KEY_STATE")
		}
	}
	return candidates, Eligible()
}

func clearTopicBindingCandidates(candidates []TopicBindingCandidate) {
	for index := range candidates {
		clear(candidates[index].TopicBinding[:])
		candidates[index].TopicKeyEpoch = 0
	}
	clear(candidates)
}

// EqualBinding performs the required constant-time comparison.
func EqualBinding(left, right []byte) bool {
	return len(left) == len(right) &&
		subtle.ConstantTimeCompare(left, right) == 1
}

// Close erases the package-owned copies of the out-of-band secrets.
func (set *TopicKeySet) Close() {
	if set == nil {
		return
	}
	set.mu.Lock()
	defer set.mu.Unlock()
	if set.closed {
		return
	}
	if set.retireTimer != nil {
		set.retireTimer.Stop()
	}
	wipeTopicRecords(set.records)
	set.records = nil
	set.environment = ""
	set.retireEpoch = 0
	set.retireAt = time.Time{}
	set.retireTimer = nil
	set.clock = nil
	set.steadyClock = nil
	set.recheck = 0
	set.retired = TopicKeyDescriptor{}
	set.hasRetired = false
	set.closed = true
}

func (set *TopicKeySet) startRetirement(now time.Time) {
	set.mu.Lock()
	defer set.mu.Unlock()
	if set.closed || len(set.records) == 0 {
		return
	}
	set.scheduleRetirementLocked(now)
}

func (set *TopicKeySet) scheduleRetirementLocked(now time.Time) {
	if set.closed || len(set.records) == 0 {
		return
	}
	steadyNow := set.steadyNow()
	set.initializeRetirementDeadlinesLocked(now, steadyNow)
	var (
		retireEpoch  uint32
		retireAt     time.Time
		hardRetireAt time.Time
	)
	for index := range set.records {
		record := &set.records[index]
		epoch := record.descriptor.TopicKeyEpoch
		if epoch == ^uint32(0) {
			continue
		}
		if retireAt.IsZero() || record.retireAt.Before(retireAt) {
			retireEpoch = epoch
			retireAt = record.retireAt
			hardRetireAt = record.hardRetireAt
		}
	}
	if retireAt.IsZero() {
		return
	}
	set.retireEpoch = retireEpoch
	set.retireAt = retireAt
	if !now.Before(retireAt) ||
		!steadyNow.Before(hardRetireAt) {
		set.eraseRetiredLockedAt(now, steadyNow)
		return
	}
	delay := retireAt.Sub(now)
	hardDelay := hardRetireAt.Sub(steadyNow)
	if hardDelay < delay {
		delay = hardDelay
	}
	recheck := set.recheck
	if recheck <= 0 || recheck > maxRetirementClockRecheck {
		recheck = maxRetirementClockRecheck
	}
	if delay > recheck {
		delay = recheck
	}
	set.retireTimer = time.AfterFunc(delay, func() {
		set.mu.Lock()
		defer set.mu.Unlock()
		set.retireTimer = nil
		set.eraseRetiredLocked(set.now())
	})
}

func (set *TopicKeySet) now() time.Time {
	if set.clock == nil {
		return time.Now().UTC()
	}
	return set.clock().UTC()
}

func (set *TopicKeySet) steadyNow() time.Time {
	if set.steadyClock == nil {
		return time.Now()
	}
	return set.steadyClock()
}

func (set *TopicKeySet) initializeRetirementDeadlinesLocked(
	now time.Time,
	steadyNow time.Time,
) {
	for index := range set.records {
		record := &set.records[index]
		epoch := record.descriptor.TopicKeyEpoch
		if epoch == ^uint32(0) {
			continue
		}
		if record.retireAt.IsZero() {
			record.retireAt = TopicEpochBoundary(epoch + 1).
				Add(60 * time.Second)
		}
		if record.hardRetireAt.IsZero() {
			delay := record.retireAt.Sub(now)
			if delay < 0 {
				delay = 0
			}
			// time.Now carries a monotonic reading. Add preserves it, so this
			// deadline cannot move when the injected wall clock freezes or
			// rolls backward.
			record.hardRetireAt = steadyNow.Add(delay)
		}
	}
}

func (set *TopicKeySet) eraseRetiredLocked(now time.Time) {
	if set.closed || len(set.records) == 0 {
		return
	}
	steadyNow := set.steadyNow()
	set.initializeRetirementDeadlinesLocked(now, steadyNow)
	set.eraseRetiredLockedAt(now, steadyNow)
}

func (set *TopicKeySet) eraseRetiredLockedAt(
	now time.Time,
	steadyNow time.Time,
) {
	if set.closed || len(set.records) == 0 {
		return
	}
	due := false
	for index := range set.records {
		record := &set.records[index]
		if record.descriptor.TopicKeyEpoch != ^uint32(0) &&
			(!now.Before(record.retireAt) ||
				!steadyNow.Before(record.hardRetireAt)) {
			due = true
			break
		}
	}
	if !due {
		if set.retireTimer == nil {
			set.scheduleRetirementLocked(now)
		}
		return
	}
	if set.retireTimer != nil {
		set.retireTimer.Stop()
		set.retireTimer = nil
	}
	kept := make([]topicKeyRecord, 0, len(set.records)-1)
	for index := range set.records {
		record := &set.records[index]
		if record.descriptor.TopicKeyEpoch != ^uint32(0) &&
			(!now.Before(record.retireAt) ||
				!steadyNow.Before(record.hardRetireAt)) {
			if !set.hasRetired ||
				record.descriptor.TopicKeyEpoch >
					set.retired.TopicKeyEpoch {
				set.retired = record.descriptor
				set.hasRetired = true
			}
			clear(record.key)
			record.key = nil
			continue
		}
		kept = append(kept, *record)
		record.key = nil
	}
	clear(set.records)
	set.records = kept
	set.retireEpoch = 0
	set.retireAt = time.Time{}
	set.retireTimer = nil
	set.scheduleRetirementLocked(now)
}

func topicKeyDescriptorEqual(
	retired TopicKeyDescriptor,
	signed CommitmentKey,
) bool {
	return signed.TopicKeyEpoch != nil &&
		retired.TopicKeyEpoch == *signed.TopicKeyEpoch &&
		retired.KeyID == signed.KeyID &&
		retired.NotBefore.Equal(signed.NotBefore) &&
		retired.NotAfter.Equal(signed.NotAfter)
}

func wipeTopicRecords(records []topicKeyRecord) {
	for index := range records {
		clear(records[index].key)
		records[index].key = nil
	}
	clear(records)
}

func hasExactFields(
	object map[string]any,
	fields map[string]struct{},
) bool {
	if len(object) != len(fields) {
		return false
	}
	for field := range object {
		if _, ok := fields[field]; !ok {
			return false
		}
	}
	return true
}
