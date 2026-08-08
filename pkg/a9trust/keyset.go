package a9trust

import (
	"crypto/ed25519"
	"sort"
	"strings"
	"time"
)

type OnlineKey struct {
	KeyID     string
	Use       string
	PublicKey []byte
	NotBefore time.Time
	NotAfter  time.Time
	State     string
}

type CommitmentKey struct {
	Purpose       string
	KeyID         string
	TopicKeyEpoch *uint32
	NotBefore     time.Time
	NotAfter      time.Time
}

func ValidateKeyset(object map[string]any, pinnedRootPublic []byte, pinnedRootKeyID, environment string, now time.Time) Verdict {
	if objectString(object, "protocol") != "hytch.a9-bridge-keyset" ||
		!objectIntegerEquals(object, "schema_version", 1) ||
		objectString(object, "environment") != environment ||
		objectString(object, "root_signature_algorithm") != "Ed25519" {
		return Inconclusive("KEY_STATE")
	}
	expectedRootID, err := Ed25519KeyID(pinnedRootPublic)
	if err != nil || pinnedRootKeyID != expectedRootID ||
		objectString(object, "root_signing_key_id") != pinnedRootKeyID {
		return Inconclusive("KEY_STATE")
	}
	issued, ok := parseWireTime(objectString(object, "issued_at"))
	if !ok {
		return Inconclusive("KEY_STATE")
	}
	expires, ok := parseWireTime(objectString(object, "expires_at"))
	if !ok || !expires.After(issued) || expires.Sub(issued) > 24*time.Hour ||
		(!now.IsZero() &&
			(now.Before(issued) || !now.Before(expires))) {
		return Inconclusive("KEY_STATE")
	}
	if _, verdict := positiveInteger(object["keyset_sequence"]); !verdict.IsEligible() {
		return Inconclusive("KEY_STATE")
	}
	online, ok := parseOnlineKeys(object["keys"])
	if !ok || len(online) < 2 || len(online) > 4 || !onlineKeysOrdered(online) {
		return Inconclusive("KEY_STATE")
	}
	signCounts := map[string]int{"A9_CONTROL": 0, "SERVICE_AUTH": 0}
	seenOnline := make(map[string]bool)
	for _, key := range online {
		if seenOnline[key.KeyID] || (key.Use != "A9_CONTROL" && key.Use != "SERVICE_AUTH") ||
			(key.State != "SIGN" && key.State != "VERIFY_ONLY") ||
			!key.NotAfter.After(key.NotBefore) {
			return Inconclusive("KEY_STATE")
		}
		seenOnline[key.KeyID] = true
		recomputed, _ := Ed25519KeyID(key.PublicKey)
		if recomputed != key.KeyID {
			return Inconclusive("KEY_STATE")
		}
		if key.State == "SIGN" {
			signCounts[key.Use]++
		}
	}
	if signCounts["A9_CONTROL"] != 1 || signCounts["SERVICE_AUTH"] != 1 {
		return Inconclusive("KEY_STATE")
	}
	for _, use := range []string{"A9_CONTROL", "SERVICE_AUTH"} {
		if _, verdict := SigningKeyAt(object, use, issued); !verdict.IsEligible() {
			return Inconclusive("KEY_STATE")
		}
	}
	commitments, ok := parseCommitmentKeys(object["commitment_keys"])
	if !ok || len(commitments) < 3 || len(commitments) > 6 || !commitmentKeysOrdered(commitments) {
		return Inconclusive("KEY_STATE")
	}
	counts := map[string]int{"ROSTER": 0, "TOPIC": 0, "TUPLE": 0}
	seenCommitment := make(map[string]bool)
	for _, descriptor := range commitments {
		if seenCommitment[descriptor.KeyID] || !descriptor.NotAfter.After(descriptor.NotBefore) ||
			!strings.HasPrefix(descriptor.KeyID, "hmac-sha256:") ||
			!lowerHex64Pattern.MatchString(strings.TrimPrefix(descriptor.KeyID, "hmac-sha256:")) {
			return Inconclusive("KEY_STATE")
		}
		seenCommitment[descriptor.KeyID] = true
		switch descriptor.Purpose {
		case "TOPIC":
			if descriptor.TopicKeyEpoch == nil || *descriptor.TopicKeyEpoch == 0 {
				return Inconclusive("KEY_STATE")
			}
		case "ROSTER", "TUPLE":
			if descriptor.TopicKeyEpoch != nil {
				return Inconclusive("KEY_STATE")
			}
		default:
			return Inconclusive("KEY_STATE")
		}
		counts[descriptor.Purpose]++
	}
	for _, purpose := range []string{"ROSTER", "TOPIC", "TUPLE"} {
		if counts[purpose] < 1 || counts[purpose] > 2 {
			return Inconclusive("KEY_STATE")
		}
	}
	rootVerdict := VerifyObject(object, "root_signature_base64url", KeysetSignatureDomain, pinnedRootPublic)
	if !rootVerdict.IsEligible() {
		return Inconclusive("KEY_STATE")
	}
	return Eligible()
}

// OnlineKeyAt returns an artifact-verification key. Both SIGN and VERIFY_ONLY
// descriptors can verify, but the validity window is half-open.
func OnlineKeyAt(keyset map[string]any, keyID, use string, at time.Time) ([]byte, Verdict) {
	keys, ok := parseOnlineKeys(keyset["keys"])
	if !ok {
		return nil, Invalid("KEY_STATE")
	}
	for _, key := range keys {
		if key.KeyID != keyID || key.Use != use {
			continue
		}
		if at.Before(key.NotBefore) || !at.Before(key.NotAfter) {
			return nil, Invalid("KEY_STATE")
		}
		return key.PublicKey, Eligible()
	}
	return nil, Invalid("KEY_STATE")
}

// SigningKeyAt returns the sole active SIGN descriptor for issuing an
// artifact.
func SigningKeyAt(keyset map[string]any, use string, at time.Time) (OnlineKey, Verdict) {
	keys, ok := parseOnlineKeys(keyset["keys"])
	if !ok {
		return OnlineKey{}, Invalid("KEY_STATE")
	}
	var selected *OnlineKey
	for i := range keys {
		key := &keys[i]
		if key.Use == use && key.State == "SIGN" &&
			!at.Before(key.NotBefore) && at.Before(key.NotAfter) {
			if selected != nil {
				return OnlineKey{}, Invalid("KEY_STATE")
			}
			selected = key
		}
	}
	if selected == nil {
		return OnlineKey{}, Invalid("KEY_STATE")
	}
	return *selected, Eligible()
}

func CommitmentKeyAt(keyset map[string]any, purpose string, topicEpoch *uint32, at time.Time, forIssuance bool) (CommitmentKey, Verdict) {
	keys, ok := parseCommitmentKeys(keyset["commitment_keys"])
	if !ok {
		return CommitmentKey{}, Invalid("KEY_STATE")
	}
	var selected *CommitmentKey
	for i := range keys {
		key := &keys[i]
		if key.Purpose != purpose || !sameEpoch(key.TopicKeyEpoch, topicEpoch) {
			continue
		}
		if at.Before(key.NotBefore) || !at.Before(key.NotAfter) {
			continue
		}
		if purpose == "TOPIC" && (topicEpoch == nil || !TopicEpochUsable(*topicEpoch, at, forIssuance)) {
			continue
		}
		if selected != nil {
			return CommitmentKey{}, Invalid("KEY_STATE")
		}
		selected = key
	}
	if selected == nil {
		if purpose == "TOPIC" {
			return CommitmentKey{}, Invalid("TOPIC_KEY_EPOCH")
		}
		return CommitmentKey{}, Invalid("KEY_STATE")
	}
	return *selected, Eligible()
}

func ValidateKeysetSequence(incoming map[string]any, storedSequence uint64, storedObjectHash string) Verdict {
	sequence, verdict := positiveInteger(incoming["keyset_sequence"])
	if !verdict.IsEligible() {
		return Inconclusive("KEYSET_ROLLBACK")
	}
	if sequence < storedSequence {
		return Inconclusive("KEYSET_ROLLBACK")
	}
	if sequence == storedSequence && storedObjectHash != "" {
		hash, err := CanonicalObjectHash(incoming)
		if err != nil || hash != storedObjectHash {
			return Inconclusive("KEYSET_ROLLBACK")
		}
	}
	return Eligible()
}

// ValidateOnlineRotation checks every online signing-key change between two
// accepted keysets. A9_CONTROL and SERVICE_AUTH rotate independently, and an
// unchanged use does not require the other use to rotate at the same time.
func ValidateOnlineRotation(transition, cutover map[string]any) Verdict {
	transitionSequence, v := positiveInteger(transition["keyset_sequence"])
	if !v.IsEligible() {
		return Inconclusive("KEY_STATE")
	}
	cutoverSequence, v := positiveInteger(cutover["keyset_sequence"])
	if !v.IsEligible() || cutoverSequence <= transitionSequence {
		return Inconclusive("KEY_STATE")
	}
	transitionIssued, ok := parseWireTime(objectString(transition, "issued_at"))
	if !ok {
		return Inconclusive("KEY_STATE")
	}
	cutoverIssued, ok := parseWireTime(objectString(cutover, "issued_at"))
	if !ok {
		return Inconclusive("KEY_STATE")
	}
	before, ok := parseOnlineKeys(transition["keys"])
	if !ok {
		return Inconclusive("KEY_STATE")
	}
	after, ok := parseOnlineKeys(cutover["keys"])
	if !ok {
		return Inconclusive("KEY_STATE")
	}
	if cutoverIssued.Before(transitionIssued) {
		return Inconclusive("KEY_STATE")
	}
	for _, use := range []string{"A9_CONTROL", "SERVICE_AUTH"} {
		if verdict := validateOnlineRotationForUse(
			before,
			after,
			use,
			transitionIssued,
			cutoverIssued,
		); !verdict.IsEligible() {
			return verdict
		}
	}
	return Eligible()
}

func validateOnlineRotationForUse(
	before []OnlineKey,
	after []OnlineKey,
	use string,
	transitionIssued time.Time,
	cutoverIssued time.Time,
) Verdict {
	oldSign, ok := soleSigningKeyForUse(before, use)
	if !ok {
		return Inconclusive("KEY_STATE")
	}
	newSign, ok := soleSigningKeyForUse(after, use)
	if !ok {
		return Inconclusive("KEY_STATE")
	}
	if oldSign.KeyID == newSign.KeyID {
		if !sameOnlineKeyMaterial(oldSign, newSign) {
			return Inconclusive("KEY_STATE")
		}
		return validateVerifyOnlyContinuity(
			before,
			after,
			use,
			transitionIssued,
			cutoverIssued,
			"",
			"",
		)
	}

	staged, ok := findOnlineKey(before, use, oldSign.KeyID, newSign.KeyID)
	if !ok ||
		staged.State != "VERIFY_ONLY" ||
		staged.NotBefore.Sub(transitionIssued) < 24*time.Hour ||
		cutoverIssued.Before(staged.NotBefore) ||
		!sameOnlineKeyMaterial(staged, newSign) {
		return Inconclusive("KEY_STATE")
	}
	oldVerify, ok := findOnlineKey(after, use, newSign.KeyID, oldSign.KeyID)
	if !ok ||
		oldVerify.State != "VERIFY_ONLY" ||
		!sameOnlineKeyMaterial(oldSign, oldVerify) {
		return Inconclusive("KEY_STATE")
	}

	retention := 90 * time.Second
	if use == "SERVICE_AUTH" {
		// A service JWT may live for 60 seconds and remains acceptable for the
		// five-second verifier skew. The old verifier then remains published for
		// the contract's additional 60-second retirement interval.
		retention = 125 * time.Second
	}
	if oldVerify.NotAfter.Before(cutoverIssued.Add(retention)) {
		return Inconclusive("KEY_STATE")
	}
	return validateVerifyOnlyContinuity(
		before,
		after,
		use,
		transitionIssued,
		cutoverIssued,
		staged.KeyID,
		oldVerify.KeyID,
	)
}

func validateVerifyOnlyContinuity(
	before []OnlineKey,
	after []OnlineKey,
	use string,
	transitionIssued time.Time,
	cutoverIssued time.Time,
	promotedKeyID string,
	retiredKeyID string,
) Verdict {
	for index := range before {
		key := &before[index]
		if key.Use != use ||
			key.State != "VERIFY_ONLY" ||
			key.KeyID == promotedKeyID {
			continue
		}
		if key.NotBefore.After(transitionIssued) &&
			!cutoverIssued.Before(key.NotBefore) {
			return Inconclusive("KEY_STATE")
		}
		next, exists := onlineKeyByID(after, use, key.KeyID)
		if cutoverIssued.Before(key.NotAfter) {
			if !exists ||
				next.State != "VERIFY_ONLY" ||
				!sameOnlineKeyMaterial(*key, next) {
				return Inconclusive("KEY_STATE")
			}
			continue
		}
		if exists && !sameOnlineKeyMaterial(*key, next) {
			return Inconclusive("KEY_STATE")
		}
	}
	for index := range after {
		key := &after[index]
		if key.Use != use ||
			key.State != "VERIFY_ONLY" ||
			key.KeyID == retiredKeyID {
			continue
		}
		if _, existed := onlineKeyByID(before, use, key.KeyID); existed {
			continue
		}
		if key.NotBefore.Sub(cutoverIssued) < 24*time.Hour {
			return Inconclusive("KEY_STATE")
		}
	}
	return Eligible()
}

func soleSigningKeyForUse(keys []OnlineKey, use string) (OnlineKey, bool) {
	var selected *OnlineKey
	for index := range keys {
		key := &keys[index]
		if key.Use != use || key.State != "SIGN" {
			continue
		}
		if selected != nil {
			return OnlineKey{}, false
		}
		selected = key
	}
	if selected == nil {
		return OnlineKey{}, false
	}
	return *selected, true
}

func findOnlineKey(
	keys []OnlineKey,
	use string,
	excludedKeyID string,
	keyID string,
) (OnlineKey, bool) {
	var selected *OnlineKey
	for index := range keys {
		key := &keys[index]
		if key.Use != use ||
			key.KeyID == excludedKeyID ||
			key.KeyID != keyID {
			continue
		}
		if selected != nil {
			return OnlineKey{}, false
		}
		selected = key
	}
	if selected == nil {
		return OnlineKey{}, false
	}
	return *selected, true
}

func onlineKeyByID(
	keys []OnlineKey,
	use string,
	keyID string,
) (OnlineKey, bool) {
	var selected *OnlineKey
	for index := range keys {
		key := &keys[index]
		if key.Use != use || key.KeyID != keyID {
			continue
		}
		if selected != nil {
			return OnlineKey{}, false
		}
		selected = key
	}
	if selected == nil {
		return OnlineKey{}, false
	}
	return *selected, true
}

func sameOnlineKeyMaterial(left, right OnlineKey) bool {
	return left.KeyID == right.KeyID &&
		bytesEqual(left.PublicKey, right.PublicKey) &&
		left.NotBefore.Equal(right.NotBefore) &&
		left.NotAfter.Equal(right.NotAfter)
}

// ValidateTopicTransition enforces the exact current/next-period handoff.
func ValidateTopicTransition(keyset map[string]any) Verdict {
	issued, ok := parseWireTime(objectString(keyset, "issued_at"))
	if !ok {
		return Inconclusive("KEY_STATE")
	}
	currentEpoch := TopicEpoch(issued)
	nextEpoch := currentEpoch + 1
	descriptors, ok := parseCommitmentKeys(keyset["commitment_keys"])
	if !ok {
		return Inconclusive("KEY_STATE")
	}
	var current, next *CommitmentKey
	for i := range descriptors {
		descriptor := &descriptors[i]
		if descriptor.Purpose != "TOPIC" || descriptor.TopicKeyEpoch == nil {
			continue
		}
		switch *descriptor.TopicKeyEpoch {
		case currentEpoch:
			current = descriptor
		case nextEpoch:
			next = descriptor
		}
	}
	boundary := TopicEpochBoundary(nextEpoch)
	if current == nil || next == nil ||
		!next.NotBefore.Equal(boundary) ||
		current.NotAfter.Before(boundary.Add(60*time.Second)) {
		return Inconclusive("KEY_STATE")
	}
	return Eligible()
}

// ValidateTopicKeySchedule validates the topic descriptors usable by a
// bridge at keyset issue time. A one-key steady state is valid. A two-key
// state must be either current+next with the exact boundary handoff or, for
// the first 60 seconds of a new period, previous+current with the same
// handoff. Other epoch combinations fail closed.
func ValidateTopicKeySchedule(keyset map[string]any) Verdict {
	issued, ok := parseWireTime(objectString(keyset, "issued_at"))
	if !ok {
		return Inconclusive("KEY_STATE")
	}
	descriptors, ok := parseCommitmentKeys(keyset["commitment_keys"])
	if !ok {
		return Inconclusive("KEY_STATE")
	}
	var topic []CommitmentKey
	for _, descriptor := range descriptors {
		if descriptor.Purpose == "TOPIC" {
			topic = append(topic, descriptor)
		}
	}
	if len(topic) < 1 || len(topic) > 2 {
		return Inconclusive("KEY_STATE")
	}

	currentEpoch := TopicEpoch(issued)
	var current, adjacent *CommitmentKey
	for index := range topic {
		descriptor := &topic[index]
		if descriptor.TopicKeyEpoch == nil {
			return Inconclusive("KEY_STATE")
		}
		if *descriptor.TopicKeyEpoch == currentEpoch {
			if current != nil {
				return Inconclusive("KEY_STATE")
			}
			current = descriptor
		} else {
			if adjacent != nil {
				return Inconclusive("KEY_STATE")
			}
			adjacent = descriptor
		}
	}
	if current == nil ||
		issued.Before(current.NotBefore) ||
		!issued.Before(current.NotAfter) {
		return Inconclusive("KEY_STATE")
	}
	if adjacent == nil {
		return Eligible()
	}

	switch adjacentEpoch := *adjacent.TopicKeyEpoch; {
	case adjacentEpoch == currentEpoch+1:
		boundary := TopicEpochBoundary(adjacentEpoch)
		if !adjacent.NotBefore.Equal(boundary) ||
			current.NotAfter.Before(boundary.Add(60*time.Second)) {
			return Inconclusive("KEY_STATE")
		}
	case currentEpoch > 0 && adjacentEpoch == currentEpoch-1:
		boundary := TopicEpochBoundary(currentEpoch)
		if !current.NotBefore.Equal(boundary) ||
			adjacent.NotAfter.Before(boundary.Add(60*time.Second)) ||
			!issued.Before(boundary.Add(60*time.Second)) {
			return Inconclusive("KEY_STATE")
		}
	default:
		return Inconclusive("KEY_STATE")
	}
	return Eligible()
}

func parseOnlineKeys(value any) ([]OnlineKey, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	keys := make([]OnlineKey, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok || len(object) != 6 {
			return nil, false
		}
		publicKey, err := DecodeBase64URL(objectString(object, "public_key_base64url"), ed25519.PublicKeySize)
		if err != nil {
			return nil, false
		}
		notBefore, ok := parseWireTime(objectString(object, "not_before"))
		if !ok {
			return nil, false
		}
		notAfter, ok := parseWireTime(objectString(object, "not_after"))
		if !ok {
			return nil, false
		}
		keys = append(keys, OnlineKey{
			KeyID: objectString(object, "key_id"), Use: objectString(object, "use"),
			PublicKey: publicKey, NotBefore: notBefore, NotAfter: notAfter,
			State: objectString(object, "state"),
		})
	}
	return keys, true
}

func parseCommitmentKeys(value any) ([]CommitmentKey, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	keys := make([]CommitmentKey, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok || len(object) != 5 {
			return nil, false
		}
		var epoch *uint32
		if object["topic_key_epoch"] != nil {
			n, verdict := positiveInteger(object["topic_key_epoch"])
			if !verdict.IsEligible() || n > uint64(^uint32(0)) {
				return nil, false
			}
			converted := uint32(n)
			epoch = &converted
		}
		notBefore, ok := parseWireTime(objectString(object, "not_before"))
		if !ok {
			return nil, false
		}
		notAfter, ok := parseWireTime(objectString(object, "not_after"))
		if !ok {
			return nil, false
		}
		keys = append(keys, CommitmentKey{
			Purpose: objectString(object, "purpose"), KeyID: objectString(object, "key_id"),
			TopicKeyEpoch: epoch, NotBefore: notBefore, NotAfter: notAfter,
		})
	}
	return keys, true
}

func onlineKeysOrdered(keys []OnlineKey) bool {
	return sort.SliceIsSorted(keys, func(i, j int) bool {
		left := keys[i].Use + "\x00" + keys[i].State + "\x00" + keys[i].KeyID
		right := keys[j].Use + "\x00" + keys[j].State + "\x00" + keys[j].KeyID
		return left < right
	})
}

func commitmentKeysOrdered(keys []CommitmentKey) bool {
	return sort.SliceIsSorted(keys, func(i, j int) bool {
		return commitmentSortKey(keys[i]) < commitmentSortKey(keys[j])
	})
}

func commitmentSortKey(key CommitmentKey) string {
	epoch := ""
	if key.TopicKeyEpoch != nil {
		epoch = leftPadUint(*key.TopicKeyEpoch, 10)
	}
	return key.Purpose + "\x00" + epoch + "\x00" +
		key.NotBefore.Format("2006-01-02T15:04:05.000Z") + "\x00" + key.KeyID
}

func sameEpoch(a, b *uint32) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

func leftPadUint(value uint32, width int) string {
	if value == 0 {
		if width <= 1 {
			return "0"
		}
		return strings.Repeat("0", width-1) + "0"
	}
	var reversed [10]byte
	i := len(reversed)
	for value > 0 {
		i--
		reversed[i] = byte('0' + value%10)
		value /= 10
	}
	result := string(reversed[i:])
	if len(result) < width {
		result = strings.Repeat("0", width-len(result)) + result
	}
	return result
}
