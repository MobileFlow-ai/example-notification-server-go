package a9trust

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseTopicKeySetBytesConsumesConfigurationBuffer(t *testing.T) {
	fixture := managerFixtureFromCorpus(t)
	redacted := []byte(fixture.topicConfig)
	extracted, ok := extractAndRedactTopicKeys(redacted)
	if !ok || len(extracted) < 1 || len(extracted) > 2 {
		t.Fatalf("pre-parser extraction count = %d, ok=%v", len(extracted), ok)
	}
	if bytes.Count(
		redacted,
		[]byte(redactedTopicKeyBase64URL),
	) != len(extracted) {
		t.Fatal("generic JSON input retained a configured secret")
	}
	wipeExtractedTopicKeys(extracted)
	for index := range extracted {
		if !allBytesZero(extracted[index][:]) {
			t.Fatal("extracted secret copy was not cleared")
		}
	}
	clear(redacted)

	raw := []byte(fixture.topicConfig)
	set, err := ParseTopicKeySetBytes(raw, "dev")
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	if !allBytesZero(raw) {
		t.Fatal("configuration source buffer was not cleared")
	}

	invalid := []byte(`{"not":"an array"}`)
	if _, err := ParseTopicKeySetBytes(
		invalid,
		"dev",
	); err == nil {
		t.Fatal("invalid configuration unexpectedly succeeded")
	}
	if !allBytesZero(invalid) {
		t.Fatal("invalid configuration source buffer was not cleared")
	}

	escaped := []byte(strings.Replace(
		fixture.topicConfig,
		`"key_base64url"`,
		`"key_base64\u0075rl"`,
		1,
	))
	if _, err := ParseTopicKeySetBytes(
		escaped,
		"dev",
	); err == nil {
		t.Fatal("escaped secret field unexpectedly succeeded")
	}
	if !allBytesZero(escaped) {
		t.Fatal("escaped configuration source buffer was not cleared")
	}
}

func TestTopicKeySetActivelyErasesPreviousSecretAtDeadline(
	t *testing.T,
) {
	epoch := uint32(700)
	retireAt := TopicEpochBoundary(epoch + 1).
		Add(60 * time.Second)
	realStart := time.Now()
	fakeStart := retireAt.Add(-25 * time.Millisecond)
	retiredKey := testTopicKey(1)
	survivorKey := testTopicKey(2)
	records := []topicKeyRecord{
		{
			descriptor: TopicKeyDescriptor{TopicKeyEpoch: epoch},
			key:        retiredKey,
		},
		{
			descriptor: TopicKeyDescriptor{TopicKeyEpoch: epoch + 1},
			key:        survivorKey,
		},
	}
	set := &TopicKeySet{
		environment: "dev",
		records:     records,
		clock: func() time.Time {
			return fakeStart.Add(time.Since(realStart))
		},
	}
	set.startRetirement(set.now())
	defer set.Close()

	deadline := time.After(time.Second)
	for {
		set.mu.RLock()
		remaining := len(set.records)
		set.mu.RUnlock()
		if remaining == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("previous secret was not actively erased")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if !allBytesZero(retiredKey) {
		t.Fatal("retired secret bytes remain in the original allocation")
	}
	if len(records[0].key) != 0 || len(records[1].key) != 0 {
		t.Fatal("old record headers retained key ownership")
	}
	set.mu.RLock()
	current := set.records[0]
	set.mu.RUnlock()
	if current.descriptor.TopicKeyEpoch != epoch+1 ||
		allBytesZero(current.key) ||
		len(current.key) == 0 ||
		&current.key[0] != &survivorKey[0] {
		t.Fatal("current secret ownership was not transferred exactly once")
	}
}

func TestTopicBindingCandidatesUseExactOverlapAndErasure(
	t *testing.T,
) {
	previousEpoch := uint32(700)
	currentEpoch := previousEpoch + 1
	boundary := TopicEpochBoundary(currentEpoch)
	previousKey := testTopicKey(1)
	currentKey := testTopicKey(2)
	set := &TopicKeySet{
		environment: "dev",
		records: []topicKeyRecord{
			{
				descriptor: TopicKeyDescriptor{
					TopicKeyEpoch: previousEpoch,
					NotBefore:     boundary.Add(-time.Hour),
					NotAfter:      boundary.Add(time.Hour),
				},
				key: previousKey,
			},
			{
				descriptor: TopicKeyDescriptor{
					TopicKeyEpoch: currentEpoch,
					NotBefore:     boundary.Add(-time.Hour),
					NotAfter:      boundary.Add(30 * 24 * time.Hour),
				},
				key: currentKey,
			},
		},
		clock:       func() time.Time { return boundary.Add(30 * time.Second) },
		steadyClock: time.Now,
	}
	defer set.Close()
	topic := make([]byte, 33)
	topic[32] = 9

	candidates, verdict := set.candidateTopicBindings(
		topic,
		boundary.Add(30*time.Second),
	)
	if !verdict.IsEligible() || len(candidates) != 2 {
		t.Fatalf("overlap candidates=%v verdict=%+v", candidates, verdict)
	}
	if candidates[0].TopicKeyEpoch != currentEpoch ||
		candidates[1].TopicKeyEpoch != previousEpoch {
		t.Fatalf("candidate ordering = %+v", candidates)
	}
	expectedCurrent, err := TopicBinding(currentKey, topic)
	if err != nil {
		t.Fatal(err)
	}
	expectedPrevious, err := TopicBinding(previousKey, topic)
	if err != nil {
		t.Fatal(err)
	}
	if !EqualBinding(candidates[0].TopicBinding[:], expectedCurrent) ||
		!EqualBinding(candidates[1].TopicBinding[:], expectedPrevious) {
		t.Fatal("candidate bindings did not match their epochs")
	}
	clear(expectedCurrent)
	clear(expectedPrevious)

	candidates, verdict = set.candidateTopicBindings(
		topic,
		boundary.Add(60*time.Second),
	)
	if !verdict.IsEligible() || len(candidates) != 1 ||
		candidates[0].TopicKeyEpoch != currentEpoch {
		t.Fatalf("deadline candidates=%v verdict=%+v", candidates, verdict)
	}
	if !allBytesZero(previousKey) {
		t.Fatal("previous key remained after candidate deadline erasure")
	}
	candidates, verdict = set.candidateTopicBindings(
		topic,
		boundary.Add(30*time.Second),
	)
	if !verdict.IsEligible() || len(candidates) != 1 ||
		candidates[0].TopicKeyEpoch != currentEpoch {
		t.Fatalf("post-erasure rollback candidates=%v verdict=%+v", candidates, verdict)
	}
}

func TestTopicKeySetSchedulesOneKeyAndRearmsSurvivor(t *testing.T) {
	epoch := uint32(700)
	withinEpoch := TopicEpochBoundary(epoch).Add(time.Hour)
	one := &TopicKeySet{
		environment: "dev",
		records: []topicKeyRecord{{
			descriptor: TopicKeyDescriptor{TopicKeyEpoch: epoch},
			key:        testTopicKey(1),
		}},
		clock: func() time.Time { return withinEpoch },
	}
	one.startRetirement(one.now())
	one.mu.RLock()
	oneRetireEpoch := one.retireEpoch
	oneRetireAt := one.retireAt
	oneTimer := one.retireTimer
	one.mu.RUnlock()
	if oneRetireEpoch != epoch ||
		!oneRetireAt.Equal(
			TopicEpochBoundary(epoch+1).Add(60*time.Second),
		) ||
		oneTimer == nil {
		t.Fatalf(
			"one-key retirement epoch=%d at=%s timer=%v",
			oneRetireEpoch,
			oneRetireAt,
			oneTimer != nil,
		)
	}
	one.Close()

	boundaryDeadline := TopicEpochBoundary(epoch + 1).
		Add(60 * time.Second)
	two := &TopicKeySet{
		environment: "dev",
		records: []topicKeyRecord{
			{
				descriptor: TopicKeyDescriptor{
					TopicKeyEpoch: epoch,
				},
				key: testTopicKey(1),
			},
			{
				descriptor: TopicKeyDescriptor{
					TopicKeyEpoch: epoch + 1,
				},
				key: testTopicKey(2),
			},
		},
		clock: func() time.Time { return boundaryDeadline },
	}
	two.startRetirement(two.now())
	defer two.Close()
	two.mu.RLock()
	remaining := len(two.records)
	var survivorEpoch uint32
	if remaining > 0 {
		survivorEpoch = two.records[0].descriptor.TopicKeyEpoch
	}
	nextRetireEpoch := two.retireEpoch
	nextRetireAt := two.retireAt
	nextTimer := two.retireTimer
	two.mu.RUnlock()
	if remaining != 1 ||
		survivorEpoch != epoch+1 ||
		nextRetireEpoch != epoch+1 ||
		!nextRetireAt.Equal(
			TopicEpochBoundary(epoch+2).Add(60*time.Second),
		) ||
		nextTimer == nil {
		t.Fatalf(
			"survivor remaining=%d epoch=%d retire_epoch=%d at=%s timer=%v",
			remaining,
			survivorEpoch,
			nextRetireEpoch,
			nextRetireAt,
			nextTimer != nil,
		)
	}
}

func TestTopicKeySetForwardClockCorrectionCannotRetainSecret(
	t *testing.T,
) {
	epoch := uint32(700)
	var clockNanos atomic.Int64
	clockNanos.Store(
		TopicEpochBoundary(epoch).Add(time.Hour).UnixNano(),
	)
	secret := testTopicKey(9)
	records := []topicKeyRecord{{
		descriptor: TopicKeyDescriptor{TopicKeyEpoch: epoch},
		key:        secret,
	}}
	set := &TopicKeySet{
		environment: "dev",
		records:     records,
		clock: func() time.Time {
			return time.Unix(0, clockNanos.Load()).UTC()
		},
		recheck: 10 * time.Millisecond,
	}
	set.startRetirement(set.now())
	defer set.Close()

	clockNanos.Store(
		TopicEpochBoundary(epoch + 1).
			Add(60 * time.Second).
			UnixNano(),
	)
	deadline := time.After(time.Second)
	for {
		set.mu.RLock()
		remaining := len(set.records)
		set.mu.RUnlock()
		if remaining == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("forward clock correction retained the expired secret")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if !allBytesZero(secret) {
		t.Fatal("forward-corrected secret bytes were not erased")
	}
}

func TestTopicKeySetFrozenClockCannotRetainSecretPastHardDeadline(
	t *testing.T,
) {
	epoch := uint32(700)
	retireAt := TopicEpochBoundary(epoch + 1).
		Add(60 * time.Second)
	frozenNow := retireAt.Add(-35 * time.Millisecond)
	secret := testTopicKey(10)
	set := &TopicKeySet{
		environment: "dev",
		records: []topicKeyRecord{{
			descriptor: TopicKeyDescriptor{TopicKeyEpoch: epoch},
			key:        secret,
		}},
		clock: func() time.Time { return frozenNow },
	}
	set.startRetirement(set.now())
	defer set.Close()

	awaitTopicKeyCount(t, set, 0)
	if !allBytesZero(secret) {
		t.Fatal("frozen-clock secret bytes were not erased")
	}
	if !set.now().Before(retireAt) {
		t.Fatal("test wall clock unexpectedly reached retirement deadline")
	}
}

func TestTopicKeySetBackwardClockCannotExtendHardDeadline(
	t *testing.T,
) {
	epoch := uint32(700)
	retireAt := TopicEpochBoundary(epoch + 1).
		Add(60 * time.Second)
	var clockNanos atomic.Int64
	clockNanos.Store(retireAt.Add(-40 * time.Millisecond).UnixNano())
	secret := testTopicKey(11)
	set := &TopicKeySet{
		environment: "dev",
		records: []topicKeyRecord{{
			descriptor: TopicKeyDescriptor{TopicKeyEpoch: epoch},
			key:        secret,
		}},
		clock: func() time.Time {
			return time.Unix(0, clockNanos.Load()).UTC()
		},
	}
	set.startRetirement(set.now())
	defer set.Close()

	clockNanos.Store(retireAt.Add(-24 * time.Hour).UnixNano())
	awaitTopicKeyCount(t, set, 0)
	if !allBytesZero(secret) {
		t.Fatal("backward-clock secret bytes were not erased")
	}
	if !set.now().Before(retireAt) {
		t.Fatal("test wall clock unexpectedly reached retirement deadline")
	}
}

func awaitTopicKeyCount(
	t *testing.T,
	set *TopicKeySet,
	want int,
) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		set.mu.RLock()
		remaining := len(set.records)
		set.mu.RUnlock()
		if remaining == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf(
				"topic key count = %d, want %d before hard deadline",
				remaining,
				want,
			)
		case <-ticker.C:
		}
	}
}

func TestTopicKeyReconcileAtErasureBoundary(t *testing.T) {
	fixture := managerBoundaryFixtureFromCorpus(t)
	descriptors, ok := parseCommitmentKeys(
		fixture.keyset["commitment_keys"],
	)
	if !ok {
		t.Fatal("fixture commitment descriptors failed to parse")
	}
	var epochs []uint32
	for _, descriptor := range descriptors {
		if descriptor.Purpose == "TOPIC" &&
			descriptor.TopicKeyEpoch != nil {
			epochs = append(epochs, *descriptor.TopicKeyEpoch)
		}
	}
	if len(epochs) != 2 {
		t.Fatalf("topic epochs = %v", epochs)
	}
	if epochs[1] < epochs[0] {
		epochs[0], epochs[1] = epochs[1], epochs[0]
	}
	deadline := TopicEpochBoundary(epochs[1]).
		Add(60 * time.Second)

	currentOnly := cloneKeysetWithoutTopicEpoch(
		t,
		fixture.keyset,
		epochs[0],
	)
	set := topicSetWithClock(
		t,
		fixture.topicConfig,
		deadline.Add(-time.Second),
	)
	assertVerdict(
		t,
		set.Reconcile(currentOnly, deadline),
		Eligible(),
	)
	set.Close()

	set = topicSetWithClock(
		t,
		fixture.topicConfig,
		deadline.Add(-time.Second),
	)
	assertVerdict(
		t,
		set.Reconcile(fixture.keyset, deadline),
		Eligible(),
	)
	set.Close()

	set = topicSetWithClock(
		t,
		fixture.topicConfig,
		deadline.Add(-time.Second),
	)
	removeLocalTopicEpoch(set, epochs[1])
	verdict := set.Reconcile(fixture.keyset, deadline)
	if verdict.IsEligible() {
		t.Fatal("reconciliation accepted a missing current secret")
	}
	set.Close()

	mutatedPrevious := cloneKeyset(t, fixture.keyset)
	items := mutatedPrevious["commitment_keys"].([]any)
	var currentKeyID string
	for _, item := range items {
		object := item.(map[string]any)
		value, candidate := positiveInteger(object["topic_key_epoch"])
		if objectString(object, "purpose") == "TOPIC" &&
			candidate.IsEligible() &&
			value == uint64(epochs[1]) {
			currentKeyID = objectString(object, "key_id")
		}
	}
	if currentKeyID == "" {
		t.Fatal("current TOPIC descriptor missing")
	}
	for _, item := range items {
		object := item.(map[string]any)
		value, candidate := positiveInteger(object["topic_key_epoch"])
		if objectString(object, "purpose") == "TOPIC" &&
			candidate.IsEligible() &&
			value == uint64(epochs[0]) {
			object["key_id"] = currentKeyID
		}
	}
	set = topicSetWithClock(
		t,
		fixture.topicConfig,
		deadline.Add(-time.Second),
	)
	if verdict := set.Reconcile(
		mutatedPrevious,
		deadline,
	); verdict.IsEligible() {
		t.Fatal("changed retired descriptor metadata was accepted")
	}
	set.Close()
}

func topicSetWithClock(
	t *testing.T,
	raw string,
	now time.Time,
) *TopicKeySet {
	t.Helper()
	set, err := parseTopicKeySetBytes(
		[]byte(raw),
		"dev",
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func cloneKeysetWithoutTopicEpoch(
	t *testing.T,
	keyset map[string]any,
	epoch uint32,
) map[string]any {
	t.Helper()
	cloned := cloneKeyset(t, keyset)
	items, ok := cloned["commitment_keys"].([]any)
	if !ok {
		t.Fatal("cloned commitment_keys is not an array")
	}
	filtered := make([]any, 0, len(items)-1)
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			t.Fatal("cloned descriptor is not an object")
		}
		value, verdict := positiveInteger(object["topic_key_epoch"])
		if objectString(object, "purpose") == "TOPIC" &&
			verdict.IsEligible() &&
			value == uint64(epoch) {
			continue
		}
		filtered = append(filtered, item)
	}
	cloned["commitment_keys"] = filtered
	return cloned
}

func cloneKeyset(
	t *testing.T,
	keyset map[string]any,
) map[string]any {
	t.Helper()
	raw, err := Canonicalize(keyset)
	if err != nil {
		t.Fatal(err)
	}
	value, err := ParseStrictJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	cloned, ok := value.(map[string]any)
	if !ok {
		t.Fatal("cloned keyset is not an object")
	}
	return cloned
}

func removeLocalTopicEpoch(set *TopicKeySet, epoch uint32) {
	set.mu.Lock()
	defer set.mu.Unlock()
	if set.retireTimer != nil {
		set.retireTimer.Stop()
		set.retireTimer = nil
	}
	kept := make([]topicKeyRecord, 0, len(set.records)-1)
	for index := range set.records {
		record := &set.records[index]
		if record.descriptor.TopicKeyEpoch != epoch {
			kept = append(kept, *record)
			record.key = nil
			continue
		}
		clear(record.key)
		record.key = nil
	}
	clear(set.records)
	set.records = kept
	set.retireEpoch = 0
	set.retireAt = time.Time{}
	set.retired = TopicKeyDescriptor{}
	set.hasRetired = false
}

func allBytesZero(value []byte) bool {
	return bytes.Equal(value, make([]byte, len(value)))
}

func testTopicKey(first byte) []byte {
	key := make([]byte, 32)
	key[0] = first
	return key
}
