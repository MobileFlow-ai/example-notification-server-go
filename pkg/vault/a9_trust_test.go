package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

type a9TrustLeaseStub struct{}

func (*a9TrustLeaseStub) CandidateTopicBindings(
	context.Context,
	[]byte,
	time.Time,
) ([]a9trust.TopicBindingCandidate, a9trust.Verdict) {
	return nil, a9trust.Verdict{}
}

func (*a9TrustLeaseStub) TopicBindingForEpoch(
	context.Context,
	[]byte,
	uint32,
	time.Time,
	time.Time,
	bool,
) ([]byte, a9trust.Verdict) {
	return nil, a9trust.Verdict{}
}

func (*a9TrustLeaseStub) Close() {}

type a9TrustStub struct {
	mu               sync.Mutex
	ctx              context.Context
	now              time.Time
	expectedSequence uint64
	expectedHash     [32]byte
	lease            a9trust.TopicBindingLease
	err              error
}

func (stub *a9TrustStub) AcquireCurrentTopicBindingLease(
	ctx context.Context,
	now time.Time,
) (a9trust.TopicBindingLease, uint64, [32]byte, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.ctx = ctx
	stub.now = now
	return stub.lease, stub.expectedSequence, stub.expectedHash, stub.err
}

func (stub *a9TrustStub) AcquireTopicBindingLease(
	ctx context.Context,
	now time.Time,
	expectedSequence uint64,
	expectedHash [32]byte,
) (a9trust.TopicBindingLease, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.ctx = ctx
	stub.now = now
	stub.expectedSequence = expectedSequence
	stub.expectedHash = expectedHash
	return stub.lease, stub.err
}

func TestA9TrustHandleIsSingleAssignmentAndFailsClosedUnbound(
	t *testing.T,
) {
	handle := &A9TrustHandle{}
	if lease, sequence, hash, err :=
		handle.AcquireCurrentTopicBindingLease(
			t.Context(),
			time.Now(),
		); lease != nil || sequence != 0 ||
		hash != [32]byte{} || err != ErrStoreUnavailable {
		t.Fatalf(
			"unbound current result = (%v, %d, %x, %v)",
			lease,
			sequence,
			hash,
			err,
		)
	}
	if lease, err := handle.AcquireTopicBindingLease(
		t.Context(),
		time.Now(),
		1,
		[32]byte{1},
	); lease != nil || err != ErrStoreUnavailable {
		t.Fatalf("unbound result = (%v, %v)", lease, err)
	}
	require.ErrorIs(t, handle.Bind(nil), ErrStoreUnavailable)
	var typedNil *a9TrustStub
	require.ErrorIs(t, handle.Bind(typedNil), ErrStoreUnavailable)

	expectedLease := &a9TrustLeaseStub{}
	first := &a9TrustStub{lease: expectedLease}
	require.NoError(t, handle.Bind(first))
	require.ErrorIs(
		t,
		handle.Bind(&a9TrustStub{}),
		ErrStoreUnavailable,
	)

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	expectedHash := [32]byte{0x41}
	lease, err := handle.AcquireTopicBindingLease(
		t.Context(),
		now,
		7,
		expectedHash,
	)
	require.NoError(t, err)
	require.Same(t, expectedLease, lease)
	first.mu.Lock()
	defer first.mu.Unlock()
	require.NotNil(t, first.ctx)
	require.Equal(t, now, first.now)
	require.Equal(t, uint64(7), first.expectedSequence)
	require.Equal(t, expectedHash, first.expectedHash)
	first.mu.Unlock()
	currentLease, sequence, hash, err :=
		handle.AcquireCurrentTopicBindingLease(t.Context(), now)
	require.NoError(t, err)
	require.Same(t, expectedLease, currentLease)
	require.Equal(t, uint64(7), sequence)
	require.Equal(t, expectedHash, hash)
	first.mu.Lock()
}

func TestA9TrustHandleConcurrentBindHasOneWinner(t *testing.T) {
	handle := &A9TrustHandle{}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- handle.Bind(&a9TrustStub{})
		}()
	}
	wait.Wait()
	close(results)

	var accepted int
	for err := range results {
		if err == nil {
			accepted++
			continue
		}
		require.ErrorIs(t, err, ErrStoreUnavailable)
	}
	require.Equal(t, 1, accepted)
}

func TestNewStoreRequiresExactA9EnablementPair(t *testing.T) {
	keyring, err := NewKeyring(1, map[uint32][]byte{
		1: bytes.Repeat([]byte{0x31}, 32),
	})
	require.NoError(t, err)
	lookup, err := NewLookupKey(bytes.Repeat([]byte{0x42}, 32))
	require.NoError(t, err)
	options := StoreOptions{
		Environment: "dev",
		Encryption:  keyring,
		Lookup:      lookup,
		AuthorityKeys: map[string]ed25519.PublicKey{
			"key-1": bytes.Repeat([]byte{0x53}, ed25519.PublicKeySize),
		},
	}
	handle := &A9TrustHandle{}

	enabledWithoutHandle := options
	enabledWithoutHandle.A9Enabled = true
	_, err = NewStore(&sql.DB{}, enabledWithoutHandle)
	require.ErrorIs(t, err, ErrStoreUnavailable)

	disabledWithHandle := options
	disabledWithHandle.A9Trust = handle
	_, err = NewStore(&sql.DB{}, disabledWithHandle)
	require.ErrorIs(t, err, ErrStoreUnavailable)

	enabled := options
	enabled.A9Enabled = true
	enabled.A9Trust = handle
	store, err := NewStore(&sql.DB{}, enabled)
	require.NoError(t, err)
	require.True(t, store.a9Enabled)
	require.Same(t, handle, store.a9Trust)
	_, err = store.Refresh(t.Context(), RefreshRequest{})
	require.ErrorIs(t, err, ErrStoreUnavailable)

	legacy, err := NewStore(&sql.DB{}, options)
	require.NoError(t, err)
	require.False(t, legacy.a9Enabled)
	require.Nil(t, legacy.a9Trust)
	_, err = legacy.Refresh(t.Context(), RefreshRequest{})
	require.ErrorIs(t, err, ErrRefreshInvalid)
}
