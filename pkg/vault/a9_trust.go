package vault

import (
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

// A9Trust is the narrow trust-manager surface required by the vault. Route
// discovery obtains an exact durable receipt with its lease; enqueue and
// pre-egress must reacquire against that same receipt.
type A9Trust interface {
	AcquireCurrentTopicBindingLease(
		context.Context,
		time.Time,
	) (a9trust.TopicBindingLease, uint64, [32]byte, error)
	AcquireTopicBindingLease(
		context.Context,
		time.Time,
		uint64,
		[32]byte,
	) (a9trust.TopicBindingLease, error)
}

// A9TrustHandle breaks the Store-to-trust-manager construction cycle without
// permitting dependency replacement. Its zero value is unbound and fails
// closed; one successful Bind is permanent.
type A9TrustHandle struct {
	mu    sync.RWMutex
	trust A9Trust
}

func (handle *A9TrustHandle) Bind(trust A9Trust) error {
	if handle == nil || nilA9Trust(trust) {
		return ErrStoreUnavailable
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.trust != nil {
		return ErrStoreUnavailable
	}
	handle.trust = trust
	return nil
}

func nilA9Trust(trust A9Trust) bool {
	if trust == nil {
		return true
	}
	value := reflect.ValueOf(trust)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (handle *A9TrustHandle) AcquireCurrentTopicBindingLease(
	ctx context.Context,
	now time.Time,
) (a9trust.TopicBindingLease, uint64, [32]byte, error) {
	if handle == nil {
		return nil, 0, [32]byte{}, ErrStoreUnavailable
	}
	handle.mu.RLock()
	trust := handle.trust
	handle.mu.RUnlock()
	if trust == nil {
		return nil, 0, [32]byte{}, ErrStoreUnavailable
	}
	return trust.AcquireCurrentTopicBindingLease(ctx, now)
}

func (handle *A9TrustHandle) AcquireTopicBindingLease(
	ctx context.Context,
	now time.Time,
	expectedSequence uint64,
	expectedHash [32]byte,
) (a9trust.TopicBindingLease, error) {
	if handle == nil {
		return nil, ErrStoreUnavailable
	}
	handle.mu.RLock()
	trust := handle.trust
	handle.mu.RUnlock()
	if trust == nil {
		return nil, ErrStoreUnavailable
	}
	return trust.AcquireTopicBindingLease(
		ctx,
		now,
		expectedSequence,
		expectedHash,
	)
}
