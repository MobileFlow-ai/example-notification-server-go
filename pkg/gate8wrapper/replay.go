package gate8wrapper

import (
	"reflect"
	"sync"
)

// ReplayProtector atomically compares and advances authenticated replay state.
// Implementations used for delivery must durably commit the new high-water mark
// before returning nil. A persistence failure must return ErrReplayState (or an
// error wrapping it) and leave delivery closed.
//
// CompareAndAdvanceAuthenticated is called only after route and AEAD
// authentication succeed.
type ReplayProtector interface {
	CompareAndAdvanceAuthenticated(Header) error
}

func replayProtectorUnavailable(protector ReplayProtector) bool {
	if protector == nil {
		return true
	}
	value := reflect.ValueOf(protector)
	switch value.Kind() {
	case reflect.Chan,
		reflect.Func,
		reflect.Interface,
		reflect.Map,
		reflect.Ptr,
		reflect.Slice,
		reflect.UnsafePointer:
		return value.IsNil()
	default:
		return false
	}
}

// ReplayState is the complete fixed replay scope and high-water mark. It
// contains no raw topic, installation, token, or payload material.
type ReplayState struct {
	Environment     Environment
	AliasDay        string
	RouteAlias      RouteAlias
	RouteKeyEpoch   uint32
	NoncePrefix     [NoncePrefixSize]byte
	HighestSequence uint64
}

// ReplayWindow is a monotonic repeated/lower-sequence rejection helper. One
// window is scoped to exactly one environment, alias day, route alias,
// route-key epoch, and nonce prefix. A scope change fails closed instead of
// silently resetting the highest sequence.
//
// Gate 8 requires protected replay state but does not define persistence. This
// in-memory helper deliberately does not claim crash safety. Delivery
// integrations must inject a durable ReplayProtector; Snapshot and
// RestoreReplayWindow exist for bounded state transfer and tests.
type ReplayWindow struct {
	mu sync.Mutex

	initialized bool
	environment Environment
	aliasDay    string
	routeAlias  RouteAlias
	routeEpoch  uint32
	noncePrefix [NoncePrefixSize]byte
	highest     uint64
}

// RestoreReplayWindow validates and restores a complete replay high-water
// mark. Persisting a later Snapshot after Open is not atomic with delivery and
// therefore is not a substitute for a durable ReplayProtector.
func RestoreReplayWindow(state ReplayState) (*ReplayWindow, error) {
	header := Header{
		SchemaVersion:    SchemaVersion,
		Environment:      state.Environment,
		AliasDay:         state.AliasDay,
		RouteAlias:       state.RouteAlias,
		RouteKeyEpoch:    state.RouteKeyEpoch,
		NoncePrefix:      state.NoncePrefix,
		DeliverySequence: state.HighestSequence,
	}
	if err := header.validate(); err != nil {
		return nil, ErrReplayState
	}
	return &ReplayWindow{
		initialized: true,
		environment: state.Environment,
		aliasDay:    state.AliasDay,
		routeAlias:  state.RouteAlias,
		routeEpoch:  state.RouteKeyEpoch,
		noncePrefix: state.NoncePrefix,
		highest:     state.HighestSequence,
	}, nil
}

// Snapshot returns the complete in-memory state when initialized.
func (window *ReplayWindow) Snapshot() (ReplayState, bool) {
	if window == nil {
		return ReplayState{}, false
	}
	window.mu.Lock()
	defer window.mu.Unlock()

	if !window.initialized {
		return ReplayState{}, false
	}
	return ReplayState{
		Environment:     window.environment,
		AliasDay:        window.aliasDay,
		RouteAlias:      window.routeAlias,
		RouteKeyEpoch:   window.routeEpoch,
		NoncePrefix:     window.noncePrefix,
		HighestSequence: window.highest,
	}, true
}

// CompareAndAdvanceAuthenticated implements ReplayProtector for transient
// in-memory use.
func (window *ReplayWindow) CompareAndAdvanceAuthenticated(
	header Header,
) error {
	if window == nil {
		return ErrReplayState
	}
	window.mu.Lock()
	defer window.mu.Unlock()

	if !window.initialized {
		window.initialized = true
		window.environment = header.Environment
		window.aliasDay = header.AliasDay
		window.routeAlias = header.RouteAlias
		window.routeEpoch = header.RouteKeyEpoch
		window.noncePrefix = header.NoncePrefix
		window.highest = header.DeliverySequence
		return nil
	}
	if window.environment != header.Environment ||
		window.aliasDay != header.AliasDay ||
		window.routeAlias != header.RouteAlias ||
		window.routeEpoch != header.RouteKeyEpoch ||
		window.noncePrefix != header.NoncePrefix {
		return ErrReplayState
	}
	if header.DeliverySequence <= window.highest {
		return ErrReplay
	}
	window.highest = header.DeliverySequence
	return nil
}
