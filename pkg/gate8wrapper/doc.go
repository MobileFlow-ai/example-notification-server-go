// Package gate8wrapper implements the cryptographic core of the Gate 8 APNs
// route wrapper.
//
// It deliberately has no database, APNs, logging, or API dependencies. Callers
// are responsible for allocating nonce prefixes and sequences atomically,
// persisting replay state, enforcing capability freshness, and accounting for
// the complete APNs JSON payload when supplying a size-fit callback.
//
// The Gate 8 specification fixes the derivation inputs and required fields but
// does not fix JSON field names, binary-to-text encoding, or the inner
// length-prefixed framing. This package makes those choices explicit and pins
// them with vectors so the iOS implementation can either adopt them or replace
// them through a coordinated contract version before integration.
package gate8wrapper
