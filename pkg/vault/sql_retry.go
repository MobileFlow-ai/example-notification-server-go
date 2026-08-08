package vault

import "errors"

type sqlStateError interface {
	SQLState() string
}

func isSerializationFailure(err error) bool {
	var state sqlStateError
	if !errors.As(err, &state) {
		return false
	}
	switch state.SQLState() {
	case "40001", "40P01":
		return true
	default:
		return false
	}
}

// storeDatabaseError preserves only retryable transaction conflicts for the
// private retry loop. Every other database error is collapsed to the fixed
// public failure so driver details cannot escape the vault.
func storeDatabaseError(err error) error {
	if isSerializationFailure(err) {
		return err
	}
	return ErrStoreUnavailable
}
