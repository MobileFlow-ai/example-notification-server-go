package vault

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type testSQLStateError string

func (value testSQLStateError) Error() string    { return "database operation failed" }
func (value testSQLStateError) SQLState() string { return string(value) }

func TestSerializationFailuresAreTheOnlyRetriedDatabaseErrors(t *testing.T) {
	require.True(t, isSerializationFailure(testSQLStateError("40001")))
	require.True(t, isSerializationFailure(testSQLStateError("40P01")))
	require.False(t, isSerializationFailure(testSQLStateError("23505")))
	require.False(t, isSerializationFailure(errors.New("database operation failed")))
}

func TestStoreDatabaseErrorPreservesOnlyRetryableConflicts(t *testing.T) {
	require.NoError(t, storeDatabaseError(nil))
	retryable := testSQLStateError("40001")
	require.ErrorIs(t, storeDatabaseError(retryable), retryable)
	require.ErrorIs(
		t,
		storeDatabaseError(testSQLStateError("23505")),
		ErrStoreUnavailable,
	)
	require.ErrorIs(
		t,
		storeDatabaseError(errors.New("database operation failed")),
		ErrStoreUnavailable,
	)
}
