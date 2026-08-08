package authority

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExpectedConversationCommitmentWireVector(t *testing.T) {
	commitment, err := ExpectedConversationCommitment(
		"dev",
		testInstallationID,
		testAccountIncarnationID,
		"conversation",
	)
	require.NoError(t, err)
	require.Equal(
		t,
		"ea7a8a3f8a487fd4117713e405a7063ef08f3577e33c74ff8e00455eea32dc00",
		hex.EncodeToString(commitment[:]),
	)
}

func TestExpectedConversationCommitmentRejectsNoncanonicalFields(t *testing.T) {
	_, err := ExpectedConversationCommitment(
		"dev",
		testInstallationID,
		testAccountIncarnationID,
		"",
	)
	require.ErrorIs(t, err, ErrCapabilityInvalid)

	_, err = ExpectedConversationCommitment(
		"dev",
		testInstallationID,
		testAccountIncarnationID,
		"conversation\u2028identifier",
	)
	require.ErrorIs(t, err, ErrCapabilityInvalid)
}
