package authority

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExpectedConversationCommitmentWireVector(t *testing.T) {
	commitment, err := ExpectedConversationCommitment(
		"development",
		"installation",
		"incarnation",
		"conversation",
	)
	require.NoError(t, err)
	require.Equal(
		t,
		"5c98d79b0069383245a2fe22c161c922c244d3a9557340ff8ce2c88e542287bc",
		hex.EncodeToString(commitment[:]),
	)
}

func TestExpectedConversationCommitmentRejectsNoncanonicalFields(t *testing.T) {
	_, err := ExpectedConversationCommitment(
		"development",
		"installation",
		"incarnation",
		"",
	)
	require.ErrorIs(t, err, ErrCapabilityInvalid)

	_, err = ExpectedConversationCommitment(
		"development",
		"installation",
		"incarnation",
		"conversation\u2028identifier",
	)
	require.ErrorIs(t, err, ErrCapabilityInvalid)
}
