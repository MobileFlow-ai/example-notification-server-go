package authority

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// This fixture is copied byte-for-byte from modern-api PR #980's
// docs/xmtp-gate6-vectors/gate6-expected-conversation-commitments.json.
// Keep the source tuple separate from runtime identifier validation: it is a
// reproducible algorithm vector, not a live authority identifier.
//
//go:embed testdata/gate6-expected-conversation-commitments.json
var ratifiedGate6VectorPackage []byte

type ratifiedGate6VectorPackageJSON struct {
	NormativeVectors []struct {
		CommitmentHex string `json:"commitment_hex"`
		Environment   string `json:"environment"`
	} `json:"normative_vectors"`
	SourceTuple struct {
		AccountIncarnationID   string `json:"account_incarnation_id"`
		ExpectedConversationID string `json:"expected_conversation_id"`
		InstallationID         string `json:"installation_id"`
	} `json:"source_tuple"`
}

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

func TestExpectedConversationCommitmentRatifiedGate6Vectors(t *testing.T) {
	var packageJSON ratifiedGate6VectorPackageJSON
	require.NoError(t, json.Unmarshal(ratifiedGate6VectorPackage, &packageJSON))
	require.Len(t, packageJSON.NormativeVectors, 2)

	wantByEnvironment := map[string]string{
		"dev":        "5cb3201c89d14ca817a25d9924ff3c041e2d634b45a97def637e103cefe3fe48",
		"production": "3ee7370330e06231ccf4cabe3472b77d8d68edffd669566e668720d628e1f495",
	}
	for _, vector := range packageJSON.NormativeVectors {
		want, ok := wantByEnvironment[vector.Environment]
		require.Truef(t, ok, "unexpected Gate 6 environment %q", vector.Environment)
		require.Equal(t, want, vector.CommitmentHex)

		commitment := deriveExpectedConversationCommitment(
			vector.Environment,
			packageJSON.SourceTuple.InstallationID,
			packageJSON.SourceTuple.AccountIncarnationID,
			packageJSON.SourceTuple.ExpectedConversationID,
		)
		require.Equal(t, vector.CommitmentHex, hex.EncodeToString(commitment[:]))
	}
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
