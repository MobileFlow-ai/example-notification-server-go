package authority

import (
	"crypto/sha256"
	"encoding/binary"
)

const expectedConversationCommitmentDomain = "Hytch expected conversation commitment v1\x00"

// ExpectedConversationCommitment commits the authority issuer to one canonical
// conversation identifier without disclosing that identifier to the bridge.
// The trusted issuer must validate the publisher/conversation association
// before signing a capability or Welcome authorization; hashing an identifier
// echoed by an untrusted caller is not authority.
//
// The preimage is the exact ASCII domain followed by environment,
// installationID, accountIncarnationID, and expectedConversationID, in that
// order. Each value is encoded as an unsigned 64-bit big-endian byte length
// followed by its exact bounded-ASCII bytes.
func ExpectedConversationCommitment(
	environment string,
	installationID string,
	accountIncarnationID string,
	expectedConversationID string,
) ([sha256.Size]byte, error) {
	if !ValidEnvironment(environment) ||
		!ValidInstallationID(installationID) ||
		!ValidAccountIncarnationID(accountIncarnationID) ||
		!validASCIIField(expectedConversationID, 1, maxCapabilityFieldBytes) {
		return [sha256.Size]byte{}, ErrCapabilityInvalid
	}
	return deriveExpectedConversationCommitment(
		environment,
		installationID,
		accountIncarnationID,
		expectedConversationID,
	), nil
}

func deriveExpectedConversationCommitment(
	environment string,
	installationID string,
	accountIncarnationID string,
	expectedConversationID string,
) [sha256.Size]byte {
	values := []string{
		environment,
		installationID,
		accountIncarnationID,
		expectedConversationID,
	}
	size := len(expectedConversationCommitmentDomain)
	for _, value := range values {
		size += 8 + len(value)
	}
	preimage := make([]byte, 0, size)
	preimage = append(preimage, expectedConversationCommitmentDomain...)
	for _, value := range values {
		preimage = binary.BigEndian.AppendUint64(preimage, uint64(len(value)))
		preimage = append(preimage, value...)
	}
	commitment := sha256.Sum256(preimage)
	for index := range preimage {
		preimage[index] = 0
	}
	return commitment
}
