package vault

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/xmtp/example-notification-server-go/pkg/authority"
)

func controlDigest(
	control authority.PolicyControlV1,
) ([sha256.Size]byte, error) {
	signingBytes, err := control.SigningBytes()
	if err != nil {
		return [sha256.Size]byte{}, ErrRefreshInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(control.Signature)
	if err != nil {
		return [sha256.Size]byte{}, ErrRefreshInvalid
	}
	digest := sha256.New()
	_, _ = digest.Write(signingBytes)
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(signature)
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}
