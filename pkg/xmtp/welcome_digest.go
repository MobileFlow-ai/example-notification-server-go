package xmtp

import (
	"crypto/sha256"
	"errors"

	"github.com/xmtp/xmtpd/pkg/topic"
)

const (
	v3WelcomeDigestDomain = "Hytch exact Welcome outer envelope v3\x00"
	v4WelcomeDigestDomain = "Hytch exact Welcome outer envelope v4\x00"
)

var errWelcomeDigestInvalid = errors.New("welcome digest input invalid")

// V3WelcomeEnvelopeDigest binds the parsed binary topic and the exact encrypted
// V3 envelope message. Timestamp metadata is intentionally excluded because it
// is not part of the encrypted outer payload authorized by the publisher.
func V3WelcomeEnvelopeDigest(
	targetTopic *topic.Topic,
	message []byte,
) ([sha256.Size]byte, error) {
	return welcomeEnvelopeDigest(v3WelcomeDigestDomain, targetTopic, message)
}

// V4WelcomeEnvelopeDigest binds the parsed binary topic and the raw serialized
// OriginatorEnvelope bytes delivered by the stream.
func V4WelcomeEnvelopeDigest(
	targetTopic *topic.Topic,
	rawOriginatorEnvelope []byte,
) ([sha256.Size]byte, error) {
	return welcomeEnvelopeDigest(
		v4WelcomeDigestDomain,
		targetTopic,
		rawOriginatorEnvelope,
	)
}

func welcomeEnvelopeDigest(
	domain string,
	targetTopic *topic.Topic,
	outerEnvelope []byte,
) ([sha256.Size]byte, error) {
	if targetTopic == nil ||
		targetTopic.Kind() != topic.TopicKindWelcomeMessagesV1 ||
		len(outerEnvelope) == 0 {
		return [sha256.Size]byte{}, errWelcomeDigestInvalid
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write(targetTopic.Bytes())
	_, _ = digest.Write(outerEnvelope)
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}
