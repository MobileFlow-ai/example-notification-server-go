package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	rosterDomain = "Hytch A9 bridge roster v1\x00"
	topicDomain  = "Hytch A9 bridge topic v1\x00"
	tupleDomain  = "Hytch A9 push tuple v1\x00"

	topicPeriodSeconds int64 = 30 * 24 * 60 * 60
)

var (
	canonicalUUIDPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	lowerHex64Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	lowerHexDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// DecodeBase64URL decodes an unpadded, canonical Base64url value and requires
// the exact decoded byte length.
func DecodeBase64URL(value string, expectedLength int) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") {
		return nil, errors.New("non-canonical Base64url")
	}
	for i := 0; i < len(value); i++ {
		if !isBase64URLByte(value[i]) {
			return nil, errors.New("non-canonical Base64url")
		}
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != expectedLength {
		return nil, errors.New("non-canonical Base64url")
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("non-canonical Base64url")
	}
	return decoded, nil
}

func EncodeBase64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func SHA256LowerHex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func Ed25519KeyID(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", fmt.Errorf("Ed25519 public key length is %d", len(publicKey))
	}
	return "ed25519-sha256:" + SHA256LowerHex(publicKey), nil
}

func HMACKeyID(secret []byte) (string, error) {
	if len(secret) != 32 {
		return "", fmt.Errorf("HMAC key length is %d", len(secret))
	}
	return "hmac-sha256:" + SHA256LowerHex(secret), nil
}

// ResolvedTopic is the pinned xmtpd GroupMessagesV1 representation.
type ResolvedTopic struct {
	GroupID []byte
	Bytes   []byte
}

func ResolveTopic(transportConversationID string) (ResolvedTopic, error) {
	if !lowerHex64Pattern.MatchString(transportConversationID) {
		return ResolvedTopic{}, errors.New("transport ID is not 64 lowercase hex characters")
	}
	groupID, err := hex.DecodeString(transportConversationID)
	if err != nil || len(groupID) != 32 {
		return ResolvedTopic{}, errors.New("transport ID does not decode to a 32-byte group ID")
	}
	topic := make([]byte, 33)
	copy(topic[1:], groupID)
	return ResolvedTopic{GroupID: groupID, Bytes: topic}, nil
}

// VerifyResolvedTopic enforces the exact resolver match.  A non-zero kind byte
// gets the distinct Welcome-closed result required by the contract.
func VerifyResolvedTopic(transportConversationID, topicBase64URL string) Verdict {
	resolved, err := ResolveTopic(transportConversationID)
	if err != nil {
		return Invalid("TOPIC_RESOLVER")
	}
	topic, err := DecodeBase64URL(topicBase64URL, 33)
	if err != nil {
		return Invalid("TOPIC_RESOLVER")
	}
	if topic[0] != 0 {
		return Invalid("WELCOME_CLOSED")
	}
	if subtle.ConstantTimeCompare(topic, resolved.Bytes) != 1 {
		return Invalid("TOPIC_RESOLVER")
	}
	return Eligible()
}

func isBase64URLByte(value byte) bool {
	return value >= 'A' && value <= 'Z' ||
		value >= 'a' && value <= 'z' ||
		value >= '0' && value <= '9' ||
		value == '-' ||
		value == '_'
}

func RosterCommitment(key []byte, environment string, rosterDigest []byte) ([]byte, error) {
	if len(key) != 32 || len(rosterDigest) != 32 || len(environment) > 255 || !isASCII(environment) {
		return nil, errors.New("invalid roster commitment input")
	}
	message := make([]byte, 0, len(rosterDomain)+1+len(environment)+32)
	message = append(message, rosterDomain...)
	message = append(message, byte(len(environment)))
	message = append(message, environment...)
	message = append(message, rosterDigest...)
	return hmacSum(key, message), nil
}

func TopicBinding(key, topic []byte) ([]byte, error) {
	if len(key) != 32 || len(topic) != 33 || topic[0] != 0 {
		return nil, errors.New("invalid topic commitment input")
	}
	message := make([]byte, 0, len(topicDomain)+4+len(topic))
	message = append(message, topicDomain...)
	message = binary.BigEndian.AppendUint32(message, uint32(len(topic)))
	message = append(message, topic...)
	return hmacSum(key, message), nil
}

// TupleInput contains the authority-only values committed by a tuple.
type TupleInput struct {
	Environment             string
	AccountIncarnationID    string
	HytchConversationID     string
	ConversationGeneration  uint32
	RosterVersion           uint32
	RosterCommitment        []byte
	TransportConversationID string
}

func TupleCommitment(key []byte, in TupleInput) ([]byte, error) {
	if len(key) != 32 || len(in.RosterCommitment) != 32 ||
		len(in.Environment) > 255 || !isASCII(in.Environment) ||
		in.ConversationGeneration == 0 || in.RosterVersion == 0 ||
		!lowerHex64Pattern.MatchString(in.TransportConversationID) {
		return nil, errors.New("invalid tuple commitment input")
	}
	account, err := ParseCanonicalUUID(in.AccountIncarnationID)
	if err != nil {
		return nil, err
	}
	conversation, err := ParseCanonicalUUID(in.HytchConversationID)
	if err != nil {
		return nil, err
	}
	const state = "ACTIVE"
	transport := []byte(in.TransportConversationID)
	message := make([]byte, 0, 256)
	message = append(message, tupleDomain...)
	message = append(message, byte(len(in.Environment)))
	message = append(message, in.Environment...)
	message = append(message, account...)
	message = append(message, conversation...)
	message = binary.BigEndian.AppendUint32(message, in.ConversationGeneration)
	message = binary.BigEndian.AppendUint32(message, in.RosterVersion)
	message = append(message, in.RosterCommitment...)
	message = append(message, byte(len(state)))
	message = append(message, state...)
	message = binary.BigEndian.AppendUint16(message, uint16(len(transport)))
	message = append(message, transport...)
	return hmacSum(key, message), nil
}

func hmacSum(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}

// ParseCanonicalUUID returns the RFC 4122 wire bytes for the contract's exact
// lowercase textual representation.
func ParseCanonicalUUID(value string) ([]byte, error) {
	if !canonicalUUIDPattern.MatchString(value) {
		return nil, errors.New("UUID is not canonical lowercase text")
	}
	compact := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != 16 {
		return nil, errors.New("invalid UUID")
	}
	return decoded, nil
}

func IsLowerHexSHA256(value string) bool {
	return lowerHexDigestPattern.MatchString(value)
}

func TopicEpoch(at time.Time) uint32 {
	seconds := at.UTC().Unix()
	if seconds < 0 {
		return 0
	}
	return uint32(seconds / topicPeriodSeconds)
}

func TopicEpochBoundary(epoch uint32) time.Time {
	return time.Unix(int64(epoch)*topicPeriodSeconds, 0).UTC()
}

// TopicEpochUsable describes the overlap rule at a particular instant.
// Issuance accepts only the current period. Verification additionally accepts
// the immediately previous period before the 60-second erasure deadline.
func TopicEpochUsable(epoch uint32, at time.Time, forIssuance bool) bool {
	current := TopicEpoch(at)
	if epoch == current {
		return true
	}
	if forIssuance || current == 0 || epoch != current-1 {
		return false
	}
	return at.Before(TopicEpochBoundary(current).Add(60 * time.Second))
}

// PreviousTopicEpochVerificationUsable adds the two state predicates that
// cryptography alone cannot infer: the assertion must already have been
// accepted and must still be unexpired.
func PreviousTopicEpochVerificationUsable(epoch uint32, at, assertionExpiry time.Time, alreadyAccepted bool) bool {
	return alreadyAccepted && at.Before(assertionExpiry) &&
		TopicEpochUsable(epoch, at, false)
}
