package gate8wrapper

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"time"
)

const (
	// SchemaVersion is the first pinned Gate 8 wrapper profile.
	SchemaVersion uint32 = 1

	RouteKeySize    = 32
	RouteAliasSize  = 16
	NoncePrefixSize = 4
	NonceSize       = 12
	DayKeySize      = 32

	// MaxTopicBytes is a conservative local bound. Gate 8 requires a fixed
	// per-field bound but does not choose one for raw topic bytes. A9 must pin
	// the same value on registration clients before this package is integrated.
	MaxTopicBytes = 4 * 1024

	// MaxCanonicalInteger avoids the RFC 8785/I-JSON ambiguity for uint64
	// values above JavaScript's exactly representable integer range. Gate 8
	// calls delivery_sequence uint64 while also requiring canonical JSON; A9
	// must either retain this fail-closed bound or version the field as a
	// canonical string/binary value.
	MaxCanonicalInteger uint64 = 1<<53 - 1
)

const (
	routeAliasDomain  = "hytch.push.route-alias.v1\x00"
	wrapperSaltDomain = "hytch.push.wrapper.salt.v1\x00"
	wrapperInfoDomain = "hytch.push.wrapper.aes-gcm.v1\x00"
)

// Environment is part of every derivation and prevents cross-environment use.
type Environment string

const (
	EnvironmentDev        Environment = "dev"
	EnvironmentProduction Environment = "production"
)

// RouteAlias is the daily 128-bit HMAC-derived routing alias.
type RouteAlias [RouteAliasSize]byte

// Header is the fixed authenticated header. AliasDay is exactly YYYY-MM-DD in
// UTC. The nonce prefix is public but must be randomly generated and never
// reused with the same day key.
type Header struct {
	SchemaVersion    uint32
	Environment      Environment
	AliasDay         string
	RouteAlias       RouteAlias
	RouteKeyEpoch    uint32
	NoncePrefix      [NoncePrefixSize]byte
	DeliverySequence uint64
}

type headerJSON struct {
	AliasDay         string `json:"alias_day"`
	DeliverySequence uint64 `json:"delivery_sequence"`
	Environment      string `json:"environment"`
	NoncePrefix      string `json:"nonce_prefix"`
	RouteAlias       string `json:"route_alias"`
	RouteKeyEpoch    uint32 `json:"route_key_epoch"`
	SchemaVersion    uint32 `json:"schema_version"`
}

// UTCDay returns the exact daily derivation string.
func UTCDay(value time.Time) string {
	return value.UTC().Format(time.DateOnly)
}

// DeriveRouteAlias implements the Gate 8 derivation exactly:
//
//	Truncate128(HMAC-SHA256(
//	  route_key,
//	  domain || I2OSP(len(topic), 4) || topic || NUL ||
//	  environment || NUL || YYYY-MM-DD))
func DeriveRouteAlias(
	routeKey []byte,
	topic []byte,
	environment Environment,
	aliasDay string,
) (RouteAlias, error) {
	var alias RouteAlias
	if err := validateRouteInputs(routeKey, topic, environment, aliasDay); err != nil {
		return alias, err
	}

	mac := hmac.New(sha256.New, routeKey)
	_, _ = mac.Write([]byte(routeAliasDomain))
	var topicLength [4]byte
	binary.BigEndian.PutUint32(topicLength[:], uint32(len(topic)))
	_, _ = mac.Write(topicLength[:])
	_, _ = mac.Write(topic)
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(environment))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(aliasDay))
	copy(alias[:], mac.Sum(nil)[:RouteAliasSize])
	return alias, nil
}

// DeriveDayKey implements the Gate 8 HKDF-SHA256 profile. It uses a local
// RFC 5869 extract/expand implementation so the package remains standard
// library only across supported Go toolchains.
func DeriveDayKey(
	routeKey []byte,
	environment Environment,
	aliasDay string,
	routeAlias RouteAlias,
	routeKeyEpoch uint32,
) ([DayKeySize]byte, error) {
	var key [DayKeySize]byte
	if len(routeKey) != RouteKeySize {
		return key, ErrInvalidRouteKey
	}
	if err := validateEnvironment(environment); err != nil {
		return key, err
	}
	if err := validateAliasDay(aliasDay); err != nil {
		return key, err
	}
	if routeKeyEpoch == 0 {
		return key, ErrInvalidHeader
	}

	saltInput := make([]byte, 0, len(wrapperSaltDomain)+len(environment)+1+len(aliasDay))
	saltInput = append(saltInput, wrapperSaltDomain...)
	saltInput = append(saltInput, environment...)
	saltInput = append(saltInput, 0)
	saltInput = append(saltInput, aliasDay...)
	salt := sha256.Sum256(saltInput)

	info := make([]byte, 0, len(wrapperInfoDomain)+RouteAliasSize+4)
	info = append(info, wrapperInfoDomain...)
	info = append(info, routeAlias[:]...)
	var epoch [4]byte
	binary.BigEndian.PutUint32(epoch[:], routeKeyEpoch)
	info = append(info, epoch[:]...)

	extract := hmac.New(sha256.New, salt[:])
	_, _ = extract.Write(routeKey)
	pseudorandomKey := extract.Sum(nil)

	expand := hmac.New(sha256.New, pseudorandomKey)
	_, _ = expand.Write(info)
	_, _ = expand.Write([]byte{1})
	copy(key[:], expand.Sum(nil))
	return key, nil
}

// BuildNonce constructs nonce_prefix_32 || I2OSP(delivery_sequence, 8).
func BuildNonce(
	noncePrefix [NoncePrefixSize]byte,
	deliverySequence uint64,
) ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	if deliverySequence > MaxCanonicalInteger {
		return nonce, ErrInvalidSequence
	}
	copy(nonce[:NoncePrefixSize], noncePrefix[:])
	binary.BigEndian.PutUint64(nonce[NoncePrefixSize:], deliverySequence)
	return nonce, nil
}

// CanonicalAAD returns the exact fixed-header JSON used as AES-GCM AAD.
//
// Gate 8 says RFC 8785 canonical JSON but does not specify field names or the
// text encoding for binary fields. This v1 contract uses snake_case names,
// lower-case hexadecimal aliases/prefixes, and lexicographic member order.
// Restricting the only uint64 field to MaxCanonicalInteger keeps it I-JSON.
func (header Header) CanonicalAAD() ([]byte, error) {
	if err := header.validate(); err != nil {
		return nil, err
	}

	alias := hex.EncodeToString(header.RouteAlias[:])
	prefix := hex.EncodeToString(header.NoncePrefix[:])
	result := make([]byte, 0, 256)
	result = append(result, `{"alias_day":"`...)
	result = append(result, header.AliasDay...)
	result = append(result, `","delivery_sequence":`...)
	result = strconv.AppendUint(result, header.DeliverySequence, 10)
	result = append(result, `,"environment":"`...)
	result = append(result, header.Environment...)
	result = append(result, `","nonce_prefix":"`...)
	result = append(result, prefix...)
	result = append(result, `","route_alias":"`...)
	result = append(result, alias...)
	result = append(result, `","route_key_epoch":`...)
	result = strconv.AppendUint(result, uint64(header.RouteKeyEpoch), 10)
	result = append(result, `,"schema_version":`...)
	result = strconv.AppendUint(result, uint64(header.SchemaVersion), 10)
	result = append(result, '}')
	return result, nil
}

// ParseCanonicalAAD accepts only the byte-exact v1 canonical representation.
// Unknown fields, duplicates, whitespace, alternate ordering, upper-case hex,
// and trailing input are rejected.
func ParseCanonicalAAD(encoded []byte) (Header, error) {
	var wire headerJSON
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return Header{}, ErrInvalidHeader
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Header{}, ErrInvalidHeader
	}

	aliasBytes, err := hex.DecodeString(wire.RouteAlias)
	if err != nil || len(aliasBytes) != RouteAliasSize ||
		wire.RouteAlias != hex.EncodeToString(aliasBytes) {
		return Header{}, ErrInvalidHeader
	}
	prefixBytes, err := hex.DecodeString(wire.NoncePrefix)
	if err != nil || len(prefixBytes) != NoncePrefixSize ||
		wire.NoncePrefix != hex.EncodeToString(prefixBytes) {
		return Header{}, ErrInvalidHeader
	}

	header := Header{
		SchemaVersion:    wire.SchemaVersion,
		Environment:      Environment(wire.Environment),
		AliasDay:         wire.AliasDay,
		RouteKeyEpoch:    wire.RouteKeyEpoch,
		DeliverySequence: wire.DeliverySequence,
	}
	copy(header.RouteAlias[:], aliasBytes)
	copy(header.NoncePrefix[:], prefixBytes)
	canonical, err := header.CanonicalAAD()
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Header{}, ErrInvalidHeader
	}
	return header, nil
}

func validateRouteInputs(
	routeKey []byte,
	topic []byte,
	environment Environment,
	aliasDay string,
) error {
	if len(routeKey) != RouteKeySize {
		return ErrInvalidRouteKey
	}
	if len(topic) == 0 || len(topic) > MaxTopicBytes {
		return ErrInvalidTopic
	}
	if err := validateEnvironment(environment); err != nil {
		return err
	}
	return validateAliasDay(aliasDay)
}

func validateEnvironment(environment Environment) error {
	switch environment {
	case EnvironmentDev, EnvironmentProduction:
		return nil
	default:
		return ErrInvalidEnvironment
	}
}

func validateAliasDay(aliasDay string) error {
	if len(aliasDay) != len("2006-01-02") {
		return ErrInvalidDay
	}
	parsed, err := time.Parse(time.DateOnly, aliasDay)
	if err != nil || parsed.Format(time.DateOnly) != aliasDay {
		return ErrInvalidDay
	}
	return nil
}

func (header Header) validate() error {
	if header.SchemaVersion != SchemaVersion {
		return ErrInvalidHeader
	}
	if header.RouteKeyEpoch == 0 {
		return ErrInvalidHeader
	}
	if err := validateEnvironment(header.Environment); err != nil {
		return ErrInvalidHeader
	}
	if err := validateAliasDay(header.AliasDay); err != nil {
		return ErrInvalidHeader
	}
	if header.DeliverySequence > MaxCanonicalInteger {
		return ErrInvalidHeader
	}
	return nil
}
