package gate8wrapper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"errors"
)

const (
	// These are conservative v1 parser bounds. Gate 8 requires explicit limits
	// but leaves their exact values to the implementation/A9 contract.
	MaxCapabilityBytes     = 64 * 1024
	MaxXMTPCiphertextBytes = 1024 * 1024
	MaxPaddingBytes        = 4 * 1024

	innerFrameVersion    byte = 1
	innerFrameFixedBytes int  = 14
	gcmTagBytes          int  = 16
)

var (
	ErrInvalidRouteKey    = errors.New("gate8 wrapper: invalid route key")
	ErrInvalidTopic       = errors.New("gate8 wrapper: invalid topic")
	ErrInvalidEnvironment = errors.New(
		"gate8 wrapper: invalid environment",
	)
	ErrInvalidDay        = errors.New("gate8 wrapper: invalid alias day")
	ErrInvalidSequence   = errors.New("gate8 wrapper: invalid sequence")
	ErrInvalidHeader     = errors.New("gate8 wrapper: invalid header")
	ErrInvalidCapability = errors.New(
		"gate8 wrapper: invalid capability",
	)
	ErrInvalidPayload = errors.New("gate8 wrapper: invalid payload")
	ErrSizeLimit      = errors.New("gate8 wrapper: size limit exceeded")
	ErrBudgetRequired = errors.New(
		"gate8 wrapper: wrapper size budget required",
	)
	ErrPayloadTooLarge = errors.New(
		"gate8 wrapper: payload does not fit",
	)
	ErrAuthentication = errors.New(
		"gate8 wrapper: authentication failed",
	)
	ErrRouteMismatch = errors.New("gate8 wrapper: route mismatch")
	ErrReplay        = errors.New("gate8 wrapper: replay rejected")
	ErrReplayState   = errors.New("gate8 wrapper: replay state unavailable")
)

// DeliveryMode is authenticated inside the encrypted plaintext. It must not be
// copied into an outer APNs field, log, trace, or metric dimension.
type DeliveryMode string

const (
	ModeCiphertextInline DeliveryMode = "ciphertext_inline"
	ModeForegroundSync   DeliveryMode = "foreground_sync"
)

// Plaintext is the authenticated, encrypted inner payload.
type Plaintext struct {
	Capability    []byte
	DeliveryMode  DeliveryMode
	XMTPEnvelope  []byte
	RandomPadding []byte
}

// Envelope is the cryptographic wrapper. Integrations must choose and pin an
// outer APNs JSON encoding separately; Header.CanonicalAAD pins the authenticated
// header bytes regardless of that transport representation.
type Envelope struct {
	Header     Header
	Ciphertext []byte
}

// SizeEstimate lets the APNs layer account for its actual JSON, base64, aps
// fallback alert, and provider budget before this package consumes a nonce.
// Gate 8 does not fix the outer ciphertext encoding, so this package must not
// guess that overhead.
type SizeEstimate struct {
	Mode                          DeliveryMode
	HeaderAADBytes                int
	InnerPlaintextBytes           int
	SealedCiphertextBytes         int
	StandardBase64CiphertextBytes int
}

// FitsWrapper returns whether the complete APNs representation will fit. It
// receives sizes only, never a topic, key, capability, or ciphertext.
type FitsWrapper func(SizeEstimate) bool

// SealRequest contains all inputs needed to produce one wrapper. FitsWrapper is
// mandatory. OnForegroundSync is an optional content-free hook invoked only
// after a fallback wrapper has been encrypted successfully.
type SealRequest struct {
	RouteKey         []byte
	Topic            []byte
	Environment      Environment
	AliasDay         string
	RouteKeyEpoch    uint32
	NoncePrefix      [NoncePrefixSize]byte
	DeliverySequence uint64

	Capability        []byte
	XMTPEnvelope      []byte
	InlinePadding     []byte
	ForegroundPadding []byte

	FitsWrapper      FitsWrapper
	OnForegroundSync func()
}

// OpenRequest contains the expected raw route and an atomic replay protector
// scoped to that environment/route/day/epoch/prefix. Nil replay state fails
// closed.
type OpenRequest struct {
	RouteKey              []byte
	Topic                 []byte
	ExpectedEnvironment   Environment
	ExpectedAliasDay      string
	ExpectedRouteKeyEpoch uint32
	Envelope              Envelope
	Replay                ReplayProtector
}

// Seal chooses ciphertext_inline only when the caller's complete-wrapper size
// callback accepts it. Otherwise it encrypts exactly one foreground_sync
// payload without the XMTP envelope. Mode selection happens before AES-GCM so
// the same nonce is never reused for different plaintext.
func Seal(request SealRequest) (Envelope, error) {
	if request.FitsWrapper == nil {
		return Envelope{}, ErrBudgetRequired
	}
	if err := validateRouteInputs(
		request.RouteKey,
		request.Topic,
		request.Environment,
		request.AliasDay,
	); err != nil {
		return Envelope{}, err
	}
	if request.DeliverySequence > MaxCanonicalInteger {
		return Envelope{}, ErrInvalidSequence
	}
	if err := validatePlaintextParts(
		request.Capability,
		request.XMTPEnvelope,
		request.InlinePadding,
		false,
	); err != nil {
		return Envelope{}, err
	}
	if len(request.ForegroundPadding) > MaxPaddingBytes {
		return Envelope{}, ErrSizeLimit
	}

	alias, err := DeriveRouteAlias(
		request.RouteKey,
		request.Topic,
		request.Environment,
		request.AliasDay,
	)
	if err != nil {
		return Envelope{}, err
	}
	header := Header{
		SchemaVersion:    SchemaVersion,
		Environment:      request.Environment,
		AliasDay:         request.AliasDay,
		RouteAlias:       alias,
		RouteKeyEpoch:    request.RouteKeyEpoch,
		NoncePrefix:      request.NoncePrefix,
		DeliverySequence: request.DeliverySequence,
	}
	aad, err := header.CanonicalAAD()
	if err != nil {
		return Envelope{}, err
	}

	mode := ModeCiphertextInline
	message := request.XMTPEnvelope
	padding := request.InlinePadding
	inlineSize, err := estimateSize(mode, len(aad), len(request.Capability), len(message), len(padding))
	if err != nil {
		return Envelope{}, err
	}
	if len(message) == 0 || !request.FitsWrapper(inlineSize) {
		mode = ModeForegroundSync
		message = nil
		padding = request.ForegroundPadding
		foregroundSize, estimateErr := estimateSize(
			mode,
			len(aad),
			len(request.Capability),
			0,
			len(padding),
		)
		if estimateErr != nil {
			return Envelope{}, estimateErr
		}
		if !request.FitsWrapper(foregroundSize) {
			return Envelope{}, ErrPayloadTooLarge
		}
	}

	plaintext, err := encodePlaintext(Plaintext{
		Capability:    request.Capability,
		DeliveryMode:  mode,
		XMTPEnvelope:  message,
		RandomPadding: padding,
	})
	if err != nil {
		return Envelope{}, err
	}
	defer clear(plaintext)

	dayKey, err := DeriveDayKey(
		request.RouteKey,
		request.Environment,
		request.AliasDay,
		alias,
		request.RouteKeyEpoch,
	)
	if err != nil {
		return Envelope{}, err
	}
	defer clear(dayKey[:])
	aead, err := newGCM(dayKey[:])
	if err != nil {
		return Envelope{}, ErrAuthentication
	}
	nonce, err := BuildNonce(request.NoncePrefix, request.DeliverySequence)
	if err != nil {
		return Envelope{}, err
	}
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	if len(ciphertext) > maxSealedCiphertextBytes() {
		clear(ciphertext)
		return Envelope{}, ErrSizeLimit
	}

	if mode == ModeForegroundSync && request.OnForegroundSync != nil {
		request.OnForegroundSync()
	}
	return Envelope{Header: header, Ciphertext: ciphertext}, nil
}

// Open verifies the expected route alias, authenticates the wrapper, advances
// replay state, and parses the bounded inner frame. Authentication happens
// before replay advancement, so unauthenticated high-sequence input cannot
// poison the window.
func Open(request OpenRequest) (Plaintext, error) {
	if replayProtectorUnavailable(request.Replay) {
		return Plaintext{}, ErrReplayState
	}
	if err := validateRouteInputs(
		request.RouteKey,
		request.Topic,
		request.Envelope.Header.Environment,
		request.Envelope.Header.AliasDay,
	); err != nil {
		return Plaintext{}, err
	}
	if err := request.Envelope.Header.validate(); err != nil {
		return Plaintext{}, err
	}
	if request.ExpectedEnvironment == "" ||
		request.ExpectedAliasDay == "" ||
		request.ExpectedRouteKeyEpoch == 0 ||
		request.Envelope.Header.Environment != request.ExpectedEnvironment ||
		request.Envelope.Header.AliasDay != request.ExpectedAliasDay ||
		request.Envelope.Header.RouteKeyEpoch != request.ExpectedRouteKeyEpoch {
		return Plaintext{}, ErrRouteMismatch
	}
	if len(request.Envelope.Ciphertext) < gcmTagBytes ||
		len(request.Envelope.Ciphertext) > maxSealedCiphertextBytes() {
		return Plaintext{}, ErrSizeLimit
	}

	expectedAlias, err := DeriveRouteAlias(
		request.RouteKey,
		request.Topic,
		request.Envelope.Header.Environment,
		request.Envelope.Header.AliasDay,
	)
	if err != nil {
		return Plaintext{}, err
	}
	if !hmac.Equal(expectedAlias[:], request.Envelope.Header.RouteAlias[:]) {
		return Plaintext{}, ErrRouteMismatch
	}

	aad, err := request.Envelope.Header.CanonicalAAD()
	if err != nil {
		return Plaintext{}, err
	}
	dayKey, err := DeriveDayKey(
		request.RouteKey,
		request.Envelope.Header.Environment,
		request.Envelope.Header.AliasDay,
		request.Envelope.Header.RouteAlias,
		request.Envelope.Header.RouteKeyEpoch,
	)
	if err != nil {
		return Plaintext{}, err
	}
	defer clear(dayKey[:])
	aead, err := newGCM(dayKey[:])
	if err != nil {
		return Plaintext{}, ErrAuthentication
	}
	nonce, err := BuildNonce(
		request.Envelope.Header.NoncePrefix,
		request.Envelope.Header.DeliverySequence,
	)
	if err != nil {
		return Plaintext{}, err
	}
	opened, err := aead.Open(
		nil,
		nonce[:],
		request.Envelope.Ciphertext,
		aad,
	)
	if err != nil {
		return Plaintext{}, ErrAuthentication
	}
	defer clear(opened)

	if err := request.Replay.CompareAndAdvanceAuthenticated(
		request.Envelope.Header,
	); err != nil {
		return Plaintext{}, err
	}
	plaintext, err := decodePlaintext(opened)
	if err != nil {
		return Plaintext{}, err
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func estimateSize(
	mode DeliveryMode,
	aadBytes int,
	capabilityBytes int,
	messageBytes int,
	paddingBytes int,
) (SizeEstimate, error) {
	if err := validatePlaintextLengths(
		mode,
		capabilityBytes,
		messageBytes,
		paddingBytes,
	); err != nil {
		return SizeEstimate{}, err
	}
	plaintextBytes := innerFrameFixedBytes +
		capabilityBytes +
		messageBytes +
		paddingBytes
	sealedBytes := plaintextBytes + gcmTagBytes
	return SizeEstimate{
		Mode:                          mode,
		HeaderAADBytes:                aadBytes,
		InnerPlaintextBytes:           plaintextBytes,
		SealedCiphertextBytes:         sealedBytes,
		StandardBase64CiphertextBytes: base64.StdEncoding.EncodedLen(sealedBytes),
	}, nil
}

func encodePlaintext(plaintext Plaintext) ([]byte, error) {
	messageRequired := plaintext.DeliveryMode == ModeCiphertextInline
	if err := validatePlaintextParts(
		plaintext.Capability,
		plaintext.XMTPEnvelope,
		plaintext.RandomPadding,
		messageRequired,
	); err != nil {
		return nil, err
	}
	if plaintext.DeliveryMode == ModeForegroundSync &&
		len(plaintext.XMTPEnvelope) != 0 {
		return nil, ErrInvalidPayload
	}

	modeCode, err := encodeMode(plaintext.DeliveryMode)
	if err != nil {
		return nil, err
	}
	total := innerFrameFixedBytes +
		len(plaintext.Capability) +
		len(plaintext.XMTPEnvelope) +
		len(plaintext.RandomPadding)
	encoded := make([]byte, total)
	encoded[0] = innerFrameVersion
	encoded[1] = modeCode
	binary.BigEndian.PutUint32(encoded[2:6], uint32(len(plaintext.Capability)))
	binary.BigEndian.PutUint32(encoded[6:10], uint32(len(plaintext.XMTPEnvelope)))
	binary.BigEndian.PutUint32(encoded[10:14], uint32(len(plaintext.RandomPadding)))
	offset := innerFrameFixedBytes
	offset += copy(encoded[offset:], plaintext.Capability)
	offset += copy(encoded[offset:], plaintext.XMTPEnvelope)
	copy(encoded[offset:], plaintext.RandomPadding)
	return encoded, nil
}

func decodePlaintext(encoded []byte) (Plaintext, error) {
	if len(encoded) < innerFrameFixedBytes || encoded[0] != innerFrameVersion {
		return Plaintext{}, ErrInvalidPayload
	}
	mode, err := decodeMode(encoded[1])
	if err != nil {
		return Plaintext{}, err
	}
	capabilityLength := int(binary.BigEndian.Uint32(encoded[2:6]))
	messageLength := int(binary.BigEndian.Uint32(encoded[6:10]))
	paddingLength := int(binary.BigEndian.Uint32(encoded[10:14]))
	if err := validatePlaintextLengths(
		mode,
		capabilityLength,
		messageLength,
		paddingLength,
	); err != nil {
		return Plaintext{}, err
	}
	expectedLength := innerFrameFixedBytes +
		capabilityLength +
		messageLength +
		paddingLength
	if expectedLength != len(encoded) {
		return Plaintext{}, ErrInvalidPayload
	}

	offset := innerFrameFixedBytes
	capability := append([]byte(nil), encoded[offset:offset+capabilityLength]...)
	offset += capabilityLength
	message := append([]byte(nil), encoded[offset:offset+messageLength]...)
	offset += messageLength
	padding := append([]byte(nil), encoded[offset:offset+paddingLength]...)
	return Plaintext{
		Capability:    capability,
		DeliveryMode:  mode,
		XMTPEnvelope:  message,
		RandomPadding: padding,
	}, nil
}

func validatePlaintextParts(
	capability []byte,
	message []byte,
	padding []byte,
	messageRequired bool,
) error {
	if len(capability) == 0 {
		return ErrInvalidCapability
	}
	if len(capability) > MaxCapabilityBytes ||
		len(message) > MaxXMTPCiphertextBytes ||
		len(padding) > MaxPaddingBytes {
		return ErrSizeLimit
	}
	if messageRequired && len(message) == 0 {
		return ErrInvalidPayload
	}
	return nil
}

func validatePlaintextLengths(
	mode DeliveryMode,
	capabilityBytes int,
	messageBytes int,
	paddingBytes int,
) error {
	if capabilityBytes <= 0 {
		return ErrInvalidCapability
	}
	if capabilityBytes > MaxCapabilityBytes ||
		messageBytes < 0 ||
		messageBytes > MaxXMTPCiphertextBytes ||
		paddingBytes < 0 ||
		paddingBytes > MaxPaddingBytes {
		return ErrSizeLimit
	}
	switch mode {
	case ModeCiphertextInline:
		if messageBytes == 0 {
			return ErrInvalidPayload
		}
	case ModeForegroundSync:
		if messageBytes != 0 {
			return ErrInvalidPayload
		}
	default:
		return ErrInvalidPayload
	}
	return nil
}

func encodeMode(mode DeliveryMode) (byte, error) {
	switch mode {
	case ModeCiphertextInline:
		return 1, nil
	case ModeForegroundSync:
		return 2, nil
	default:
		return 0, ErrInvalidPayload
	}
}

func decodeMode(value byte) (DeliveryMode, error) {
	switch value {
	case 1:
		return ModeCiphertextInline, nil
	case 2:
		return ModeForegroundSync, nil
	default:
		return "", ErrInvalidPayload
	}
}

func maxSealedCiphertextBytes() int {
	return innerFrameFixedBytes +
		MaxCapabilityBytes +
		MaxXMTPCiphertextBytes +
		MaxPaddingBytes +
		gcmTagBytes
}
