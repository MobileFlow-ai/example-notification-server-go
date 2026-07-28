package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"
)

const (
	envelopeMagic          = "HV1\x00"
	envelopeHeaderBytes    = 4 + 4 + 12 + 12 + 48
	lookupRotationInterval = 7 * 24 * time.Hour
)

var (
	ErrCryptoUnavailable = errors.New("vault cryptography unavailable")
	ErrCiphertextInvalid = errors.New("vault ciphertext invalid")
	ErrLookupUnavailable = errors.New("vault lookup unavailable")
)

type Keyring struct {
	activeVersion uint32
	keys          map[uint32][]byte
	random        io.Reader
}

type keyringJSON struct {
	ActiveVersion uint32            `json:"active_version"`
	Keys          map[string]string `json:"keys"`
}

func (k *Keyring) ActiveVersion() uint32 {
	if k == nil {
		return 0
	}
	return k.activeVersion
}

func ParseKeyring(raw string) (*Keyring, error) {
	var encoded keyringJSON
	if err := json.Unmarshal([]byte(raw), &encoded); err != nil ||
		encoded.ActiveVersion == 0 || len(encoded.Keys) == 0 {
		return nil, ErrCryptoUnavailable
	}
	keys := make(map[uint32][]byte, len(encoded.Keys))
	for versionString, value := range encoded.Keys {
		version, err := strconv.ParseUint(versionString, 10, 32)
		if err != nil || version == 0 {
			return nil, ErrCryptoUnavailable
		}
		key, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(key) != 32 {
			return nil, ErrCryptoUnavailable
		}
		keys[uint32(version)] = key
	}
	if _, ok := keys[encoded.ActiveVersion]; !ok {
		return nil, ErrCryptoUnavailable
	}
	return &Keyring{
		activeVersion: encoded.ActiveVersion,
		keys:          keys,
		random:        rand.Reader,
	}, nil
}

func NewKeyring(activeVersion uint32, keys map[uint32][]byte) (*Keyring, error) {
	if activeVersion == 0 {
		return nil, ErrCryptoUnavailable
	}
	cloned := make(map[uint32][]byte, len(keys))
	for version, key := range keys {
		if version == 0 || len(key) != 32 {
			return nil, ErrCryptoUnavailable
		}
		cloned[version] = append([]byte(nil), key...)
	}
	if _, ok := cloned[activeVersion]; !ok {
		return nil, ErrCryptoUnavailable
	}
	return &Keyring{
		activeVersion: activeVersion,
		keys:          cloned,
		random:        rand.Reader,
	}, nil
}

// Seal uses a fresh per-value data key. The active root key wraps that data key;
// the root key never encrypts routing material directly.
func (k *Keyring) Seal(context, plaintext []byte) ([]byte, error) {
	if k == nil || len(context) == 0 {
		return nil, ErrCryptoUnavailable
	}
	rootKey, ok := k.keys[k.activeVersion]
	if !ok || len(rootKey) != 32 {
		return nil, ErrCryptoUnavailable
	}
	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(k.random, dataKey); err != nil {
		return nil, ErrCryptoUnavailable
	}
	defer zero(dataKey)

	dataAEAD, err := aesGCM(dataKey)
	if err != nil {
		return nil, ErrCryptoUnavailable
	}
	dataNonce := make([]byte, dataAEAD.NonceSize())
	if _, err = io.ReadFull(k.random, dataNonce); err != nil {
		return nil, ErrCryptoUnavailable
	}
	dataCiphertext := dataAEAD.Seal(
		nil,
		dataNonce,
		plaintext,
		vaultAAD("hytch.vault.data.v1\x00", context),
	)

	rootAEAD, err := aesGCM(rootKey)
	if err != nil {
		return nil, ErrCryptoUnavailable
	}
	wrapNonce := make([]byte, rootAEAD.NonceSize())
	if _, err = io.ReadFull(k.random, wrapNonce); err != nil {
		return nil, ErrCryptoUnavailable
	}
	wrappedDataKey := rootAEAD.Seal(
		nil,
		wrapNonce,
		dataKey,
		vaultAAD("hytch.vault.wrap.v1\x00", context),
	)
	if len(wrapNonce) != 12 || len(dataNonce) != 12 || len(wrappedDataKey) != 48 {
		return nil, ErrCryptoUnavailable
	}

	out := make([]byte, 0, envelopeHeaderBytes+len(dataCiphertext))
	out = append(out, envelopeMagic...)
	out = binary.BigEndian.AppendUint32(out, k.activeVersion)
	out = append(out, wrapNonce...)
	out = append(out, dataNonce...)
	out = append(out, wrappedDataKey...)
	out = append(out, dataCiphertext...)
	return out, nil
}

func (k *Keyring) Open(context, sealed []byte) ([]byte, error) {
	if k == nil || len(context) == 0 || len(sealed) < envelopeHeaderBytes+16 ||
		string(sealed[:4]) != envelopeMagic {
		return nil, ErrCiphertextInvalid
	}
	version := binary.BigEndian.Uint32(sealed[4:8])
	rootKey, ok := k.keys[version]
	if !ok || len(rootKey) != 32 {
		return nil, ErrCryptoUnavailable
	}
	wrapNonce := sealed[8:20]
	dataNonce := sealed[20:32]
	wrappedDataKey := sealed[32:80]
	dataCiphertext := sealed[80:]

	rootAEAD, err := aesGCM(rootKey)
	if err != nil {
		return nil, ErrCryptoUnavailable
	}
	dataKey, err := rootAEAD.Open(
		nil,
		wrapNonce,
		wrappedDataKey,
		vaultAAD("hytch.vault.wrap.v1\x00", context),
	)
	if err != nil || len(dataKey) != 32 {
		return nil, ErrCiphertextInvalid
	}
	defer zero(dataKey)

	dataAEAD, err := aesGCM(dataKey)
	if err != nil {
		return nil, ErrCryptoUnavailable
	}
	plaintext, err := dataAEAD.Open(
		nil,
		dataNonce,
		dataCiphertext,
		vaultAAD("hytch.vault.data.v1\x00", context),
	)
	if err != nil {
		return nil, ErrCiphertextInvalid
	}
	return plaintext, nil
}

type LookupKey struct {
	root []byte
}

func ParseLookupKey(encoded string) (*LookupKey, error) {
	root, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(root) != 32 {
		return nil, ErrLookupUnavailable
	}
	return &LookupKey{root: root}, nil
}

func NewLookupKey(root []byte) (*LookupKey, error) {
	if len(root) != 32 {
		return nil, ErrLookupUnavailable
	}
	return &LookupKey{root: append([]byte(nil), root...)}, nil
}

func LookupEpoch(at time.Time) uint64 {
	return uint64(at.UTC().Unix()) / uint64(lookupRotationInterval/time.Second)
}

func (k *LookupKey) Digest(domain string, epoch uint64, value []byte) ([]byte, error) {
	if k == nil || len(k.root) != 32 || len(domain) == 0 || len(value) == 0 {
		return nil, ErrLookupUnavailable
	}
	mac := hmac.New(sha256.New, k.root)
	_, _ = mac.Write([]byte("hytch.vault.lookup.v1\x00"))
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], epoch)
	_, _ = mac.Write(encoded[:])
	binary.BigEndian.PutUint64(encoded[:], uint64(len(value)))
	_, _ = mac.Write(encoded[:])
	_, _ = mac.Write(value)
	return mac.Sum(nil), nil
}

func (k *LookupKey) RootCommitment() ([]byte, error) {
	return k.Digest(
		"lookup-root-binding",
		0,
		[]byte("hytch.push.vault.lookup-root.v1"),
	)
}

// CandidateEpochs covers the current and immediately previous seven-day
// lookup periods. Active leases cannot be older than seven days.
func CandidateEpochs(at time.Time) []uint64 {
	current := LookupEpoch(at)
	if current == 0 {
		return []uint64{0}
	}
	return []uint64{current, current - 1}
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func vaultAAD(domain string, context []byte) []byte {
	out := make([]byte, 0, len(domain)+8+len(context))
	out = append(out, domain...)
	out = binary.BigEndian.AppendUint64(out, uint64(len(context)))
	return append(out, context...)
}

func zero(value []byte) {
	for idx := range value {
		value[idx] = 0
	}
}
