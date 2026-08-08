package incidentaccess

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/xmtp/example-notification-server-go/pkg/vault"
)

const (
	maxCredentialConfigBytes = 64 * 1024
	maxActorCredentials      = 32
	maxBearerSecretBytes     = 4096
	minBearerSecretBytes     = 32
)

var ErrInvalidConfiguration = errors.New(
	"incident access configuration invalid",
)

type actorRole string

const (
	actorRoleRequester actorRole = "requester"
	actorRoleApprover  actorRole = "approver"
)

type actorCredentialJSON struct {
	Actor           string    `json:"actor"`
	Role            actorRole `json:"role"`
	SecretSHA256B64 string    `json:"secret_sha256_b64"`
}

type actorCredential struct {
	actor  string
	role   actorRole
	digest [sha256.Size]byte
}

// Authenticator retains only configured SHA-256 digests. The corresponding
// bearer values must be delivered out of band and are never persisted by the
// bridge.
type Authenticator struct {
	credentials []actorCredential
}

// MarshalJSON makes the credential-bearing authenticator deliberately opaque
// if it is ever passed to structured logging or another JSON encoder.
func (*Authenticator) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}

func ParseActorCredentials(
	raw string,
) (*Authenticator, []string, error) {
	if len(raw) == 0 || len(raw) > maxCredentialConfigBytes {
		return nil, nil, ErrInvalidConfiguration
	}
	decoder := json.NewDecoder(
		io.LimitReader(
			strings.NewReader(raw),
			maxCredentialConfigBytes+1,
		),
	)
	decoder.DisallowUnknownFields()
	var incoming []actorCredentialJSON
	if err := decoder.Decode(&incoming); err != nil ||
		len(incoming) < 2 ||
		len(incoming) > maxActorCredentials ||
		requireJSONEOF(decoder) != nil {
		return nil, nil, ErrInvalidConfiguration
	}

	authenticator := &Authenticator{
		credentials: make([]actorCredential, 0, len(incoming)),
	}
	actors := make(map[string]struct{}, len(incoming))
	approvers := make([]string, 0, len(incoming))
	requesters := 0
	for _, configured := range incoming {
		if !vault.ValidIncidentActorID(configured.Actor) ||
			(configured.Role != actorRoleRequester &&
				configured.Role != actorRoleApprover) {
			return nil, nil, ErrInvalidConfiguration
		}
		if _, exists := actors[configured.Actor]; exists {
			return nil, nil, ErrInvalidConfiguration
		}
		actors[configured.Actor] = struct{}{}
		decoded, err := base64.RawURLEncoding.DecodeString(
			configured.SecretSHA256B64,
		)
		if err != nil ||
			len(decoded) != sha256.Size ||
			base64.RawURLEncoding.EncodeToString(decoded) !=
				configured.SecretSHA256B64 {
			return nil, nil, ErrInvalidConfiguration
		}
		var digest [sha256.Size]byte
		copy(digest[:], decoded)
		for _, existing := range authenticator.credentials {
			if hmac.Equal(existing.digest[:], digest[:]) {
				return nil, nil, ErrInvalidConfiguration
			}
		}
		authenticator.credentials = append(
			authenticator.credentials,
			actorCredential{
				actor:  configured.Actor,
				role:   configured.Role,
				digest: digest,
			},
		)
		switch configured.Role {
		case actorRoleRequester:
			requesters++
		case actorRoleApprover:
			approvers = append(approvers, configured.Actor)
		}
	}
	if requesters == 0 || len(approvers) == 0 {
		return nil, nil, ErrInvalidConfiguration
	}
	return authenticator, approvers, nil
}

func (a *Authenticator) requester(
	authorization string,
) (string, bool) {
	return a.authenticate(authorization, actorRoleRequester)
}

func (a *Authenticator) approver(
	authorization string,
) (string, bool) {
	return a.authenticate(authorization, actorRoleApprover)
}

func (a *Authenticator) either(
	authorization string,
) (string, bool) {
	requester, requesterOK := a.requester(authorization)
	approver, approverOK := a.approver(authorization)
	if requesterOK == approverOK {
		return "", false
	}
	if requesterOK {
		return requester, true
	}
	return approver, true
}

func (a *Authenticator) authenticate(
	authorization string,
	required actorRole,
) (string, bool) {
	const prefix = "Bearer "
	if a == nil ||
		len(authorization) <= len(prefix) ||
		len(authorization) > len(prefix)+maxBearerSecretBytes ||
		!strings.HasPrefix(authorization, prefix) {
		return "", false
	}
	secret := authorization[len(prefix):]
	if len(secret) < minBearerSecretBytes ||
		strings.TrimSpace(secret) != secret {
		return "", false
	}
	digest := sha256.Sum256([]byte(secret))
	matchedActor := ""
	matches := 0
	for _, configured := range a.credentials {
		digestMatch := hmac.Equal(configured.digest[:], digest[:])
		roleMatch := configured.role == required
		if digestMatch && roleMatch {
			matchedActor = configured.actor
			matches++
		}
	}
	if matches != 1 {
		return "", false
	}
	return matchedActor, true
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return ErrInvalidConfiguration
}

func decodeCanonicalBase64URL(
	value string,
	expectedSize int,
) ([]byte, error) {
	if value == "" || expectedSize <= 0 {
		return nil, ErrInvalidConfiguration
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil ||
		len(decoded) != expectedSize ||
		!bytes.Equal(
			[]byte(base64.RawURLEncoding.EncodeToString(decoded)),
			[]byte(value),
		) {
		return nil, ErrInvalidConfiguration
	}
	return decoded, nil
}
