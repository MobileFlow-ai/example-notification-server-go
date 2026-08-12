package vault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/hex"

	"github.com/xmtp/example-notification-server-go/pkg/a10registration"
	"github.com/xmtp/example-notification-server-go/pkg/authority"
)

// A10RegistrationSink updates only the encrypted APNS token of an installation
// whose A9-to-Gate-6 identity mapping already exists. It cannot create routing
// authority, extend a lease, or repair an uncertain A9 stream.
type A10RegistrationSink struct {
	store *Store
	topic string
}

func NewA10RegistrationSink(store *Store, topic string) (*A10RegistrationSink, error) {
	expected := map[string]string{"dev": "com.mobileflow.hytchdev", "production": "com.hytch.rewards"}
	if store == nil || !store.a9Enabled || topic == "" || expected[store.environment] != topic {
		return nil, ErrStoreUnavailable
	}
	return &A10RegistrationSink{store: store, topic: topic}, nil
}

func (sink *A10RegistrationSink) RegisterVerified(ctx context.Context, registration a10registration.VerifiedRegistration) error {
	token := registration.APNSToken.Bytes()
	defer zero(token)
	return sink.registerVerified(ctx, registration, token)
}

func (sink *A10RegistrationSink) registerVerified(ctx context.Context, registration a10registration.VerifiedRegistration, token []byte) error {
	if sink == nil || sink.store == nil || ctx == nil || ctx.Err() != nil ||
		registration.Environment != sink.store.environment || registration.APNSTopic != sink.topic ||
		registration.PayloadSchema != "xmtp.encrypted.v4" || len(token) < 1 || len(token) > 256 {
		return ErrStoreUnavailable
	}
	installationID := hex.EncodeToString(registration.InstallationID[:])
	if !authority.ValidInstallationID(installationID) {
		return ErrStoreUnavailable
	}
	identity, err := sink.store.installationDeletionIdentity(installationID)
	if err != nil {
		return ErrStoreUnavailable
	}
	defer zero(identity)
	for attempt := 0; attempt < a9TransactionAttempts; attempt++ {
		err = sink.registerOnce(ctx, registration, identity, token)
		if err == nil {
			return nil
		}
		if !isSerializationFailure(err) {
			return ErrStoreUnavailable
		}
	}
	return ErrStoreUnavailable
}

func (sink *A10RegistrationSink) registerOnce(ctx context.Context, registration a10registration.VerifiedRegistration, identity, token []byte) error {
	tx, err := sink.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err = sink.store.requireRetentionSafeTx(ctx, tx); err != nil {
		return err
	}
	var (
		storedIdentity     []byte
		installationLookup []byte
		encryptedToken     []byte
		authorityState     int16
		installationState  int16
	)
	err = tx.QueryRowContext(ctx, `
		SELECT mapping.installation_identity,
		       installation.installation_lookup,
		       installation.encrypted_apns_token,
		       authority.state,
		       installation.state
		  FROM hytch_push_vault.a9_installation_gate6_bindings AS mapping
		  JOIN hytch_push_vault.a9_installation_authority AS authority
		    ON authority.environment = mapping.environment
		   AND authority.installation_binding_id = mapping.installation_binding_id
		  JOIN hytch_push_vault.installation_states AS installation
		    ON installation.environment = mapping.environment
		   AND installation.installation_identity = mapping.installation_identity
		  JOIN hytch_push_vault.a9_keyset_state AS keyset
		    ON keyset.environment = authority.environment
		 WHERE mapping.environment = $1
		   AND mapping.installation_binding_id = $2
		   AND authority.state = 1
		   AND authority.uncertainty_reason = 0
		   AND authority.watermark_status = 1
		   AND authority.watermark_committed_through = authority.contiguous_stream_sequence
		   AND authority.watermark_expires_at > pg_catalog.clock_timestamp()
		   AND keyset.state = 1
		   AND keyset.keyset_sequence = authority.watermark_keyset_sequence
		   AND keyset.signed_keyset_hash = authority.watermark_keyset_hash
		   AND keyset.expires_at > pg_catalog.clock_timestamp()
		   AND installation.state = 2
		   AND installation.expires_at > pg_catalog.clock_timestamp()
		   AND installation.control_expires_at > pg_catalog.clock_timestamp()
		 FOR UPDATE OF authority, installation`, sink.store.environmentID, registration.InstallationBindingID[:]).Scan(
		&storedIdentity, &installationLookup, &encryptedToken, &authorityState, &installationState,
	)
	if err != nil || len(storedIdentity) != 32 || len(installationLookup) != 32 ||
		authorityState != a9AuthorityActive || installationState != stateActive || !bytes.Equal(storedIdentity, identity) {
		return ErrStoreUnavailable
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO hytch_push_vault.a10_registration_bindings
		(environment, installation_binding_id, installation_identity, owner_binding)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (environment, installation_binding_id) DO NOTHING`,
		sink.store.environmentID, registration.InstallationBindingID[:], identity, registration.OwnerBinding[:])
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || (rows != 0 && rows != 1) {
		return ErrStoreUnavailable
	}
	if rows == 0 {
		var boundIdentity, boundOwner []byte
		if err = tx.QueryRowContext(ctx, `SELECT installation_identity, owner_binding FROM hytch_push_vault.a10_registration_bindings WHERE environment = $1 AND installation_binding_id = $2`, sink.store.environmentID, registration.InstallationBindingID[:]).Scan(&boundIdentity, &boundOwner); err != nil || !bytes.Equal(boundIdentity, identity) || !hmac.Equal(boundOwner, registration.OwnerBinding[:]) {
			return ErrStoreUnavailable
		}
	}
	changed := len(encryptedToken) == 0
	if !changed {
		current, openErr := sink.store.encryption.Open(installationContext(installationLookup, "apns-token"), encryptedToken)
		if openErr != nil {
			return ErrStoreUnavailable
		}
		changed = !hmac.Equal(current, token)
		zero(current)
	}
	if changed {
		if err = sink.store.markDeliveryJobsSafetyForInstallationTx(ctx, tx, installationLookup, nil); err != nil {
			return err
		}
		ciphertext, sealErr := sink.store.encryption.Seal(installationContext(installationLookup, "apns-token"), token)
		if sealErr != nil {
			return ErrStoreUnavailable
		}
		defer zero(ciphertext)
		result, err = tx.ExecContext(ctx, `UPDATE hytch_push_vault.installation_states SET encrypted_apns_token = $1, encryption_key_version = $2 WHERE installation_lookup = $3 AND environment = $4 AND state = $5`, ciphertext, int32(sink.store.encryption.ActiveVersion()), installationLookup, sink.store.environmentID, stateActive)
		if err != nil {
			return err
		}
		if rows, err = result.RowsAffected(); err != nil || rows != 1 {
			return ErrStoreUnavailable
		}
	}
	return tx.Commit()
}

var _ a10registration.Sink = (*A10RegistrationSink)(nil)
