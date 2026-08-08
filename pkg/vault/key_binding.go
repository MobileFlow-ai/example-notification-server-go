package vault

import (
	"context"
	"crypto/subtle"
	"database/sql"
)

func requireLookupKeyBoundTx(
	ctx context.Context,
	tx *sql.Tx,
	lookup *LookupKey,
	environmentID int16,
) error {
	if tx == nil || lookup == nil ||
		(environmentID != environmentDevelopment &&
			environmentID != environmentProduction) {
		return ErrLookupUnavailable
	}
	commitment, err := lookup.RootCommitment()
	if err != nil || len(commitment) != 32 {
		return ErrLookupUnavailable
	}
	defer zero(commitment)
	if _, err = tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.vault_key_bindings (
		     environment, lookup_root_commitment, bound_at
		 ) VALUES ($1,$2,clock_timestamp())
		 ON CONFLICT (environment) DO NOTHING`,
		environmentID,
		commitment,
	); err != nil {
		return ErrLookupUnavailable
	}
	var stored []byte
	if err = tx.QueryRowContext(
		ctx,
		`SELECT lookup_root_commitment
		   FROM hytch_push_vault.vault_key_bindings
		  WHERE environment = $1
		  FOR SHARE`,
		environmentID,
	).Scan(&stored); err != nil {
		return ErrLookupUnavailable
	}
	if len(stored) != len(commitment) ||
		subtle.ConstantTimeCompare(stored, commitment) != 1 {
		return ErrLookupUnavailable
	}
	return nil
}
