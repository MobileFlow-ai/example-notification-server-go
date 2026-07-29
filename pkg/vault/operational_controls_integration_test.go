package vault

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	testdb "github.com/xmtp/example-notification-server-go/pkg/testutils"
)

func TestIncidentAccessGateIntegration(t *testing.T) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	now := time.Date(2026, 7, 26, 12, 10, 0, 0, time.UTC)
	random := &sequenceReader{}
	var oversightNotices []IncidentOversightNotice
	gate, err := NewIncidentAccessGate(
		db,
		IncidentAccessOptions{
			Environment:         "dev",
			RoleTTL:             20 * time.Minute,
			Now:                 func() time.Time { return now },
			Random:              random,
			AuthorizedApprovers: []string{"security:actor"},
			Broadcast: func(
				_ context.Context,
				notice IncidentOversightNotice,
			) error {
				oversightNotices = append(oversightNotices, notice)
				return nil
			},
		},
	)
	require.NoError(t, err)

	status, err := gate.CreateRequest(
		t.Context(),
		CreateIncidentAccessRequest{
			RequesterActor:  "requester:actor",
			TicketReference: "incident:ticket-001",
			Hypothesis:      IncidentHypothesisMissingDelivery,
			WindowStart:     now.Add(-time.Hour),
			WindowEnd:       now,
			Purpose:         AccessPurposeIncidentResponse,
			DataClass:       AccessDataClassRawVault,
		},
	)
	require.NoError(t, err)
	require.Equal(t, accessStatePending, status.State)
	require.Equal(t, now.Truncate(time.Hour), status.CoarseCreated)

	_, err = gate.Approve(
		t.Context(),
		IncidentApproval{
			RequestID: status.RequestID,
			Actor:     "requester:actor",
		},
	)
	require.ErrorIs(t, err, ErrIncidentAccessDenied)
	require.Empty(t, oversightNotices)

	var storedState, storedEnvironment int16
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT state, environment
			 FROM hytch_push_vault.access_requests
			 WHERE request_id = $1`,
			status.RequestID[:],
		).Scan(&storedState, &storedEnvironment),
	)
	require.Equal(t, accessStatePending, storedState)
	require.Equal(t, environmentDevelopment, storedEnvironment)

	_, err = gate.Approve(
		t.Context(),
		IncidentApproval{
			RequestID: status.RequestID,
			Actor:     "operations:actor",
		},
	)
	require.ErrorIs(t, err, ErrIncidentAccessDenied)
	require.Empty(t, oversightNotices)

	status, err = gate.Approve(
		t.Context(),
		IncidentApproval{
			RequestID: status.RequestID,
			Actor:     "security:actor",
		},
	)
	require.NoError(t, err)
	require.Equal(t, accessStateApproved, status.State)
	require.NotNil(t, status.RoleExpiresAt)
	require.Equal(t, now.Add(20*time.Minute), *status.RoleExpiresAt)
	require.Equal(
		t,
		[]IncidentOversightNotice{{
			Purpose:            AccessPurposeIncidentResponse,
			DataClass:          AccessDataClassRawVault,
			CoarseApprovedHour: now.Truncate(time.Hour),
		}},
		oversightNotices,
	)

	status, err = gate.Approve(
		t.Context(),
		IncidentApproval{
			RequestID: status.RequestID,
			Actor:     "security:actor",
		},
	)
	require.NoError(t, err)
	require.Equal(t, accessStateApproved, status.State)
	require.Len(t, oversightNotices, 1)

	result, err := gate.WithAuthorizedRawVaultQuery(
		t.Context(),
		RawVaultAccessRequest{
			RequestID: status.RequestID,
			Actor:     "requester:actor",
			Purpose:   AccessPurposeIncidentResponse,
			DataClass: AccessDataClassRawVault,
			QueryKind: RawVaultQueryInstallation,
			Target:    repeatedBytes(32, 0xa1),
		},
	)
	require.NoError(t, err)
	require.Nil(t, result.Value)
	require.Zero(t, result.ResultCount)

	// The typed query API rejects a target shape that does not match its
	// fixed query kind; callers cannot supply SQL or a mutation callback.
	_, err = gate.WithAuthorizedRawVaultQuery(
		t.Context(),
		RawVaultAccessRequest{
			RequestID: status.RequestID,
			Actor:     "requester:actor",
			Purpose:   AccessPurposeIncidentResponse,
			DataClass: AccessDataClassRawVault,
			QueryKind: RawVaultQueryInstallation,
			Target:    repeatedBytes(16, 0xa2),
		},
	)
	require.ErrorIs(t, err, ErrIncidentAccessInvalid)

	require.NoError(
		t,
		gate.Revoke(t.Context(), status.RequestID, "security:actor"),
	)
	_, err = gate.WithAuthorizedRawVaultQuery(
		t.Context(),
		RawVaultAccessRequest{
			RequestID: status.RequestID,
			Actor:     "requester:actor",
			Purpose:   AccessPurposeIncidentResponse,
			DataClass: AccessDataClassRawVault,
			QueryKind: RawVaultQueryLease,
			Target:    repeatedBytes(16, 0xa3),
		},
	)
	require.ErrorIs(t, err, ErrIncidentAccessDenied)

	var nonCoarseEvents int
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*)
			 FROM hytch_push_vault.access_audit
			 WHERE environment <> $1
			    OR coarse_event_hour AT TIME ZONE 'UTC' <>
			           date_trunc(
			               'hour',
			               coarse_event_hour AT TIME ZONE 'UTC'
			           )
			    OR expires_on >
			           (coarse_event_hour AT TIME ZONE 'UTC')::date + 180`,
			environmentDevelopment,
		).Scan(&nonCoarseEvents),
	)
	require.Zero(t, nonCoarseEvents)
}

func TestIncidentAccessApprovalFailsClosedWhenOversightBroadcastFails(
	t *testing.T,
) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	now := time.Date(2026, 7, 26, 12, 10, 0, 0, time.UTC)
	gate, err := NewIncidentAccessGate(
		db,
		IncidentAccessOptions{
			Environment:         "dev",
			Now:                 func() time.Time { return now },
			Random:              &sequenceReader{},
			AuthorizedApprovers: []string{"security:actor"},
			Broadcast: func(
				context.Context,
				IncidentOversightNotice,
			) error {
				return errors.New("oversight unavailable")
			},
		},
	)
	require.NoError(t, err)
	status, err := gate.CreateRequest(
		t.Context(),
		CreateIncidentAccessRequest{
			RequesterActor:  "requester:actor",
			TicketReference: "incident:ticket-002",
			Hypothesis:      IncidentHypothesisSpuriousDelivery,
			WindowStart:     now.Add(-time.Hour),
			WindowEnd:       now,
			Purpose:         AccessPurposeIncidentResponse,
			DataClass:       AccessDataClassRawVault,
		},
	)
	require.NoError(t, err)

	_, err = gate.Approve(
		t.Context(),
		IncidentApproval{
			RequestID: status.RequestID,
			Actor:     "security:actor",
		},
	)
	require.ErrorIs(t, err, ErrIncidentAccessUnavailable)

	var state int16
	var approver sql.NullString
	var broadcast sql.NullTime
	var expiry sql.NullTime
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT state, approver_actor, oversight_broadcast_hour,
			        role_expires_at
			   FROM hytch_push_vault.access_requests
			  WHERE request_id = $1`,
			status.RequestID[:],
		).Scan(&state, &approver, &broadcast, &expiry),
	)
	require.Equal(t, accessStatePending, state)
	require.False(t, approver.Valid)
	require.False(t, broadcast.Valid)
	require.False(t, expiry.Valid)
}

func TestIncidentAccessIsEnvironmentScoped(t *testing.T) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	now := time.Date(2026, 7, 26, 12, 10, 0, 0, time.UTC)
	broadcast := func(
		context.Context,
		IncidentOversightNotice,
	) error {
		return nil
	}
	development, err := NewIncidentAccessGate(
		db,
		IncidentAccessOptions{
			Environment:         "dev",
			Now:                 func() time.Time { return now },
			Random:              &sequenceReader{},
			AuthorizedApprovers: []string{"security:actor"},
			Broadcast:           broadcast,
		},
	)
	require.NoError(t, err)
	production, err := NewIncidentAccessGate(
		db,
		IncidentAccessOptions{
			Environment:         "production",
			Now:                 func() time.Time { return now },
			Random:              &sequenceReader{next: 0x80},
			AuthorizedApprovers: []string{"security:actor"},
			Broadcast:           broadcast,
		},
	)
	require.NoError(t, err)

	status, err := development.CreateRequest(
		t.Context(),
		CreateIncidentAccessRequest{
			RequesterActor:  "requester:actor",
			TicketReference: "incident:ticket-env",
			Hypothesis:      IncidentHypothesisMissingDelivery,
			WindowStart:     now.Add(-time.Hour),
			WindowEnd:       now,
			Purpose:         AccessPurposeIncidentResponse,
			DataClass:       AccessDataClassRawVault,
		},
	)
	require.NoError(t, err)
	_, err = production.Approve(
		t.Context(),
		IncidentApproval{
			RequestID: status.RequestID,
			Actor:     "security:actor",
		},
	)
	require.ErrorIs(t, err, ErrIncidentAccessDenied)
	_, err = development.Approve(
		t.Context(),
		IncidentApproval{
			RequestID: status.RequestID,
			Actor:     "security:actor",
		},
	)
	require.NoError(t, err)

	installationLookup := repeatedBytes(32, 0xb1)
	leaseID := repeatedBytes(16, 0xb6)
	jobID := repeatedBytes(16, 0xb9)
	createdAt := now.Add(-30 * time.Minute)
	controlExpiresAt := createdAt.Add(time.Minute)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.installation_states (
		     installation_lookup, installation_identity,
		     incarnation_lookup, lookup_key_epoch, generation,
		     idempotency_digest, control_event_digest,
		     encrypted_apns_token, environment, payload_schema,
		     age_policy, policy_epoch, state, encryption_key_version,
		     created_at, refreshed_at, expires_at, control_expires_at
		 ) VALUES (
		     $1,$2,$3,1,1,$4,$5,$6,$7,1,1,1,$8,1,$9,$9,$10,$11
		 )`,
		installationLookup,
		repeatedBytes(32, 0xb2),
		repeatedBytes(32, 0xb3),
		repeatedBytes(32, 0xb4),
		repeatedBytes(32, 0xb5),
		[]byte{0x01},
		environmentProduction,
		stateActive,
		createdAt,
		now.Add(time.Hour),
		controlExpiresAt,
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.subscription_leases (
		     lease_id, installation_lookup, route_identity, topic_lookup,
		     lookup_key_epoch, encrypted_topic, encrypted_route_key,
		     encrypted_hmac_keys, encrypted_receive_capability, environment,
		     payload_schema, topic_kind, push_mode, state, generation,
		     policy_epoch, route_key_epoch, encrypted_nonce_state,
		     encryption_key_version, issued_at, refreshed_at, expires_at,
		     control_expires_at
		 ) VALUES (
		     $1,$2,$3,$4,1,$5,$5,$5,$5,$6,1,1,1,$7,1,1,1,$5,1,
		     $8,$8,$9,$10
		 )`,
		leaseID,
		installationLookup,
		repeatedBytes(32, 0xb7),
		repeatedBytes(32, 0xb8),
		[]byte{0x02},
		environmentProduction,
		stateActive,
		createdAt,
		now.Add(time.Hour),
		controlExpiresAt,
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.delivery_jobs (
		     job_id, lease_id, encrypted_job, environment, state, attempts,
		     retry_exponent, available_at, expires_at, created_at
		 ) VALUES ($1,$2,$3,$4,$5,0,0,$6,$7,$8)`,
		jobID,
		leaseID,
		[]byte{0x03},
		environmentProduction,
		deliveryJobPending,
		now,
		now.Add(10*time.Minute),
		now.Add(-2*time.Minute),
	)
	require.NoError(t, err)

	for _, query := range []struct {
		kind   RawVaultQueryKind
		target []byte
	}{
		{kind: RawVaultQueryInstallation, target: installationLookup},
		{kind: RawVaultQueryLease, target: leaseID},
		{kind: RawVaultQueryDeliveryJob, target: jobID},
	} {
		result, queryErr := development.WithAuthorizedRawVaultQuery(
			t.Context(),
			RawVaultAccessRequest{
				RequestID: status.RequestID,
				Actor:     "requester:actor",
				Purpose:   AccessPurposeIncidentResponse,
				DataClass: AccessDataClassRawVault,
				QueryKind: query.kind,
				Target:    query.target,
			},
		)
		require.NoError(t, queryErr)
		require.Nil(t, result.Value)
		require.Zero(t, result.ResultCount)
	}

	var crossEnvironmentAudits int
	require.NoError(
		t,
		db.QueryRowContext(
			t.Context(),
			`SELECT COUNT(*)
			   FROM hytch_push_vault.access_audit
			  WHERE request_id = $1
			    AND environment <> $2`,
			status.RequestID[:],
			environmentDevelopment,
		).Scan(&crossEnvironmentAudits),
	)
	require.Zero(t, crossEnvironmentAudits)
}

func TestRetentionSweeperIntegrationAndFailClosedHealth(t *testing.T) {
	requireVaultIntegrationTests(t)
	db := testdb.CreateTestDb(t)
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	expiredRefresh := now.Add(-10 * 24 * time.Hour)
	expiredAt := now.Add(-3 * 24 * time.Hour)

	installationLookup := repeatedBytes(32, 1)
	leaseID := repeatedBytes(16, 2)
	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.installation_states (
		     installation_lookup, incarnation_lookup, lookup_key_epoch,
		     generation, idempotency_digest, control_event_digest,
		     encrypted_apns_token, environment, payload_schema, age_policy,
		     policy_epoch, state, encryption_key_version, created_at,
		     refreshed_at, expires_at, control_expires_at,
		     installation_identity
		 ) VALUES ($1,$2,1,1,$3,$4,$5,1,1,1,1,2,1,$6,$6,$7,$8,$9)`,
		installationLookup,
		repeatedBytes(32, 3),
		repeatedBytes(32, 4),
		repeatedBytes(32, 5),
		[]byte{1},
		expiredRefresh,
		expiredAt,
		expiredRefresh.Add(30*time.Second),
		repeatedBytes(32, 17),
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.route_key_history (
			     environment, route_identity, route_key_epoch,
			     route_key_commitment,
			     updated_at, expires_at
			 ) VALUES (1,$1,1,$2,$3,$4)`,
		repeatedBytes(32, 8),
		repeatedBytes(32, 18),
		expiredRefresh,
		expiredAt.Add(8*24*time.Hour),
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.route_key_history (
			     environment, route_identity, route_key_epoch,
			     route_key_commitment,
			     updated_at, expires_at
			 ) VALUES (1,$1,1,$2,$3,$4)`,
		repeatedBytes(32, 19),
		repeatedBytes(32, 20),
		now.Add(-9*24*time.Hour),
		now.Add(-time.Hour),
	)
	require.NoError(t, err)

	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.subscription_leases (
		     lease_id, installation_lookup, topic_lookup, lookup_key_epoch,
		     encrypted_topic, encrypted_route_key, encrypted_hmac_keys,
		     encrypted_receive_capability, environment, payload_schema,
		     topic_kind, push_mode, state, generation, policy_epoch,
		     route_key_epoch, encrypted_nonce_state, encryption_key_version,
		     issued_at, refreshed_at, expires_at,
		     control_expires_at, route_identity
		 ) VALUES (
		     $1,$2,$3,1,$4,$4,$4,$4,1,1,1,2,2,1,1,1,$4,1,$5,$5,$6,$7,$8
		 )`,
		leaseID,
		installationLookup,
		repeatedBytes(32, 6),
		[]byte{2},
		expiredRefresh,
		expiredAt,
		expiredRefresh.Add(30*time.Second),
		repeatedBytes(32, 8),
	)
	require.NoError(t, err)

	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.delivery_jobs (
			     job_id, lease_id, encrypted_job, environment, state, attempts,
			     available_at, expires_at, created_at
			 ) VALUES ($1,$2,$3,1,1,0,$4,$5,$6)`,
		repeatedBytes(16, 7),
		leaseID,
		[]byte{3},
		now.Add(-10*time.Minute),
		now.Add(-6*time.Minute),
		now.Add(-20*time.Minute),
	)
	require.NoError(t, err)

	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.welcome_authorizations (
			     authorization_id, lease_id, environment, envelope_lookup,
			     encrypted_authorization, policy_epoch, issued_at, expires_at
			 ) VALUES ($1,$2,1,$3,$4,1,$5,$6)`,
		repeatedBytes(16, 8),
		leaseID,
		repeatedBytes(32, 9),
		[]byte{4},
		now.Add(-time.Hour),
		now.Add(-time.Minute),
	)
	require.NoError(t, err)

	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.welcome_budgets (
			     environment, destination_lookup,
			     minute_window_start, minute_count,
			     hour_window_start, hour_count, updated_at, expires_at
			 ) VALUES
			     (1,$1,$2,1,$2,1,$2,$3),
			     (1,$4,$6,1,$6,1,$6,$5)`,
		repeatedBytes(32, 10),
		now.Add(-time.Hour),
		now.Add(-time.Minute),
		repeatedBytes(32, 11),
		now.Add(time.Hour),
		now,
	)
	require.NoError(t, err)

	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.deletion_tombstones (
			     environment, target_kind, target_identity,
			     key_version, fence_epoch,
			     created_at, expires_at
			 ) VALUES (1,$1,$2,1,1,$3,$4)`,
		deletionTargetRoute,
		repeatedBytes(32, 12),
		now.Add(-9*24*time.Hour),
		now.Add(-24*time.Hour),
	)
	require.NoError(t, err)

	oldDay := now.AddDate(0, 0, -31)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.operational_aggregates (
		     bucket_day, bucket_hour, event_name, component, environment,
		     traffic_class, outcome, count_bucket, size_bucket,
		     latency_bucket, privacy_version, expires_on
		 ) VALUES ($1::date,1,1,1,1,0,1,1,NULL,1,1,$2::date)`,
		oldDay,
		now.AddDate(0, 0, -1),
	)
	require.NoError(t, err)

	oldHour := coarseHour(now.AddDate(0, 0, -181))
	requestID := repeatedBytes(16, 13)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.access_requests (
				     request_id, environment, purpose, data_class,
				     requester_actor,
				     ticket_reference, hypothesis, window_start, window_end,
				     coarse_created_hour, state
				 ) VALUES ($1,1,1,1,$2,$3,1,$4,$5,$5,4)`,
		requestID,
		"requester:old",
		"incident:old-001",
		oldHour.Add(-time.Hour),
		oldHour,
	)
	require.NoError(t, err)
	_, err = db.ExecContext(
		t.Context(),
		`INSERT INTO hytch_push_vault.access_audit (
			     event_id, request_id, environment,
			     actor, purpose, data_class,
			     coarse_event_hour, action, result_count_bucket, expires_on
			 ) VALUES ($1,$2,1,$3,1,1,$4,1,0,$5::date)`,
		repeatedBytes(16, 14),
		requestID,
		"requester:old",
		oldHour,
		now.AddDate(0, 0, -1),
	)
	require.NoError(t, err)

	retentionLookup, err := NewLookupKey(repeatedBytes(32, 99))
	require.NoError(t, err)
	sweeper, err := NewRetentionSweeper(
		db,
		RetentionOptions{
			SweepInterval:        15 * time.Minute,
			Environment:          "dev",
			Lookup:               retentionLookup,
			EncryptionKeyVersion: 1,
			Now:                  func() time.Time { return now },
		},
	)
	require.NoError(t, err)
	result, err := sweeper.Sweep(t.Context())
	require.NoError(t, err)
	require.Equal(t, now, result.CompletedAt)
	require.Equal(t, now.Add(15*time.Minute), result.NextDueAt)
	require.NoError(t, sweeper.Ready(t.Context()))

	assertTableCount(t, db, "installation_states", 0)
	assertTableCount(t, db, "subscription_leases", 0)
	assertTableCount(t, db, "delivery_jobs", 0)
	assertTableCount(t, db, "welcome_authorizations", 0)
	assertTableCount(t, db, "deletion_tombstones", 2)
	assertTableCount(t, db, "route_key_history", 1)
	assertTableCount(t, db, "operational_aggregates", 1)
	var finalizedLegacyRows int
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*)
		   FROM hytch_push_vault.operational_aggregates
		  WHERE event_name = $1
		    AND environment = 1
		    AND traffic_class = 0
		    AND outcome = $2
		    AND privacy_version = $3`,
		aggregateEventDeliveryFinal,
		DeliveryOutcomeMaterialInvalid,
		aggregatePrivacyVersion,
	).Scan(&finalizedLegacyRows))
	require.Equal(t, 1, finalizedLegacyRows)
	assertTableCount(t, db, "access_audit", 0)
	assertTableCount(t, db, "access_requests", 0)
	assertTableCount(t, db, "welcome_budgets", 1)
	assertTableCount(t, db, "welcome_global_circuit", 2)

	_, err = db.ExecContext(
		t.Context(),
		`DROP TABLE hytch_push_vault.delivery_jobs`,
	)
	require.NoError(t, err)
	_, err = sweeper.Sweep(t.Context())
	require.ErrorIs(t, err, ErrRetentionUnavailable)
	health, healthErr := sweeper.Health(t.Context())
	require.NoError(t, healthErr)
	require.False(t, health.Safe)
	require.ErrorIs(t, sweeper.Ready(t.Context()), ErrRetentionUnsafe)
}

func requireVaultIntegrationTests(t *testing.T) {
	t.Helper()
	if os.Getenv("VAULT_INTEGRATION_TESTS") != "1" {
		t.Skip("set VAULT_INTEGRATION_TESTS=1 to run database integration coverage")
	}
}

type sequenceReader struct {
	next byte
}

func (r *sequenceReader) Read(destination []byte) (int, error) {
	for index := range destination {
		r.next++
		if r.next == 0 {
			r.next++
		}
		destination[index] = r.next
	}
	return len(destination), nil
}

func repeatedBytes(length int, value byte) []byte {
	out := make([]byte, length)
	for index := range out {
		out[index] = value
	}
	return out
}

func assertTableCount(
	t *testing.T,
	db interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	},
	table string,
	expected int,
) {
	t.Helper()
	allowed := map[string]struct{}{
		"vault_key_bindings":     {},
		"installation_states":    {},
		"route_key_history":      {},
		"subscription_leases":    {},
		"delivery_jobs":          {},
		"welcome_authorizations": {},
		"welcome_budgets":        {},
		"welcome_global_circuit": {},
		"deletion_tombstones":    {},
		"operational_aggregates": {},
		"access_audit":           {},
		"access_requests":        {},
	}
	if _, ok := allowed[table]; !ok {
		t.Fatal(errors.New("integration assertion invalid"))
	}
	var count int
	err := db.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*) FROM hytch_push_vault.`+table,
	).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, expected, count)
}
