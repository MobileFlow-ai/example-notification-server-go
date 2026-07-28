package vault

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewIncidentAccessGateRejectsInvalidConfiguration(t *testing.T) {
	gate, err := NewIncidentAccessGate(nil, IncidentAccessOptions{})
	require.Nil(t, gate)
	require.ErrorIs(t, err, ErrIncidentAccessInvalid)

	db := &sql.DB{}
	validBroadcast := func(
		context.Context,
		IncidentOversightNotice,
	) error {
		return nil
	}
	gate, err = NewIncidentAccessGate(
		db,
		IncidentAccessOptions{
			Environment:         "staging",
			AuthorizedApprovers: []string{"security:actor"},
			Broadcast:           validBroadcast,
		},
	)
	require.Nil(t, gate)
	require.ErrorIs(t, err, ErrIncidentAccessInvalid)

	gate, err = NewIncidentAccessGate(
		db,
		IncidentAccessOptions{
			Environment:         "development",
			RoleTTL:             maxIncidentRoleTTL + time.Nanosecond,
			AuthorizedApprovers: []string{"security:actor"},
			Broadcast:           validBroadcast,
		},
	)
	require.Nil(t, gate)
	require.ErrorIs(t, err, ErrIncidentAccessInvalid)

	gate, err = NewIncidentAccessGate(
		db,
		IncidentAccessOptions{
			Environment:         "production",
			AuthorizedApprovers: []string{"security:actor"},
			Broadcast:           validBroadcast,
		},
	)
	require.NoError(t, err)
	require.Equal(t, environmentProduction, gate.environmentID)
}

func TestIncidentAccessValidationIsStrictAndContentFree(t *testing.T) {
	require.True(t, validActorID("security:actor-01"))
	require.True(t, validActorID("privacy_actor.02"))
	require.False(t, validActorID("short"))
	require.False(t, validActorID("person@example.com"))
	require.False(t, validActorID("actor with spaces"))

	require.Equal(t, "incident access request invalid", ErrIncidentAccessInvalid.Error())
	require.Equal(t, "incident access denied", ErrIncidentAccessDenied.Error())
	require.Equal(t, "incident access unavailable", ErrIncidentAccessUnavailable.Error())
	require.Equal(t, "incident query failed", ErrIncidentQueryFailed.Error())

	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	require.True(
		t,
		validIncidentWindow(now.Add(-time.Hour), now, now),
	)
	require.False(
		t,
		validIncidentWindow(now.Add(-3*time.Hour), now, now),
	)
	require.False(
		t,
		validIncidentWindow(now, now.Add(6*time.Minute), now),
	)
	require.True(
		t,
		validIncidentHypothesis(IncidentHypothesisMissingDelivery),
	)
	require.False(t, validIncidentHypothesis(0))
}

func TestIncidentAccessUsesCoarseAuditDimensions(t *testing.T) {
	testCases := []struct {
		count  int
		bucket int16
	}{
		{count: 0, bucket: 0},
		{count: 1, bucket: 1},
		{count: 2, bucket: 2},
		{count: 4, bucket: 2},
		{count: 5, bucket: 3},
		{count: 16, bucket: 3},
		{count: 17, bucket: 4},
		{count: 64, bucket: 4},
		{count: 65, bucket: 5},
		{count: 1000000, bucket: 5},
	}
	for _, testCase := range testCases {
		require.Equal(t, testCase.bucket, resultCountBucket(testCase.count))
	}

	value := time.Date(2026, 7, 26, 12, 59, 59, 999, time.FixedZone("local", -5*60*60))
	require.Equal(
		t,
		time.Date(2026, 7, 26, 17, 0, 0, 0, time.UTC),
		coarseHour(value),
	)
}

func TestIncidentAccessRandomIDRejectsAllZeroValue(t *testing.T) {
	gate := &IncidentAccessGate{random: bytes.NewReader(make([]byte, 16))}
	id, err := gate.randomID()
	require.Equal(t, AccessRequestID{}, id)
	require.ErrorIs(t, err, ErrIncidentAccessUnavailable)

	randomBytes := make([]byte, 16)
	randomBytes[15] = 1
	gate.random = bytes.NewReader(randomBytes)
	id, err = gate.randomID()
	require.NoError(t, err)
	require.False(t, zeroRequestID(id))
}

func TestStoredAccessRequestRequiresIndependentApproverAndBroadcast(
	t *testing.T,
) {
	coarseCreated := time.Now().UTC().Truncate(time.Hour)
	valid := &accessRequestRow{
		purpose:         AccessPurposeIncidentResponse,
		dataClass:       AccessDataClassRawVault,
		requesterActor:  "requester:actor",
		ticketReference: "incident:ticket-001",
		hypothesis:      IncidentHypothesisMissingDelivery,
		windowStart:     coarseCreated.Add(-time.Hour),
		windowEnd:       coarseCreated,
		approverActor:   "security:actor",
		oversightBroadcast: sql.NullTime{
			Time:  coarseCreated,
			Valid: true,
		},
		coarseCreated: coarseCreated,
		roleExpires: sql.NullTime{
			Time:  coarseCreated.Add(time.Hour),
			Valid: true,
		},
		state: accessStateApproved,
	}
	require.True(t, validStoredAccessRequest(valid))

	missingBroadcast := *valid
	missingBroadcast.oversightBroadcast = sql.NullTime{}
	require.False(t, validStoredAccessRequest(&missingBroadcast))

	requesterApproved := *valid
	requesterApproved.approverActor = requesterApproved.requesterActor
	require.False(t, validStoredAccessRequest(&requesterApproved))
}

func TestRawVaultQueryKindsHaveSeparateFixedAuditActions(t *testing.T) {
	seen := make(map[int16]struct{})
	for kind := RawVaultQueryInstallation; kind <= RawVaultQueryDeliveryJob; kind++ {
		require.True(t, validRawVaultQueryKind(kind))
		success := querySuccessAction(kind)
		failure := queryFailureAction(kind)
		require.NotEqual(t, success, failure)
		_, duplicateSuccess := seen[success]
		require.False(t, duplicateSuccess)
		seen[success] = struct{}{}
		_, duplicateFailure := seen[failure]
		require.False(t, duplicateFailure)
		seen[failure] = struct{}{}
	}
	require.False(t, validRawVaultQueryKind(0))
	require.False(t, validRawVaultQueryKind(RawVaultQueryDeliveryJob+1))
	require.True(
		t,
		validRawVaultTarget(
			RawVaultQueryInstallation,
			make([]byte, 32),
		),
	)
	require.False(
		t,
		validRawVaultTarget(
			RawVaultQueryInstallation,
			make([]byte, 16),
		),
	)
	require.True(
		t,
		validRawVaultTarget(RawVaultQueryLease, make([]byte, 16)),
	)
	require.False(
		t,
		validRawVaultTarget(RawVaultQueryLease, make([]byte, 32)),
	)
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	_, err := executeRawVaultQuery(
		t.Context(),
		&sql.Tx{},
		RawVaultQueryInstallation,
		make([]byte, 32),
		0,
		now.Add(-time.Hour),
		now,
	)
	require.ErrorIs(t, err, ErrIncidentQueryFailed)
	require.False(t, errors.Is(ErrIncidentQueryFailed, ErrIncidentAccessDenied))
}
