package a3trust

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	identityv1 "github.com/xmtp/xmtpd/pkg/proto/identity/api/v1"
	associations "github.com/xmtp/xmtpd/pkg/proto/identity/associations"
	validationv1 "github.com/xmtp/xmtpd/pkg/proto/mls_validation/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type staticHistorySource struct {
	history []IdentityUpdateRecord
	err     error
}

func (source *staticHistorySource) CompleteHistory(context.Context, string) ([]IdentityUpdateRecord, error) {
	return source.history, source.err
}

type scriptedValidator struct {
	responses []*validationv1.GetAssociationStateResponse
	calls     int
}

func (validator *scriptedValidator) Validate(
	_ context.Context,
	oldUpdates []*associations.IdentityUpdate,
	newUpdates []*associations.IdentityUpdate,
) (*validationv1.GetAssociationStateResponse, error) {
	if len(oldUpdates) != validator.calls || len(newUpdates) != 1 ||
		validator.calls >= len(validator.responses) {
		return nil, ErrUnavailable
	}
	response := validator.responses[validator.calls]
	validator.calls++
	return response, nil
}

func TestValidatedAssociationReaderDerivesCurrentMembershipAndPosition(t *testing.T) {
	now := time.UnixMilli(1750000000123).UTC()
	inboxID := strings.Repeat("a", 64)
	installation := bytes.Repeat([]byte{0x11}, 32)
	otherInstallation := bytes.Repeat([]byte{0x22}, 32)
	installationID := hex.EncodeToString(installation)
	state := testAssociationState(inboxID, installation, otherInstallation)
	reader, err := NewValidatedAssociationReader(
		&staticHistorySource{history: []IdentityUpdateRecord{
			{SequenceID: 7, ServerTimestampNS: uint64(now.Add(-time.Hour).UnixNano()), Update: &associations.IdentityUpdate{InboxId: inboxID}},
			{SequenceID: 9, ServerTimestampNS: uint64(now.Add(-time.Hour).UnixNano()), Update: &associations.IdentityUpdate{InboxId: inboxID}},
		}},
		&scriptedValidator{responses: []*validationv1.GetAssociationStateResponse{
			{AssociationState: testAssociationState(inboxID, nil), StateDiff: &associations.AssociationStateDiff{}},
			{AssociationState: state, StateDiff: &associations.AssociationStateDiff{
				NewMembers: []*associations.MemberIdentifier{
					installationIdentifier(installation),
					installationIdentifier(otherInstallation),
				},
			}},
		}},
		func() time.Time { return now },
		30*time.Second,
		16,
		64*1024,
		2*1024*1024,
		16*1024*1024,
	)
	require.NoError(t, err)
	observation, err := reader.ReadAssociation(t.Context(), inboxID, installationID)
	require.NoError(t, err)
	require.True(t, observation.Associated)
	require.False(t, observation.Revoked)
	require.True(t, observation.Fresh)
	require.NotNil(t, observation.AssociatedInboxID)
	require.Equal(t, inboxID, *observation.AssociatedInboxID)
	require.Equal(t, "9", observation.Position)
	require.Equal(t, uint64(now.UnixMilli()), observation.ObservedAtMS)
	require.Len(t, observation.StateDigest, 64)
}

func TestValidatedAssociationReaderDerivesRevocationOnlyFromValidatedDiff(t *testing.T) {
	now := time.UnixMilli(1750000000123).UTC()
	inboxID := strings.Repeat("b", 64)
	installation := bytes.Repeat([]byte{0x33}, 32)
	identifier := installationIdentifier(installation)
	reader, err := NewValidatedAssociationReader(
		&staticHistorySource{history: []IdentityUpdateRecord{
			{SequenceID: 1, ServerTimestampNS: uint64(now.Add(-time.Second).UnixNano()), Update: &associations.IdentityUpdate{InboxId: inboxID}},
			{SequenceID: 2, ServerTimestampNS: uint64(now.UnixNano()), Update: &associations.IdentityUpdate{InboxId: inboxID}},
		}},
		&scriptedValidator{responses: []*validationv1.GetAssociationStateResponse{
			{AssociationState: testAssociationState(inboxID, installation), StateDiff: &associations.AssociationStateDiff{
				NewMembers: []*associations.MemberIdentifier{identifier},
			}},
			{AssociationState: testAssociationState(inboxID, nil), StateDiff: &associations.AssociationStateDiff{RemovedMembers: []*associations.MemberIdentifier{identifier}}},
		}},
		func() time.Time { return now }, 30*time.Second, 16,
		64*1024, 2*1024*1024, 16*1024*1024,
	)
	require.NoError(t, err)
	observation, err := reader.ReadAssociation(t.Context(), inboxID, hex.EncodeToString(installation))
	require.NoError(t, err)
	require.False(t, observation.Associated)
	require.Nil(t, observation.AssociatedInboxID)
	require.True(t, observation.Revoked)
}

func TestValidatedAssociationReaderRejectsInconsistentValidationDiff(t *testing.T) {
	now := time.UnixMilli(1750000000123).UTC()
	inboxID := strings.Repeat("c", 64)
	installation := bytes.Repeat([]byte{0x34}, 32)
	reader, err := NewValidatedAssociationReader(
		&staticHistorySource{history: []IdentityUpdateRecord{{
			SequenceID: 1, ServerTimestampNS: uint64(now.UnixNano()),
			Update: &associations.IdentityUpdate{InboxId: inboxID},
		}}},
		&scriptedValidator{responses: []*validationv1.GetAssociationStateResponse{{
			AssociationState: testAssociationState(inboxID, installation),
			StateDiff:        &associations.AssociationStateDiff{},
		}}},
		func() time.Time { return now }, 30*time.Second, 16,
		64*1024, 2*1024*1024, 16*1024*1024,
	)
	require.NoError(t, err)
	_, err = reader.ReadAssociation(
		t.Context(), inboxID, hex.EncodeToString(installation),
	)
	require.ErrorIs(t, err, ErrUnavailable)
}

func TestCanonicalAssociationStateDigestSortsHashCollections(t *testing.T) {
	vectors := loadA3GoldenVectors(t)
	require.Equal(t, associationDigestContext, vectors.Association.ContextASCII)
	require.Len(t, vectors.Association.InstallationPublicKeys, 2)
	require.Equal(t, vectors.Association.InstallationPublicKeys[0], vectors.Association.TargetInstallationID)
	target, err := hex.DecodeString(vectors.Association.TargetInstallationID)
	require.NoError(t, err)
	other, err := hex.DecodeString(vectors.Association.InstallationPublicKeys[1])
	require.NoError(t, err)
	first := testAssociationState(vectors.Association.InboxID, target, other)
	for _, signature := range vectors.Association.SeenSignaturesBase64 {
		decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(signature)
		require.NoError(t, decodeErr)
		first.SeenSignatures = append(first.SeenSignatures, decoded)
	}
	second := proto.Clone(first).(*associations.AssociationState)
	second.Members[0], second.Members[1] = second.Members[1], second.Members[0]
	second.SeenSignatures = [][]byte{{2}, {3}, {1}}
	firstDigest, associated, err := canonicalAssociationStateDigest(first, target)
	require.NoError(t, err)
	secondDigest, secondAssociated, err := canonicalAssociationStateDigest(second, target)
	require.NoError(t, err)
	require.True(t, associated)
	require.True(t, secondAssociated)
	require.Equal(t, firstDigest, secondDigest)
	require.Equal(t, vectors.Association.ExpectedDigestLowerHex, firstDigest)
}

func TestCanonicalAssociationStateDigestRejectsMismatchedMemberMap(t *testing.T) {
	state := testAssociationState(strings.Repeat("d", 64), bytes.Repeat([]byte{1}, 32))
	state.Members[0].Value.Identifier = installationIdentifier(bytes.Repeat([]byte{2}, 32))
	_, _, err := canonicalAssociationStateDigest(state, bytes.Repeat([]byte{1}, 32))
	require.Error(t, err)
}

type staticAssociationReader struct{ observation AssociationObservation }

func (reader staticAssociationReader) ReadAssociation(context.Context, string, string) (AssociationObservation, error) {
	return reader.observation, nil
}

func TestAssociationHandlerMatchesModernStrictResponse(t *testing.T) {
	inboxID := strings.Repeat("e", 64)
	installationID := strings.Repeat("f", 64)
	handler, err := NewAssociationHandler(AssociationOptions{
		Enabled: true, Environment: "dev", BearerToken: testOpaqueBearer(0x31),
		Reader: staticAssociationReader{observation: AssociationObservation{
			InstallationID: installationID, AssociatedInboxID: &inboxID,
			Associated: true, Fresh: true, StateDigest: strings.Repeat("1", 64),
			Position: "42", ObservedAtMS: 1750000000123,
		}},
		MaxConcurrency: 2, RatePerSecond: 100, RateBurst: 100,
		RequestTimeout: time.Second, Clock: time.Now,
	})
	require.NoError(t, err)
	body, err := json.Marshal(map[string]any{
		"environment": "dev", "inbox_id": inboxID, "installation_id": installationID,
	})
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPost, AssociationPath, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testOpaqueBearer(0x31))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.JSONEq(t, `{
		"installation_id":"`+installationID+`",
		"associated_inbox_id":"`+inboxID+`",
		"associated":true,"revoked":false,"fresh":true,
		"state_digest":"`+strings.Repeat("1", 64)+`",
		"position":"42","observed_at_ms":1750000000123
	}`, recorder.Body.String())
}

func TestAssociationHandlerRejectsDuplicateJSONAndWrongTarget(t *testing.T) {
	handler, err := NewAssociationHandler(AssociationOptions{
		Enabled: true, Environment: "dev", BearerToken: testOpaqueBearer(0x31),
		Reader: staticAssociationReader{}, MaxConcurrency: 2,
		RatePerSecond: 100, RateBurst: 100, RequestTimeout: time.Second,
	})
	require.NoError(t, err)
	for name, target := range map[string]struct {
		target string
		body   string
	}{
		"duplicate": {AssociationPath, `{"environment":"dev","environment":"dev","inbox_id":"` + strings.Repeat("a", 64) + `","installation_id":"` + strings.Repeat("b", 64) + `"}`},
		"query":     {AssociationPath + "?probe=1", `{"environment":"dev","inbox_id":"` + strings.Repeat("a", 64) + `","installation_id":"` + strings.Repeat("b", 64) + `"}`},
		"escaped":   {"/%69nternal/v1/xmtp-directory/installation-associations:read", `{"environment":"dev","inbox_id":"` + strings.Repeat("a", 64) + `","installation_id":"` + strings.Repeat("b", 64) + `"}`},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, target.target, strings.NewReader(target.body))
			request.Header.Set("Authorization", "Bearer "+testOpaqueBearer(0x31))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			require.NotEqual(t, http.StatusOK, recorder.Code)
		})
	}
	validBody := `{"environment":"dev","inbox_id":"` + strings.Repeat("a", 64) + `","installation_id":"` + strings.Repeat("b", 64) + `"}`
	for _, header := range []string{"Authorization", "Content-Type", "Accept"} {
		t.Run("duplicate "+header, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, AssociationPath, strings.NewReader(validBody))
			request.Header.Set("Authorization", "Bearer "+testOpaqueBearer(0x31))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json")
			request.Header.Add(header, request.Header.Get(header))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			require.Equal(t, http.StatusUnauthorized, recorder.Code)
		})
	}
}

type scriptedIdentityClient struct {
	responses []*identityv1.GetIdentityUpdatesResponse
	cursors   []uint64
}

func (client *scriptedIdentityClient) GetIdentityUpdates(
	_ context.Context,
	request *identityv1.GetIdentityUpdatesRequest,
	_ ...grpc.CallOption,
) (*identityv1.GetIdentityUpdatesResponse, error) {
	client.cursors = append(client.cursors, request.Requests[0].SequenceId)
	if len(client.responses) == 0 {
		return nil, ErrUnavailable
	}
	response := client.responses[0]
	client.responses = client.responses[1:]
	return response, nil
}

func TestGRPCIdentityHistorySourceLoopsUntilEmptyAndRejectsTruncation(t *testing.T) {
	inboxID := strings.Repeat("9", 64)
	client := &scriptedIdentityClient{responses: []*identityv1.GetIdentityUpdatesResponse{
		identityPage(inboxID, 1, 2), identityPage(inboxID, 3), {},
	}}
	source, err := NewGRPCIdentityHistorySource(
		client, 4, 2, 4, 64*1024, 2*1024*1024,
	)
	require.NoError(t, err)
	history, err := source.CompleteHistory(t.Context(), inboxID)
	require.NoError(t, err)
	require.Len(t, history, 3)
	require.Equal(t, []uint64{0, 2, 3}, client.cursors)

	truncated, err := NewGRPCIdentityHistorySource(
		&scriptedIdentityClient{responses: []*identityv1.GetIdentityUpdatesResponse{identityPage(inboxID, 1)}},
		1, 2, 4, 64*1024, 2*1024*1024,
	)
	require.NoError(t, err)
	_, err = truncated.CompleteHistory(t.Context(), inboxID)
	require.ErrorIs(t, err, ErrUnavailable)
}

func TestAssociationHistoryAndIncrementalValidationHaveByteWorkCaps(t *testing.T) {
	inboxID := strings.Repeat("8", 64)
	oversizedClient := &scriptedIdentityClient{responses: []*identityv1.GetIdentityUpdatesResponse{
		identityUpdatePage(inboxID, 1, largeIdentityUpdate(inboxID, 600)),
	}}
	source, err := NewGRPCIdentityHistorySource(
		oversizedClient, 2, 2, 2, 256, 512,
	)
	require.NoError(t, err)
	_, err = source.CompleteHistory(t.Context(), inboxID)
	require.ErrorIs(t, err, ErrUnavailable)

	now := time.UnixMilli(1750000000123).UTC()
	history := make([]IdentityUpdateRecord, 0, 4)
	responses := make([]*validationv1.GetAssociationStateResponse, 0, 4)
	for index := 0; index < 4; index++ {
		history = append(history, IdentityUpdateRecord{
			SequenceID:        uint64(index + 1),
			ServerTimestampNS: uint64(now.Add(time.Duration(index) * time.Nanosecond).UnixNano()),
			Update:            largeIdentityUpdate(inboxID, 350),
		})
		responses = append(responses, &validationv1.GetAssociationStateResponse{
			AssociationState: testAssociationState(inboxID, nil),
			StateDiff:        &associations.AssociationStateDiff{},
		})
	}
	validator := &scriptedValidator{responses: responses}
	reader, err := NewValidatedAssociationReader(
		&staticHistorySource{history: history},
		validator,
		func() time.Time { return now },
		30*time.Second,
		4,
		512,
		2048,
		2048,
	)
	require.NoError(t, err)
	_, err = reader.ReadAssociation(
		t.Context(), inboxID, strings.Repeat("7", 64),
	)
	require.ErrorIs(t, err, ErrUnavailable)
	require.Less(t, validator.calls, len(history))
}

func identityPage(inboxID string, sequences ...uint64) *identityv1.GetIdentityUpdatesResponse {
	updates := make([]*identityv1.GetIdentityUpdatesResponse_IdentityUpdateLog, 0, len(sequences))
	for _, sequence := range sequences {
		updates = append(updates, &identityv1.GetIdentityUpdatesResponse_IdentityUpdateLog{
			SequenceId: sequence, ServerTimestampNs: sequence,
			Update: &associations.IdentityUpdate{InboxId: inboxID},
		})
	}
	return &identityv1.GetIdentityUpdatesResponse{Responses: []*identityv1.GetIdentityUpdatesResponse_Response{{
		InboxId: inboxID, Updates: updates,
	}}}
}

func identityUpdatePage(
	inboxID string,
	sequence uint64,
	update *associations.IdentityUpdate,
) *identityv1.GetIdentityUpdatesResponse {
	return &identityv1.GetIdentityUpdatesResponse{
		Responses: []*identityv1.GetIdentityUpdatesResponse_Response{{
			InboxId: inboxID,
			Updates: []*identityv1.GetIdentityUpdatesResponse_IdentityUpdateLog{{
				SequenceId: sequence, ServerTimestampNs: sequence, Update: update,
			}},
		}},
	}
}

func largeIdentityUpdate(inboxID string, payloadBytes int) *associations.IdentityUpdate {
	return &associations.IdentityUpdate{
		InboxId: inboxID,
		Actions: []*associations.IdentityAction{{
			Kind: &associations.IdentityAction_CreateInbox{
				CreateInbox: &associations.CreateInbox{
					InitialIdentifier: strings.Repeat("x", payloadBytes),
				},
			},
		}},
	}
}

func testAssociationState(inboxID string, installations ...[]byte) *associations.AssociationState {
	state := &associations.AssociationState{InboxId: inboxID}
	for _, installation := range installations {
		if installation == nil {
			continue
		}
		identifier := installationIdentifier(installation)
		state.Members = append(state.Members, &associations.MemberMap{
			Key:   proto.Clone(identifier).(*associations.MemberIdentifier),
			Value: &associations.Member{Identifier: identifier},
		})
	}
	return state
}

func installationIdentifier(value []byte) *associations.MemberIdentifier {
	return &associations.MemberIdentifier{Kind: &associations.MemberIdentifier_InstallationPublicKey{
		InstallationPublicKey: append([]byte(nil), value...),
	}}
}
