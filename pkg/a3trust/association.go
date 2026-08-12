package a3trust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"

	identityv1 "github.com/xmtp/xmtpd/pkg/proto/identity/api/v1"
	associations "github.com/xmtp/xmtpd/pkg/proto/identity/associations"
	validationv1 "github.com/xmtp/xmtpd/pkg/proto/mls_validation/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

const (
	associationDigestContext = "hytch.xmtp-association-state-digest.v1\x00"
	maxAssociationBodyBytes  = 4 * 1024
)

type IdentityUpdateRecord struct {
	SequenceID        uint64
	ServerTimestampNS uint64
	Update            *associations.IdentityUpdate
}

type IdentityHistorySource interface {
	CompleteHistory(context.Context, string) ([]IdentityUpdateRecord, error)
}

type AssociationStateValidator interface {
	Validate(context.Context, []*associations.IdentityUpdate, []*associations.IdentityUpdate) (*validationv1.GetAssociationStateResponse, error)
}

type AssociationObservation struct {
	InstallationID    string
	AssociatedInboxID *string
	Associated        bool
	Revoked           bool
	Fresh             bool
	StateDigest       string
	Position          string
	ObservedAtMS      uint64
}

type AssociationReader interface {
	ReadAssociation(context.Context, string, string) (AssociationObservation, error)
}

type ValidatedAssociationReader struct {
	source             IdentityHistorySource
	validator          AssociationStateValidator
	clock              func() time.Time
	maximumSkew        time.Duration
	maxUpdates         int
	maxUpdateBytes     int
	maxHistoryBytes    int
	maxValidationBytes int
}

func NewValidatedAssociationReader(
	source IdentityHistorySource,
	validator AssociationStateValidator,
	clock func() time.Time,
	maximumSkew time.Duration,
	maxUpdates int,
	maxUpdateBytes int,
	maxHistoryBytes int,
	maxValidationBytes int,
) (*ValidatedAssociationReader, error) {
	if source == nil || validator == nil ||
		maximumSkew < 0 || maximumSkew > time.Hour ||
		maxUpdates < 1 || maxUpdates > 1024 ||
		maxUpdateBytes < 256 || maxUpdateBytes > 1024*1024 ||
		maxHistoryBytes < maxUpdateBytes || maxHistoryBytes > 16*1024*1024 ||
		maxValidationBytes < maxHistoryBytes ||
		maxValidationBytes > 128*1024*1024 {
		return nil, ErrConfiguration
	}
	if clock == nil {
		clock = time.Now
	}
	return &ValidatedAssociationReader{
		source: source, validator: validator, clock: clock,
		maximumSkew: maximumSkew, maxUpdates: maxUpdates,
		maxUpdateBytes: maxUpdateBytes, maxHistoryBytes: maxHistoryBytes,
		maxValidationBytes: maxValidationBytes,
	}, nil
}

func (reader *ValidatedAssociationReader) ReadAssociation(
	ctx context.Context,
	inboxID string,
	installationID string,
) (AssociationObservation, error) {
	if reader == nil || !lowerHex32Pattern.MatchString(inboxID) ||
		!lowerHex32Pattern.MatchString(installationID) {
		return AssociationObservation{}, ErrUnavailable
	}
	history, err := reader.source.CompleteHistory(ctx, inboxID)
	if err != nil || len(history) == 0 || len(history) > reader.maxUpdates {
		return AssociationObservation{}, ErrUnavailable
	}
	updates := make([]*associations.IdentityUpdate, 0, len(history))
	removed := false
	var finalState *associations.AssociationState
	previousMembers := make(map[string]struct{})
	var previousSequence uint64
	var previousTimestamp uint64
	historyBytes := 0
	validationBytes := 0
	installationBytes, _ := hex.DecodeString(installationID)
	for index, record := range history {
		if record.Update == nil || record.SequenceID == 0 ||
			record.Update.InboxId != inboxID ||
			hasUnknownFields(record.Update.ProtoReflect()) ||
			(index > 0 && record.SequenceID <= previousSequence) ||
			record.ServerTimestampNS == 0 ||
			(index > 0 && record.ServerTimestampNS < previousTimestamp) ||
			record.ServerTimestampNS/uint64(time.Millisecond) > maxExactJSONInteger {
			return AssociationObservation{}, ErrUnavailable
		}
		encodedUpdate, marshalErr := (proto.MarshalOptions{Deterministic: true}).
			Marshal(record.Update)
		if marshalErr != nil || len(encodedUpdate) > reader.maxUpdateBytes ||
			historyBytes > reader.maxHistoryBytes-len(encodedUpdate) {
			return AssociationObservation{}, ErrUnavailable
		}
		historyBytes += len(encodedUpdate)
		validationRequest := &validationv1.GetAssociationStateRequest{
			OldUpdates: updates,
			NewUpdates: []*associations.IdentityUpdate{record.Update},
		}
		encodedRequest, marshalErr := (proto.MarshalOptions{Deterministic: true}).
			Marshal(validationRequest)
		if marshalErr != nil || len(encodedRequest) == 0 ||
			validationBytes > reader.maxValidationBytes-len(encodedRequest) {
			return AssociationObservation{}, ErrUnavailable
		}
		validationBytes += len(encodedRequest)
		response, validateErr := reader.validator.Validate(
			ctx,
			updates,
			[]*associations.IdentityUpdate{record.Update},
		)
		if validateErr != nil || response == nil || response.AssociationState == nil ||
			response.StateDiff == nil || response.AssociationState.InboxId != inboxID ||
			hasUnknownFields(response.ProtoReflect()) {
			return AssociationObservation{}, ErrUnavailable
		}
		if proto.Size(response) > reader.maxHistoryBytes {
			return AssociationObservation{}, ErrUnavailable
		}
		encodedResponse, marshalErr := (proto.MarshalOptions{Deterministic: true}).
			Marshal(response)
		if marshalErr != nil || len(encodedResponse) == 0 ||
			validationBytes > reader.maxValidationBytes-len(encodedResponse) {
			return AssociationObservation{}, ErrUnavailable
		}
		currentMembers, transitionErr := validatedAssociationTransition(
			previousMembers,
			response.AssociationState,
			response.StateDiff,
		)
		if transitionErr != nil {
			return AssociationObservation{}, ErrUnavailable
		}
		validationBytes += len(encodedResponse)
		for _, member := range response.StateDiff.RemovedMembers {
			if member != nil && bytes.Equal(member.GetInstallationPublicKey(), installationBytes) {
				removed = true
			}
		}
		updates = append(updates, proto.Clone(record.Update).(*associations.IdentityUpdate))
		finalState = response.AssociationState
		previousMembers = currentMembers
		previousSequence = record.SequenceID
		previousTimestamp = record.ServerTimestampNS
	}
	digest, associated, err := canonicalAssociationStateDigest(finalState, installationBytes)
	if err != nil {
		return AssociationObservation{}, ErrUnavailable
	}
	// observed_at_ms is the time this bridge completed a full authoritative
	// read and validation, not the last identity mutation time. Stable inboxes
	// must remain queryable; upstream event timestamps are only consistency
	// inputs checked above.
	now := reader.clock().UTC()
	if now.IsZero() || now.UnixMilli() < 0 ||
		uint64(now.UnixMilli()) > maxExactJSONInteger {
		return AssociationObservation{}, ErrUnavailable
	}
	lastMutation := time.Unix(
		int64(previousTimestamp/uint64(time.Second)),
		int64(previousTimestamp%uint64(time.Second)),
	).UTC()
	if lastMutation.After(now.Add(reader.maximumSkew)) {
		return AssociationObservation{}, ErrUnavailable
	}
	observedAtMS := uint64(now.UnixMilli())
	var associatedInbox *string
	if associated {
		value := inboxID
		associatedInbox = &value
	}
	return AssociationObservation{
		InstallationID: installationID, AssociatedInboxID: associatedInbox,
		Associated: associated, Revoked: !associated && removed, Fresh: true,
		StateDigest: digest, Position: strconv.FormatUint(previousSequence, 10),
		ObservedAtMS: observedAtMS,
	}, nil
}

func validatedAssociationTransition(
	previous map[string]struct{},
	state *associations.AssociationState,
	diff *associations.AssociationStateDiff,
) (map[string]struct{}, error) {
	current, err := associationStateMemberSet(state)
	if err != nil || diff == nil || hasUnknownFields(diff.ProtoReflect()) {
		return nil, ErrUnavailable
	}
	added, err := associationIdentifierSet(diff.NewMembers)
	if err != nil {
		return nil, ErrUnavailable
	}
	removed, err := associationIdentifierSet(diff.RemovedMembers)
	if err != nil || !associationDiffMatches(previous, current, added, removed) {
		return nil, ErrUnavailable
	}
	return current, nil
}

func associationStateMemberSet(
	state *associations.AssociationState,
) (map[string]struct{}, error) {
	if state == nil || !lowerHex32Pattern.MatchString(state.InboxId) ||
		hasUnknownFields(state.ProtoReflect()) {
		return nil, ErrUnavailable
	}
	result := make(map[string]struct{}, len(state.Members))
	for _, memberMap := range state.Members {
		if memberMap == nil || memberMap.Key == nil || memberMap.Value == nil ||
			memberMap.Value.Identifier == nil ||
			!proto.Equal(memberMap.Key, memberMap.Value.Identifier) {
			return nil, ErrUnavailable
		}
		key, err := associationIdentifierKey(memberMap.Key)
		if err != nil {
			return nil, ErrUnavailable
		}
		if _, duplicate := result[key]; duplicate {
			return nil, ErrUnavailable
		}
		result[key] = struct{}{}
	}
	return result, nil
}

func associationIdentifierSet(
	members []*associations.MemberIdentifier,
) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(members))
	for _, member := range members {
		key, err := associationIdentifierKey(member)
		if err != nil {
			return nil, ErrUnavailable
		}
		if _, duplicate := result[key]; duplicate {
			return nil, ErrUnavailable
		}
		result[key] = struct{}{}
	}
	return result, nil
}

func associationIdentifierKey(
	member *associations.MemberIdentifier,
) (string, error) {
	if member == nil || member.Kind == nil ||
		hasUnknownFields(member.ProtoReflect()) {
		return "", ErrUnavailable
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(member)
	if err != nil || len(encoded) == 0 {
		return "", ErrUnavailable
	}
	return string(encoded), nil
}

func associationDiffMatches(
	previous map[string]struct{},
	current map[string]struct{},
	added map[string]struct{},
	removed map[string]struct{},
) bool {
	expectedAdded := 0
	for key := range current {
		if _, existed := previous[key]; existed {
			continue
		}
		expectedAdded++
		if _, present := added[key]; !present {
			return false
		}
	}
	if len(added) != expectedAdded {
		return false
	}
	expectedRemoved := 0
	for key := range previous {
		if _, exists := current[key]; exists {
			continue
		}
		expectedRemoved++
		if _, present := removed[key]; !present {
			return false
		}
	}
	return len(removed) == expectedRemoved
}

func canonicalAssociationStateDigest(
	state *associations.AssociationState,
	installation []byte,
) (string, bool, error) {
	if state == nil || !lowerHex32Pattern.MatchString(state.InboxId) ||
		hasUnknownFields(state.ProtoReflect()) {
		return "", false, ErrUnavailable
	}
	cloned := proto.Clone(state).(*associations.AssociationState)
	type keyedMember struct {
		encoded []byte
		member  *associations.MemberMap
	}
	keyed := make([]keyedMember, 0, len(cloned.Members))
	associated := false
	seenKeys := make(map[string]struct{}, len(cloned.Members))
	for _, memberMap := range cloned.Members {
		if memberMap == nil || memberMap.Key == nil || memberMap.Value == nil ||
			memberMap.Value.Identifier == nil ||
			!proto.Equal(memberMap.Key, memberMap.Value.Identifier) {
			return "", false, ErrUnavailable
		}
		encodedKey, err := (proto.MarshalOptions{Deterministic: true}).Marshal(memberMap.Key)
		if err != nil {
			return "", false, ErrUnavailable
		}
		keyString := string(encodedKey)
		if _, duplicate := seenKeys[keyString]; duplicate {
			return "", false, ErrUnavailable
		}
		seenKeys[keyString] = struct{}{}
		if bytes.Equal(memberMap.Key.GetInstallationPublicKey(), installation) {
			associated = true
		}
		keyed = append(keyed, keyedMember{encoded: encodedKey, member: memberMap})
	}
	sort.Slice(keyed, func(left, right int) bool {
		return bytes.Compare(keyed[left].encoded, keyed[right].encoded) < 0
	})
	for index := range keyed {
		cloned.Members[index] = keyed[index].member
	}
	sort.Slice(cloned.SeenSignatures, func(left, right int) bool {
		return bytes.Compare(cloned.SeenSignatures[left], cloned.SeenSignatures[right]) < 0
	})
	for index := 1; index < len(cloned.SeenSignatures); index++ {
		if bytes.Equal(cloned.SeenSignatures[index-1], cloned.SeenSignatures[index]) {
			return "", false, ErrUnavailable
		}
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(cloned)
	if err != nil {
		return "", false, ErrUnavailable
	}
	input := make([]byte, 0, len(associationDigestContext)+8+len(encoded))
	input = append(input, associationDigestContext...)
	input = binary.BigEndian.AppendUint64(input, uint64(len(encoded)))
	input = append(input, encoded...)
	digest := sha256.Sum256(input)
	return hex.EncodeToString(digest[:]), associated, nil
}

func hasUnknownFields(message protoreflect.Message) bool {
	if !message.IsValid() || len(message.GetUnknown()) != 0 {
		return true
	}
	unknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Kind() != protoreflect.MessageKind && field.Kind() != protoreflect.GroupKind {
			return true
		}
		if field.IsList() {
			list := value.List()
			for index := 0; index < list.Len(); index++ {
				if hasUnknownFields(list.Get(index).Message()) {
					unknown = true
					return false
				}
			}
			return !unknown
		}
		if field.IsMap() {
			return true
		}
		unknown = hasUnknownFields(value.Message())
		return !unknown
	})
	return unknown
}

type AssociationOptions struct {
	Enabled        bool
	Environment    string
	BearerToken    string
	Reader         AssociationReader
	MaxConcurrency int
	RatePerSecond  int
	RateBurst      int
	RequestTimeout time.Duration
	Clock          func() time.Time
}

type AssociationHandler struct {
	enabled     bool
	environment string
	bearer      []byte
	reader      AssociationReader
	concurrency chan struct{}
	limiter     *fixedTokenBucket
	timeout     time.Duration
	clock       func() time.Time
}

func NewAssociationHandler(options AssociationOptions) (*AssociationHandler, error) {
	if !options.Enabled {
		return &AssociationHandler{}, nil
	}
	if (options.Environment != "dev" && options.Environment != "production") ||
		!validOpaqueBearer(options.BearerToken) || options.Reader == nil ||
		options.MaxConcurrency < 1 || options.MaxConcurrency > 64 ||
		options.RatePerSecond < 1 || options.RatePerSecond > 1000 ||
		options.RateBurst < 1 || options.RateBurst > 1000 ||
		options.RequestTimeout < time.Second || options.RequestTimeout > 30*time.Second {
		return nil, ErrConfiguration
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	return &AssociationHandler{
		enabled: true, environment: options.Environment,
		bearer: []byte(options.BearerToken), reader: options.Reader,
		concurrency: make(chan struct{}, options.MaxConcurrency),
		limiter:     newFixedTokenBucket(options.RatePerSecond, options.RateBurst, clock),
		timeout:     options.RequestTimeout, clock: clock,
	}, nil
}

func (handler *AssociationHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	defer func() {
		if recover() != nil {
			writeFixedJSONError(writer, http.StatusServiceUnavailable)
		}
	}()
	if handler == nil || !handler.enabled {
		writeFixedJSONError(writer, http.StatusNotFound)
		return
	}
	if !canonicalRequestTarget(request, AssociationPath) ||
		request.Method != http.MethodPost ||
		!singleHeaderEquals(request.Header, "Content-Type", "application/json") ||
		!singleHeaderEquals(request.Header, "Accept", "application/json") {
		writeFixedJSONError(writer, http.StatusUnauthorized)
		return
	}
	authorization, ok := singleHeader(request.Header, "Authorization")
	if !ok || !constantBearer(handler.bearer, authorization) {
		writeFixedJSONError(writer, http.StatusUnauthorized)
		return
	}
	if !handler.limiter.Allow(handler.clock().UTC()) {
		writeFixedJSONError(writer, http.StatusServiceUnavailable)
		return
	}
	select {
	case handler.concurrency <- struct{}{}:
		defer func() { <-handler.concurrency }()
	default:
		writeFixedJSONError(writer, http.StatusServiceUnavailable)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, maxAssociationBodyBytes+1))
	parsed, parseErr := a9trust.ParseStrictJSON(raw)
	object, objectOK := parsed.(map[string]any)
	if err != nil || parseErr != nil || len(raw) == 0 || len(raw) > maxAssociationBodyBytes ||
		!objectOK || !exactObjectFields(object, "environment", "inbox_id", "installation_id") {
		writeFixedJSONError(writer, http.StatusUnauthorized)
		return
	}
	environment, environmentOK := stringValue(object["environment"])
	inboxID, inboxOK := stringValue(object["inbox_id"])
	installationID, installationOK := stringValue(object["installation_id"])
	if !environmentOK || !inboxOK || !installationOK || environment != handler.environment ||
		!lowerHex32Pattern.MatchString(inboxID) || !lowerHex32Pattern.MatchString(installationID) {
		writeFixedJSONError(writer, http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	observation, err := handler.reader.ReadAssociation(ctx, inboxID, installationID)
	if err != nil || observation.InstallationID != installationID ||
		!observation.Fresh || observation.ObservedAtMS == 0 ||
		observation.Associated != (observation.AssociatedInboxID != nil) ||
		(observation.Associated && observation.Revoked) ||
		(observation.AssociatedInboxID != nil &&
			(!lowerHex32Pattern.MatchString(*observation.AssociatedInboxID) ||
				*observation.AssociatedInboxID != inboxID)) ||
		!lowerHex32Pattern.MatchString(observation.StateDigest) ||
		!validAssociationPosition(observation.Position) ||
		observation.ObservedAtMS > maxExactJSONInteger {
		writeFixedJSONError(writer, http.StatusServiceUnavailable)
		return
	}
	encoded, err := json.Marshal(struct {
		InstallationID    string  `json:"installation_id"`
		AssociatedInboxID *string `json:"associated_inbox_id"`
		Associated        bool    `json:"associated"`
		Revoked           bool    `json:"revoked"`
		Fresh             bool    `json:"fresh"`
		StateDigest       string  `json:"state_digest"`
		Position          string  `json:"position"`
		ObservedAtMS      uint64  `json:"observed_at_ms"`
	}{
		observation.InstallationID, observation.AssociatedInboxID,
		observation.Associated, observation.Revoked, observation.Fresh,
		observation.StateDigest, observation.Position, observation.ObservedAtMS,
	})
	if err != nil {
		writeFixedJSONError(writer, http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}

func validAssociationPosition(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && parsed > 0 && positionPattern.MatchString(value)
}

func (handler *AssociationHandler) Close() {
	if handler == nil {
		return
	}
	clear(handler.bearer)
	handler.enabled = false
}

func constantBearer(expected []byte, value string) bool {
	const prefix = "Bearer "
	if len(value) <= len(prefix) || value[:len(prefix)] != prefix {
		return false
	}
	candidate := []byte(value[len(prefix):])
	return len(candidate) == len(expected) && subtle.ConstantTimeCompare(candidate, expected) == 1
}

type identityUpdatesClient interface {
	GetIdentityUpdates(context.Context, *identityv1.GetIdentityUpdatesRequest, ...grpc.CallOption) (*identityv1.GetIdentityUpdatesResponse, error)
}

type GRPCIdentityHistorySource struct {
	client          identityUpdatesClient
	maxPages        int
	maxPageUpdates  int
	maxUpdates      int
	maxUpdateBytes  int
	maxHistoryBytes int
}

func NewGRPCIdentityHistorySource(
	client identityUpdatesClient,
	maxPages int,
	maxPageUpdates int,
	maxUpdates int,
	maxUpdateBytes int,
	maxHistoryBytes int,
) (*GRPCIdentityHistorySource, error) {
	if client == nil || maxPages < 1 || maxPages > 128 || maxPageUpdates < 1 ||
		maxPageUpdates > 1024 || maxUpdates < 1 || maxUpdates > 1024 ||
		maxPageUpdates > maxUpdates ||
		maxUpdateBytes < 256 || maxUpdateBytes > 1024*1024 ||
		maxHistoryBytes < maxUpdateBytes || maxHistoryBytes > 16*1024*1024 {
		return nil, ErrConfiguration
	}
	return &GRPCIdentityHistorySource{
		client: client, maxPages: maxPages,
		maxPageUpdates: maxPageUpdates, maxUpdates: maxUpdates,
		maxUpdateBytes: maxUpdateBytes, maxHistoryBytes: maxHistoryBytes,
	}, nil
}

func (source *GRPCIdentityHistorySource) CompleteHistory(
	ctx context.Context,
	inboxID string,
) ([]IdentityUpdateRecord, error) {
	if source == nil || !lowerHex32Pattern.MatchString(inboxID) {
		return nil, ErrUnavailable
	}
	result := make([]IdentityUpdateRecord, 0)
	historyBytes := 0
	var cursor uint64
	for page := 0; page < source.maxPages; page++ {
		response, err := source.client.GetIdentityUpdates(ctx, &identityv1.GetIdentityUpdatesRequest{
			Requests: []*identityv1.GetIdentityUpdatesRequest_Request{{InboxId: inboxID, SequenceId: cursor}},
		})
		if err != nil || response == nil ||
			hasUnknownFields(response.ProtoReflect()) {
			return nil, ErrUnavailable
		}
		// The pinned IdentityApi returns no response entry when a cursor has no
		// later updates. One echoed entry with an empty update list is also an
		// unambiguous terminal response.
		if len(response.Responses) == 0 {
			return result, nil
		}
		if len(response.Responses) != 1 || response.Responses[0] == nil ||
			response.Responses[0].InboxId != inboxID {
			return nil, ErrUnavailable
		}
		updates := response.Responses[0].Updates
		if len(updates) == 0 {
			return result, nil
		}
		if len(updates) > source.maxPageUpdates || len(result)+len(updates) > source.maxUpdates {
			return nil, ErrUnavailable
		}
		for _, update := range updates {
			if update == nil || update.Update == nil ||
				update.Update.InboxId != inboxID ||
				hasUnknownFields(update.ProtoReflect()) ||
				update.SequenceId <= cursor {
				return nil, ErrUnavailable
			}
			encodedUpdate, marshalErr := (proto.MarshalOptions{Deterministic: true}).
				Marshal(update.Update)
			if marshalErr != nil || len(encodedUpdate) > source.maxUpdateBytes ||
				historyBytes > source.maxHistoryBytes-len(encodedUpdate) {
				return nil, ErrUnavailable
			}
			historyBytes += len(encodedUpdate)
			cursor = update.SequenceId
			result = append(result, IdentityUpdateRecord{
				SequenceID: cursor, ServerTimestampNS: update.ServerTimestampNs,
				Update: proto.Clone(update.Update).(*associations.IdentityUpdate),
			})
		}
	}
	return nil, ErrUnavailable
}

type validationClient interface {
	GetAssociationState(context.Context, *validationv1.GetAssociationStateRequest, ...grpc.CallOption) (*validationv1.GetAssociationStateResponse, error)
}

type GRPCAssociationValidator struct{ client validationClient }

func NewGRPCAssociationValidator(client validationClient) (*GRPCAssociationValidator, error) {
	if client == nil {
		return nil, ErrConfiguration
	}
	return &GRPCAssociationValidator{client: client}, nil
}

func (validator *GRPCAssociationValidator) Validate(
	ctx context.Context,
	oldUpdates []*associations.IdentityUpdate,
	newUpdates []*associations.IdentityUpdate,
) (*validationv1.GetAssociationStateResponse, error) {
	if validator == nil || validator.client == nil || len(newUpdates) != 1 {
		return nil, ErrUnavailable
	}
	return validator.client.GetAssociationState(ctx, &validationv1.GetAssociationStateRequest{
		OldUpdates: oldUpdates, NewUpdates: newUpdates,
	})
}
