package vault

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"io"
	"time"
)

const (
	defaultIncidentRoleTTL = 30 * time.Minute
	maxIncidentRoleTTL     = 2 * time.Hour

	accessStatePending  int16 = 1
	accessStateApproved int16 = 2
	accessStateExpired  int16 = 3
	accessStateRevoked  int16 = 4

	accessActionRequestCreated int16 = 1
	accessActionApproved       int16 = 2
	accessActionRevoked        int16 = 3
	accessActionApprovalDenied int16 = 4
	accessActionQueryBase      int16 = 100
	accessActionQueryFailure   int16 = 120
)

var (
	ErrIncidentAccessInvalid     = errors.New("incident access request invalid")
	ErrIncidentAccessDenied      = errors.New("incident access denied")
	ErrIncidentAccessUnavailable = errors.New("incident access unavailable")
	ErrIncidentQueryFailed       = errors.New("incident query failed")
)

type AccessPurpose int16

const (
	AccessPurposeIncidentResponse AccessPurpose = 1
)

type AccessDataClass int16

const (
	AccessDataClassRawVault AccessDataClass = 1
)

type IncidentHypothesis int16

const (
	IncidentHypothesisMissingDelivery  IncidentHypothesis = 1
	IncidentHypothesisSpuriousDelivery IncidentHypothesis = 2
	IncidentHypothesisRetentionFailure IncidentHypothesis = 3
)

type RawVaultQueryKind int16

const (
	RawVaultQueryInstallation RawVaultQueryKind = 1
	RawVaultQueryLease        RawVaultQueryKind = 2
	RawVaultQueryDeliveryJob  RawVaultQueryKind = 3
)

type AccessRequestID [16]byte

type IncidentOversightNotice struct {
	Purpose            AccessPurpose
	DataClass          AccessDataClass
	CoarseApprovedHour time.Time
}

type IncidentOversightBroadcast func(
	ctx context.Context,
	notice IncidentOversightNotice,
) error

type IncidentAccessOptions struct {
	Environment         string
	RoleTTL             time.Duration
	Now                 func() time.Time
	Random              io.Reader
	AuthorizedApprovers []string
	Broadcast           IncidentOversightBroadcast
}

type IncidentAccessGate struct {
	db                  *sql.DB
	environmentID       int16
	roleTTL             time.Duration
	now                 func() time.Time
	random              io.Reader
	authorizedApprovers map[string]struct{}
	broadcast           IncidentOversightBroadcast
}

type CreateIncidentAccessRequest struct {
	RequesterActor  string
	TicketReference string
	Hypothesis      IncidentHypothesis
	WindowStart     time.Time
	WindowEnd       time.Time
	Purpose         AccessPurpose
	DataClass       AccessDataClass
}

type IncidentAccessStatus struct {
	RequestID     AccessRequestID
	State         int16
	CoarseCreated time.Time
	RoleExpiresAt *time.Time
}

type IncidentApproval struct {
	RequestID AccessRequestID
	Actor     string
}

type RawVaultAccessRequest struct {
	RequestID AccessRequestID
	Actor     string
	Purpose   AccessPurpose
	DataClass AccessDataClass
	QueryKind RawVaultQueryKind
	Target    []byte
}

type RawVaultInstallationSnapshot struct {
	EncryptedAPNSToken []byte
	State              int16
	PolicyEpoch        int64
	CreatedAt          time.Time
	RefreshedAt        time.Time
	ExpiresAt          time.Time
	ControlExpiresAt   time.Time
}

type RawVaultLeaseSnapshot struct {
	EncryptedTopic             []byte
	EncryptedRouteKey          []byte
	EncryptedHMACKeys          []byte
	EncryptedReceiveCapability []byte
	EncryptedNonceState        []byte
	State                      int16
	PolicyEpoch                int64
	RouteKeyEpoch              int64
	IssuedAt                   time.Time
	RefreshedAt                time.Time
	ExpiresAt                  time.Time
	ControlExpiresAt           time.Time
}

type RawVaultDeliveryJobSnapshot struct {
	EncryptedJob []byte
	State        int16
	Attempts     int16
	AvailableAt  time.Time
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// RawVaultQueryResult contains one fully materialized allowlisted snapshot or
// nil when the approved target did not overlap the approved time window. The
// exact 0/1 count is converted to a coarse bucket in the audit trail.
type RawVaultQueryResult struct {
	Value       any
	ResultCount int
}

func NewIncidentAccessGate(
	db *sql.DB,
	options IncidentAccessOptions,
) (*IncidentAccessGate, error) {
	environmentID, environmentErr := encodeEnvironment(options.Environment)
	if db == nil ||
		options.Broadcast == nil ||
		len(options.AuthorizedApprovers) == 0 ||
		environmentErr != nil {
		return nil, ErrIncidentAccessInvalid
	}
	authorizedApprovers := make(
		map[string]struct{},
		len(options.AuthorizedApprovers),
	)
	for _, actor := range options.AuthorizedApprovers {
		if !validActorID(actor) {
			return nil, ErrIncidentAccessInvalid
		}
		if _, duplicate := authorizedApprovers[actor]; duplicate {
			return nil, ErrIncidentAccessInvalid
		}
		authorizedApprovers[actor] = struct{}{}
	}
	roleTTL := options.RoleTTL
	if roleTTL == 0 {
		roleTTL = defaultIncidentRoleTTL
	}
	if roleTTL <= 0 || roleTTL > maxIncidentRoleTTL {
		return nil, ErrIncidentAccessInvalid
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	return &IncidentAccessGate{
		db:                  db,
		environmentID:       environmentID,
		roleTTL:             roleTTL,
		now:                 now,
		random:              random,
		authorizedApprovers: authorizedApprovers,
		broadcast:           options.Broadcast,
	}, nil
}

func (g *IncidentAccessGate) CreateRequest(
	ctx context.Context,
	request CreateIncidentAccessRequest,
) (*IncidentAccessStatus, error) {
	if g == nil ||
		!validActorID(request.RequesterActor) ||
		!validTicketReference(request.TicketReference) ||
		!validIncidentHypothesis(request.Hypothesis) ||
		!validIncidentWindow(
			request.WindowStart,
			request.WindowEnd,
			g.now().UTC(),
		) ||
		request.Purpose != AccessPurposeIncidentResponse ||
		request.DataClass != AccessDataClassRawVault {
		return nil, ErrIncidentAccessInvalid
	}
	requestID, err := g.randomID()
	if err != nil {
		return nil, err
	}
	now := g.now().UTC()
	coarseCreated := coarseHour(now)

	tx, err := g.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, ErrIncidentAccessUnavailable
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err = tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.access_requests (
		     request_id, environment, purpose, data_class, requester_actor,
		     ticket_reference, hypothesis, window_start, window_end,
		     approver_actor, oversight_broadcast_hour,
		     coarse_created_hour, role_expires_at, state
		 ) VALUES (
		     $1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,NULL,$10,NULL,$11
		 )`,
		requestID[:],
		g.environmentID,
		int16(request.Purpose),
		int16(request.DataClass),
		request.RequesterActor,
		request.TicketReference,
		int16(request.Hypothesis),
		request.WindowStart.UTC(),
		request.WindowEnd.UTC(),
		coarseCreated,
		accessStatePending,
	); err != nil {
		return nil, ErrIncidentAccessUnavailable
	}
	if err = g.insertAudit(
		ctx,
		tx,
		requestID,
		request.RequesterActor,
		request.Purpose,
		request.DataClass,
		accessActionRequestCreated,
		0,
		now,
	); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, ErrIncidentAccessUnavailable
	}
	return &IncidentAccessStatus{
		RequestID:     requestID,
		State:         accessStatePending,
		CoarseCreated: coarseCreated,
	}, nil
}

func (g *IncidentAccessGate) Approve(
	ctx context.Context,
	approval IncidentApproval,
) (*IncidentAccessStatus, error) {
	if g == nil ||
		zeroRequestID(approval.RequestID) ||
		!validActorID(approval.Actor) {
		return nil, ErrIncidentAccessInvalid
	}
	now := g.now().UTC()
	tx, err := g.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, ErrIncidentAccessUnavailable
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row, err := loadAccessRequestForUpdate(
		ctx,
		tx,
		approval.RequestID,
		g.environmentID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIncidentAccessDenied
	}
	if err != nil {
		return nil, ErrIncidentAccessUnavailable
	}
	if !validStoredAccessRequest(row) {
		return nil, ErrIncidentAccessUnavailable
	}
	if now.Before(row.coarseCreated) ||
		!now.Before(row.coarseCreated.Add(maxIncidentRoleTTL)) ||
		row.state == accessStateExpired ||
		row.state == accessStateRevoked {
		return nil, g.commitDeniedApproval(ctx, tx, row, approval, now)
	}
	if row.state == accessStateApproved {
		if !row.roleExpires.Valid ||
			!now.Before(row.roleExpires.Time) ||
			row.approverActor != approval.Actor {
			return nil, g.commitDeniedApproval(ctx, tx, row, approval, now)
		}
		if err = tx.Commit(); err != nil {
			return nil, ErrIncidentAccessUnavailable
		}
		expiry := row.roleExpires.Time.UTC()
		return &IncidentAccessStatus{
			RequestID:     approval.RequestID,
			State:         row.state,
			CoarseCreated: row.coarseCreated,
			RoleExpiresAt: &expiry,
		}, nil
	}
	if approval.Actor == row.requesterActor {
		return nil, g.commitDeniedApproval(ctx, tx, row, approval, now)
	}
	if _, authorized := g.authorizedApprovers[approval.Actor]; !authorized {
		return nil, g.commitDeniedApproval(ctx, tx, row, approval, now)
	}
	if row.approverActor != "" || row.oversightBroadcast.Valid {
		return nil, ErrIncidentAccessUnavailable
	}

	expiry := now.Add(g.roleTTL)
	maxExpiry := row.coarseCreated.Add(maxIncidentRoleTTL)
	if expiry.After(maxExpiry) {
		expiry = maxExpiry
	}
	if !expiry.After(now) {
		return nil, g.commitDeniedApproval(ctx, tx, row, approval, now)
	}
	expiry = expiry.UTC()
	broadcastHour := coarseHour(now)
	if err = g.broadcast(
		ctx,
		IncidentOversightNotice{
			Purpose:            row.purpose,
			DataClass:          row.dataClass,
			CoarseApprovedHour: broadcastHour,
		},
	); err != nil {
		return nil, ErrIncidentAccessUnavailable
	}
	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.access_requests
		 SET approver_actor = $2,
		     oversight_broadcast_hour = $3,
		     role_expires_at = $4,
		     state = $5
		 WHERE request_id = $1
		   AND environment = $6`,
		approval.RequestID[:],
		approval.Actor,
		broadcastHour,
		expiry,
		accessStateApproved,
		g.environmentID,
	); err != nil {
		return nil, ErrIncidentAccessUnavailable
	}
	if err = g.insertAudit(
		ctx,
		tx,
		approval.RequestID,
		approval.Actor,
		row.purpose,
		row.dataClass,
		accessActionApproved,
		0,
		now,
	); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, ErrIncidentAccessUnavailable
	}
	return &IncidentAccessStatus{
		RequestID:     approval.RequestID,
		State:         accessStateApproved,
		CoarseCreated: row.coarseCreated,
		RoleExpiresAt: &expiry,
	}, nil
}

func (g *IncidentAccessGate) Revoke(
	ctx context.Context,
	requestID AccessRequestID,
	actor string,
) error {
	if g == nil || zeroRequestID(requestID) || !validActorID(actor) {
		return ErrIncidentAccessInvalid
	}
	now := g.now().UTC()
	tx, err := g.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ErrIncidentAccessUnavailable
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row, err := loadAccessRequestForUpdate(
		ctx,
		tx,
		requestID,
		g.environmentID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIncidentAccessDenied
	}
	if err != nil {
		return ErrIncidentAccessUnavailable
	}
	if !validStoredAccessRequest(row) {
		return ErrIncidentAccessUnavailable
	}
	if actor != row.requesterActor &&
		actor != row.approverActor {
		return ErrIncidentAccessDenied
	}
	if _, err = tx.ExecContext(
		ctx,
		`UPDATE hytch_push_vault.access_requests
		 SET role_expires_at = NULL, state = $2
		 WHERE request_id = $1
		   AND environment = $3`,
		requestID[:],
		accessStateRevoked,
		g.environmentID,
	); err != nil {
		return ErrIncidentAccessUnavailable
	}
	if err = g.insertAudit(
		ctx,
		tx,
		requestID,
		actor,
		row.purpose,
		row.dataClass,
		accessActionRevoked,
		0,
		now,
	); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return ErrIncidentAccessUnavailable
	}
	return nil
}

// WithAuthorizedRawVaultQuery holds the access-request row locked while one
// fixed typed lookup runs in a separate database-enforced read-only
// transaction. The result is returned only after its coarse audit record
// commits.
func (g *IncidentAccessGate) WithAuthorizedRawVaultQuery(
	ctx context.Context,
	request RawVaultAccessRequest,
) (RawVaultQueryResult, error) {
	var empty RawVaultQueryResult
	if g == nil ||
		zeroRequestID(request.RequestID) ||
		!validActorID(request.Actor) ||
		request.Purpose != AccessPurposeIncidentResponse ||
		request.DataClass != AccessDataClassRawVault ||
		!validRawVaultQueryKind(request.QueryKind) ||
		!validRawVaultTarget(request.QueryKind, request.Target) {
		return empty, ErrIncidentAccessInvalid
	}
	now := g.now().UTC()
	authorizationTx, err := g.db.BeginTx(
		ctx,
		&sql.TxOptions{Isolation: sql.LevelSerializable},
	)
	if err != nil {
		return empty, ErrIncidentAccessUnavailable
	}
	defer func() {
		_ = authorizationTx.Rollback()
	}()

	row, err := loadAccessRequestForUpdate(
		ctx,
		authorizationTx,
		request.RequestID,
		g.environmentID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, ErrIncidentAccessDenied
	}
	if err != nil {
		return empty, ErrIncidentAccessUnavailable
	}
	if !validStoredAccessRequest(row) {
		return empty, ErrIncidentAccessUnavailable
	}
	if row.state != accessStateApproved ||
		!row.roleExpires.Valid ||
		!now.Before(row.roleExpires.Time) ||
		now.Before(row.coarseCreated) ||
		request.Actor != row.requesterActor ||
		request.Purpose != row.purpose ||
		request.DataClass != row.dataClass {
		return empty, g.commitDeniedQuery(
			ctx,
			authorizationTx,
			row,
			request,
			now,
		)
	}

	readTx, err := g.db.BeginTx(
		ctx,
		&sql.TxOptions{
			Isolation: sql.LevelRepeatableRead,
			ReadOnly:  true,
		},
	)
	if err != nil {
		return empty, g.commitFailedQuery(
			ctx,
			authorizationTx,
			row,
			request,
			now,
			ErrIncidentAccessUnavailable,
		)
	}
	defer func() {
		_ = readTx.Rollback()
	}()
	result, queryErr := executeRawVaultQuery(
		ctx,
		readTx,
		request.QueryKind,
		request.Target,
		g.environmentID,
		row.windowStart,
		row.windowEnd,
	)
	if queryErr != nil {
		_ = readTx.Rollback()
		return empty, g.commitFailedQuery(
			ctx,
			authorizationTx,
			row,
			request,
			g.now().UTC(),
			ErrIncidentQueryFailed,
		)
	}
	completedAt := g.now().UTC()
	if !completedAt.Before(row.roleExpires.Time) {
		_ = readTx.Rollback()
		return empty, g.commitDeniedQuery(
			ctx,
			authorizationTx,
			row,
			request,
			completedAt,
		)
	}
	if err = readTx.Commit(); err != nil {
		return empty, g.commitFailedQuery(
			ctx,
			authorizationTx,
			row,
			request,
			completedAt,
			ErrIncidentQueryFailed,
		)
	}
	if err = g.insertAudit(
		ctx,
		authorizationTx,
		request.RequestID,
		request.Actor,
		row.purpose,
		row.dataClass,
		querySuccessAction(request.QueryKind),
		resultCountBucket(result.ResultCount),
		completedAt,
	); err != nil {
		return empty, err
	}
	if err = authorizationTx.Commit(); err != nil {
		return empty, ErrIncidentAccessUnavailable
	}
	return result, nil
}

type accessRequestRow struct {
	purpose            AccessPurpose
	dataClass          AccessDataClass
	requesterActor     string
	ticketReference    string
	hypothesis         IncidentHypothesis
	windowStart        time.Time
	windowEnd          time.Time
	approverActor      string
	oversightBroadcast sql.NullTime
	coarseCreated      time.Time
	roleExpires        sql.NullTime
	state              int16
}

func loadAccessRequestForUpdate(
	ctx context.Context,
	tx *sql.Tx,
	requestID AccessRequestID,
	environmentID int16,
) (*accessRequestRow, error) {
	row := &accessRequestRow{}
	var approverActor sql.NullString
	err := tx.QueryRowContext(
		ctx,
		`SELECT purpose, data_class, requester_actor,
		        ticket_reference, hypothesis, window_start, window_end,
		        approver_actor, oversight_broadcast_hour,
		        coarse_created_hour, role_expires_at, state
		 FROM hytch_push_vault.access_requests
		 WHERE request_id = $1
		   AND environment = $2
		 FOR UPDATE`,
		requestID[:],
		environmentID,
	).Scan(
		&row.purpose,
		&row.dataClass,
		&row.requesterActor,
		&row.ticketReference,
		&row.hypothesis,
		&row.windowStart,
		&row.windowEnd,
		&approverActor,
		&row.oversightBroadcast,
		&row.coarseCreated,
		&row.roleExpires,
		&row.state,
	)
	if err != nil {
		return nil, err
	}
	if approverActor.Valid {
		row.approverActor = approverActor.String
	}
	row.coarseCreated = row.coarseCreated.UTC()
	row.windowStart = row.windowStart.UTC()
	row.windowEnd = row.windowEnd.UTC()
	if row.oversightBroadcast.Valid {
		row.oversightBroadcast.Time =
			row.oversightBroadcast.Time.UTC()
	}
	return row, nil
}

func (g *IncidentAccessGate) commitDeniedApproval(
	ctx context.Context,
	tx *sql.Tx,
	row *accessRequestRow,
	approval IncidentApproval,
	now time.Time,
) error {
	if row.state != accessStateRevoked &&
		(!now.Before(row.coarseCreated.Add(maxIncidentRoleTTL)) ||
			(row.state == accessStateApproved &&
				(!row.roleExpires.Valid ||
					!now.Before(row.roleExpires.Time)))) {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE hytch_push_vault.access_requests
			 SET role_expires_at = NULL, state = $2
			 WHERE request_id = $1
			   AND environment = $3`,
			approval.RequestID[:],
			accessStateExpired,
			g.environmentID,
		); err != nil {
			return ErrIncidentAccessUnavailable
		}
	}
	if err := g.insertAudit(
		ctx,
		tx,
		approval.RequestID,
		approval.Actor,
		row.purpose,
		row.dataClass,
		accessActionApprovalDenied,
		0,
		now,
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrIncidentAccessUnavailable
	}
	return ErrIncidentAccessDenied
}

func (g *IncidentAccessGate) commitDeniedQuery(
	ctx context.Context,
	tx *sql.Tx,
	row *accessRequestRow,
	request RawVaultAccessRequest,
	now time.Time,
) error {
	if row.state == accessStateApproved &&
		(!row.roleExpires.Valid || !now.Before(row.roleExpires.Time)) {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE hytch_push_vault.access_requests
			 SET role_expires_at = NULL, state = $2
			 WHERE request_id = $1
			   AND environment = $3`,
			request.RequestID[:],
			accessStateExpired,
			g.environmentID,
		); err != nil {
			return ErrIncidentAccessUnavailable
		}
	}
	if err := g.insertAudit(
		ctx,
		tx,
		request.RequestID,
		request.Actor,
		row.purpose,
		row.dataClass,
		queryFailureAction(request.QueryKind),
		0,
		now,
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrIncidentAccessUnavailable
	}
	return ErrIncidentAccessDenied
}

func (g *IncidentAccessGate) commitFailedQuery(
	ctx context.Context,
	tx *sql.Tx,
	row *accessRequestRow,
	request RawVaultAccessRequest,
	now time.Time,
	fixedError error,
) error {
	if err := g.insertAudit(
		ctx,
		tx,
		request.RequestID,
		request.Actor,
		row.purpose,
		row.dataClass,
		queryFailureAction(request.QueryKind),
		0,
		now,
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrIncidentAccessUnavailable
	}
	return fixedError
}

func (g *IncidentAccessGate) insertAudit(
	ctx context.Context,
	tx *sql.Tx,
	requestID AccessRequestID,
	actor string,
	purpose AccessPurpose,
	dataClass AccessDataClass,
	action int16,
	resultBucket int16,
	now time.Time,
) error {
	eventID, err := g.randomID()
	if err != nil {
		return err
	}
	coarseEvent := coarseHour(now.UTC())
	expiresOn := coarseEvent.AddDate(0, 0, 180)
	if _, err = tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.access_audit (
		     event_id, request_id, environment, actor, purpose, data_class,
		     coarse_event_hour, action, result_count_bucket, expires_on
		 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::date)`,
		eventID[:],
		requestID[:],
		g.environmentID,
		actor,
		int16(purpose),
		int16(dataClass),
		coarseEvent,
		action,
		resultBucket,
		expiresOn,
	); err != nil {
		return ErrIncidentAccessUnavailable
	}
	return nil
}

func (g *IncidentAccessGate) randomID() (AccessRequestID, error) {
	var id AccessRequestID
	if g == nil || g.random == nil {
		return id, ErrIncidentAccessUnavailable
	}
	if _, err := io.ReadFull(g.random, id[:]); err != nil {
		return AccessRequestID{}, ErrIncidentAccessUnavailable
	}
	if zeroRequestID(id) {
		return AccessRequestID{}, ErrIncidentAccessUnavailable
	}
	return id, nil
}

func executeRawVaultQuery(
	ctx context.Context,
	tx *sql.Tx,
	kind RawVaultQueryKind,
	target []byte,
	environmentID int16,
	windowStart time.Time,
	windowEnd time.Time,
) (RawVaultQueryResult, error) {
	var result RawVaultQueryResult
	if tx == nil ||
		(environmentID != environmentDevelopment &&
			environmentID != environmentProduction) ||
		!validRawVaultTarget(kind, target) ||
		!windowEnd.After(windowStart) {
		return result, ErrIncidentQueryFailed
	}
	switch kind {
	case RawVaultQueryInstallation:
		snapshot := &RawVaultInstallationSnapshot{}
		err := tx.QueryRowContext(
			ctx,
			`SELECT encrypted_apns_token, state, policy_epoch,
			        created_at, refreshed_at, expires_at,
			        control_expires_at
			   FROM hytch_push_vault.installation_states
			  WHERE installation_lookup = $1
			    AND environment = $2
			    AND created_at < $4
			    AND expires_at > $3`,
			target,
			environmentID,
			windowStart.UTC(),
			windowEnd.UTC(),
		).Scan(
			&snapshot.EncryptedAPNSToken,
			&snapshot.State,
			&snapshot.PolicyEpoch,
			&snapshot.CreatedAt,
			&snapshot.RefreshedAt,
			&snapshot.ExpiresAt,
			&snapshot.ControlExpiresAt,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return result, nil
		}
		if err != nil {
			return result, ErrIncidentQueryFailed
		}
		result.Value = snapshot
		result.ResultCount = 1
	case RawVaultQueryLease:
		snapshot := &RawVaultLeaseSnapshot{}
		err := tx.QueryRowContext(
			ctx,
			`SELECT encrypted_topic, encrypted_route_key,
			        encrypted_hmac_keys, encrypted_receive_capability,
			        encrypted_nonce_state, state, policy_epoch,
			        route_key_epoch, issued_at, refreshed_at,
			        expires_at, control_expires_at
			   FROM hytch_push_vault.subscription_leases
			  WHERE lease_id = $1
			    AND environment = $2
			    AND issued_at < $4
			    AND expires_at > $3`,
			target,
			environmentID,
			windowStart.UTC(),
			windowEnd.UTC(),
		).Scan(
			&snapshot.EncryptedTopic,
			&snapshot.EncryptedRouteKey,
			&snapshot.EncryptedHMACKeys,
			&snapshot.EncryptedReceiveCapability,
			&snapshot.EncryptedNonceState,
			&snapshot.State,
			&snapshot.PolicyEpoch,
			&snapshot.RouteKeyEpoch,
			&snapshot.IssuedAt,
			&snapshot.RefreshedAt,
			&snapshot.ExpiresAt,
			&snapshot.ControlExpiresAt,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return result, nil
		}
		if err != nil {
			return result, ErrIncidentQueryFailed
		}
		result.Value = snapshot
		result.ResultCount = 1
	case RawVaultQueryDeliveryJob:
		snapshot := &RawVaultDeliveryJobSnapshot{}
		err := tx.QueryRowContext(
			ctx,
			`SELECT encrypted_job, state, attempts, available_at,
			        created_at, expires_at
			   FROM hytch_push_vault.delivery_jobs
			  WHERE job_id = $1
			    AND environment = $2
			    AND created_at < $4
			    AND expires_at > $3`,
			target,
			environmentID,
			windowStart.UTC(),
			windowEnd.UTC(),
		).Scan(
			&snapshot.EncryptedJob,
			&snapshot.State,
			&snapshot.Attempts,
			&snapshot.AvailableAt,
			&snapshot.CreatedAt,
			&snapshot.ExpiresAt,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return result, nil
		}
		if err != nil {
			return result, ErrIncidentQueryFailed
		}
		result.Value = snapshot
		result.ResultCount = 1
	default:
		return result, ErrIncidentQueryFailed
	}
	return result, nil
}

func validStoredAccessRequest(row *accessRequestRow) bool {
	if row == nil ||
		row.purpose != AccessPurposeIncidentResponse ||
		row.dataClass != AccessDataClassRawVault ||
		!validActorID(row.requesterActor) ||
		!validTicketReference(row.ticketReference) ||
		!validIncidentHypothesis(row.hypothesis) ||
		!validIncidentWindow(
			row.windowStart,
			row.windowEnd,
			row.coarseCreated.Add(time.Hour),
		) ||
		(row.approverActor != "" && !validActorID(row.approverActor)) ||
		(row.approverActor != "" &&
			row.approverActor == row.requesterActor) ||
		row.state < accessStatePending ||
		row.state > accessStateRevoked {
		return false
	}
	switch row.state {
	case accessStatePending:
		if row.roleExpires.Valid ||
			row.approverActor != "" ||
			row.oversightBroadcast.Valid {
			return false
		}
	case accessStateApproved:
		if row.approverActor == "" ||
			!row.oversightBroadcast.Valid ||
			!row.oversightBroadcast.Time.Equal(
				coarseHour(row.oversightBroadcast.Time),
			) ||
			!row.roleExpires.Valid ||
			!row.roleExpires.Time.After(row.coarseCreated) ||
			row.roleExpires.Time.After(
				row.coarseCreated.Add(maxIncidentRoleTTL),
			) {
			return false
		}
	case accessStateExpired, accessStateRevoked:
		if row.roleExpires.Valid ||
			(row.approverActor == "") !=
				(!row.oversightBroadcast.Valid) {
			return false
		}
	}
	return true
}

func validActorID(actor string) bool {
	if len(actor) < 8 || len(actor) > 128 {
		return false
	}
	for _, character := range actor {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '-', character == '_', character == '.', character == ':':
		default:
			return false
		}
	}
	return true
}

// ValidIncidentActorID exposes the same fixed actor-ID grammar used by the
// incident gate so authentication configuration cannot accept an identity
// that the authorization layer will later reject.
func ValidIncidentActorID(actor string) bool {
	return validActorID(actor)
}

func validTicketReference(reference string) bool {
	return validActorID(reference)
}

func validIncidentHypothesis(hypothesis IncidentHypothesis) bool {
	return hypothesis >= IncidentHypothesisMissingDelivery &&
		hypothesis <= IncidentHypothesisRetentionFailure
}

func validIncidentWindow(
	start time.Time,
	end time.Time,
	now time.Time,
) bool {
	start = start.UTC()
	end = end.UTC()
	now = now.UTC()
	return !start.IsZero() &&
		!end.IsZero() &&
		end.After(start) &&
		end.Sub(start) <= 2*time.Hour &&
		!start.Before(now.Add(-8*24*time.Hour)) &&
		!end.After(now.Add(5*time.Minute))
}

func validRawVaultQueryKind(kind RawVaultQueryKind) bool {
	return kind >= RawVaultQueryInstallation &&
		kind <= RawVaultQueryDeliveryJob
}

func validRawVaultTarget(
	kind RawVaultQueryKind,
	target []byte,
) bool {
	switch kind {
	case RawVaultQueryInstallation:
		return len(target) == 32
	case RawVaultQueryLease, RawVaultQueryDeliveryJob:
		return len(target) == 16
	default:
		return false
	}
}

func zeroRequestID(id AccessRequestID) bool {
	var aggregate byte
	for _, value := range id {
		aggregate |= value
	}
	return aggregate == 0
}

func coarseHour(value time.Time) time.Time {
	return value.UTC().Truncate(time.Hour)
}

func resultCountBucket(count int) int16 {
	switch {
	case count <= 0:
		return 0
	case count == 1:
		return 1
	case count <= 4:
		return 2
	case count <= 16:
		return 3
	case count <= 64:
		return 4
	default:
		return 5
	}
}

func querySuccessAction(kind RawVaultQueryKind) int16 {
	return accessActionQueryBase + int16(kind)
}

func queryFailureAction(kind RawVaultQueryKind) int16 {
	return accessActionQueryFailure + int16(kind)
}
