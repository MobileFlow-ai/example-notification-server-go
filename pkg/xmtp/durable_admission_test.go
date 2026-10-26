package xmtp

import (
	"context"
	"database/sql"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/mocks"
	"github.com/xmtp/example-notification-server-go/pkg/installations"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/notificationqueue"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/subscriptions"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
	v1 "github.com/xmtp/xmtpd/pkg/proto/message_api/v1"
	envelopesProto "github.com/xmtp/xmtpd/pkg/proto/xmtpv4/envelopes"
	notificationApi "github.com/xmtp/xmtpd/pkg/proto/xmtpv4/message_api"
	"github.com/xmtp/xmtpd/pkg/topic"
	"google.golang.org/grpc"
)

const admissionTestGroupTopic = "/xmtp/mls/1/g-24ce39d660600b3a98adff3075b6d1f4/proto"

type scriptedV3Stream struct {
	grpc.ClientStream
	frames []*v1.Envelope
}

func (s *scriptedV3Stream) Recv() (*v1.Envelope, error) {
	if len(s.frames) == 0 {
		return nil, io.EOF
	}
	frame := s.frames[0]
	s.frames = s.frames[1:]
	return frame, nil
}

type scriptedV4Stream struct {
	grpc.ClientStream
	responses []*notificationApi.SubscribeEnvelopesResponse
}

func (s *scriptedV4Stream) Recv() (*notificationApi.SubscribeEnvelopesResponse, error) {
	if len(s.responses) == 0 {
		return nil, io.EOF
	}
	response := s.responses[0]
	s.responses = s.responses[1:]
	return response, nil
}

type envelopeRow struct {
	key, status, class string
	payloadBytes       int
}

func queryEnvelopeRows(t *testing.T, ctx context.Context, db *sql.DB) map[string]envelopeRow {
	t.Helper()
	rows, err := db.QueryContext(ctx, "SELECT message_key, status, failure_class, octet_length(payload) FROM notification_envelopes")
	require.NoError(t, err)
	defer func() { require.NoError(t, rows.Close()) }()
	out := map[string]envelopeRow{}
	for rows.Next() {
		var row envelopeRow
		require.NoError(t, rows.Scan(&row.key, &row.status, &row.class, &row.payloadBytes))
		out[row.key] = row
	}
	require.NoError(t, rows.Err())
	return out
}

// The blocking defect: an envelope above the 2 MiB durable limit used to make
// persistEnvelope report a halt, which stopped the stream and, through the
// listener's deferred Stop, every durable worker. It must be recorded as
// metadata-only dead work and skipped while consumption continues.
func TestDurableAdmission_OversizedFrameIsSkippedV3(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	logger := testutils.TestLogger(t)
	installationsService := installations.NewInstallationsService(logger, db)
	subscriptionsService := subscriptions.NewSubscriptionsService(logger, db)
	l, err := NewListener(ctx, logger, options.XmtpOptions{GrpcAddress: "localhost:1", NumWorkers: 1}, installationsService, subscriptionsService, []interfaces.Delivery{mocks.NewDelivery(t)}, "test", "test")
	require.NoError(t, err)
	t.Cleanup(l.Stop)
	l.SetNotificationQueue(notificationqueue.New(db))
	now := time.Now()
	subscribeToTopic(t, l, INSTALLATION_ID, admissionTestGroupTopic, false, interfaces.HmacKey{
		ThirtyDayPeriodsSinceEpoch: int(now.Unix() / 60 / 60 / 24 / 30),
		Key:                        testHmacKey(0x11),
	})

	oversized := &v1.Envelope{ContentTopic: admissionTestGroupTopic, Message: make([]byte, notificationqueue.MaxEnvelopeBytes+1), TimestampNs: uint64(now.UnixNano())}
	normal := &v1.Envelope{ContentTopic: admissionTestGroupTopic, Message: []byte("ciphertext"), TimestampNs: uint64(now.UnixNano()) + 1}
	delay := time.Millisecond
	stopped := l.consumeMessageStream(&scriptedV3Stream{frames: []*v1.Envelope{oversized, normal}}, &delay)
	require.False(t, stopped, "an oversized frame must not stop the stream")
	require.NoError(t, l.ctx.Err(), "the listener and its durable workers must keep running")
	require.True(t, l.admissionReady.Load())

	rows := queryEnvelopeRows(t, ctx, db)
	require.Len(t, rows, 2)
	require.Equal(t, envelopeRow{key: buildIdempotencyKey(oversized), status: "dead", class: "oversized"}, rows[buildIdempotencyKey(oversized)])
	normalRow := rows[buildIdempotencyKey(normal)]
	require.Equal(t, "pending", normalRow.status)
	require.Positive(t, normalRow.payloadBytes)

	// A replay of the same oversized frame stays deduplicated and skipped.
	delay = time.Millisecond
	require.False(t, l.consumeMessageStream(&scriptedV3Stream{frames: []*v1.Envelope{oversized}}, &delay))
	require.Len(t, queryEnvelopeRows(t, ctx, db), 2)
}

func TestDurableAdmission_OversizedFrameIsSkippedV4(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	logger := testutils.TestLogger(t)
	installationsService := installations.NewInstallationsService(logger, db)
	subscriptionsService := subscriptions.NewSubscriptionsService(logger, db)
	l, err := NewV4Listener(ctx, logger, options.XmtpOptions{GrpcAddress: "localhost:1", NumWorkers: 1}, installationsService, subscriptionsService, []interfaces.Delivery{mocks.NewDelivery(t)}, "test", "test")
	require.NoError(t, err)
	t.Cleanup(l.Stop)
	l.SetNotificationQueue(notificationqueue.New(db))
	groupID := []byte{0x41, 0x42, 0x43, 0x44}
	groupTopic := topic.NewTopic(topic.TopicKindGroupMessagesV1, groupID)
	registerV4Installation(t, &V4Listener{installations: installationsService}, "inst", interfaces.PayloadFormatV4)
	subscribeV4ToTopic(t, &V4Listener{subscriptions: subscriptionsService}, "inst", groupTopic)

	oversized := buildGroupMessageOriginatorEnvelope(t, 1, 1, int64(time.Second), groupID, make([]byte, notificationqueue.MaxEnvelopeBytes+1), nil, true)
	normal := buildGroupMessageOriginatorEnvelope(t, 1, 2, int64(time.Second), groupID, []byte("data"), nil, true)
	delay := time.Millisecond
	stopped := l.consumeEnvelopeStream(&scriptedV4Stream{responses: []*notificationApi.SubscribeEnvelopesResponse{
		{Envelopes: []*envelopesProto.OriginatorEnvelope{oversized, normal}},
	}}, &delay)
	require.False(t, stopped, "an oversized envelope must not stop the stream")
	require.NoError(t, l.ctx.Err(), "the listener and its durable workers must keep running")
	require.True(t, l.admissionReady.Load())

	rows := queryEnvelopeRows(t, ctx, db)
	require.Len(t, rows, 2)
	require.Equal(t, envelopeRow{key: "1:1", status: "dead", class: "oversized"}, rows["1:1"])
	require.Equal(t, "pending", rows["1:2"].status)
	require.Positive(t, rows["1:2"].payloadBytes)
}

// A running listener keeps delivering after an oversized frame: the durable
// worker claims and completes the next envelope, and Failed never fires.
func TestDurableAdmission_WorkersKeepRunningAfterOversizedFrame(t *testing.T) {
	db := testutils.CreateTestDb(t)
	ctx := t.Context()
	logger := testutils.TestLogger(t)
	installationsService := installations.NewInstallationsService(logger, db)
	subscriptionsService := subscriptions.NewSubscriptionsService(logger, db)
	provider, sends := testutils.MockDeliveryWithSendCounter(t)
	l, err := NewV4Listener(ctx, logger, options.XmtpOptions{GrpcAddress: "localhost:1", NumWorkers: 1}, installationsService, subscriptionsService, []interfaces.Delivery{provider}, "test", "test")
	require.NoError(t, err)
	t.Cleanup(l.Stop)
	l.SetNotificationQueue(notificationqueue.New(db))
	groupID := []byte{0x51, 0x52, 0x53, 0x54}
	groupTopic := topic.NewTopic(topic.TopicKindGroupMessagesV1, groupID)
	registerV4Installation(t, &V4Listener{installations: installationsService}, "inst", interfaces.PayloadFormatV4)
	subscribeV4ToTopic(t, &V4Listener{subscriptions: subscriptionsService}, "inst", groupTopic)
	l.startEnvelopeWorkers()

	oversized := buildGroupMessageOriginatorEnvelope(t, 1, 1, int64(time.Second), groupID, make([]byte, notificationqueue.MaxEnvelopeBytes+1), nil, true)
	normal := buildGroupMessageOriginatorEnvelope(t, 1, 2, int64(time.Second), groupID, []byte("data"), nil, true)
	delay := time.Millisecond
	require.False(t, l.consumeEnvelopeStream(&scriptedV4Stream{responses: []*notificationApi.SubscribeEnvelopesResponse{
		{Envelopes: []*envelopesProto.OriginatorEnvelope{oversized}},
		{Envelopes: []*envelopesProto.OriginatorEnvelope{normal}},
	}}, &delay))
	require.Eventually(t, func() bool { return sends.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return queryEnvelopeRows(t, ctx, db)["1:2"].status == "complete" }, 5*time.Second, 10*time.Millisecond)
	select {
	case <-l.Failed():
		t.Fatal("an oversized frame must not fail the listener")
	default:
	}
	require.NoError(t, l.ctx.Err())
}
