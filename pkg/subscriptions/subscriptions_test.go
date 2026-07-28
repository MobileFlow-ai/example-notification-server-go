package subscriptions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/testutils"
	topicutil "github.com/xmtp/example-notification-server-go/pkg/topics"
	topicpkg "github.com/xmtp/xmtpd/pkg/topic"
)

const INSTALLATION_ID = "installation_1"

// Valid V3 topic and its parsed form for testing
var TEST_TOPIC, _ = topicutil.ParseV3Topic("/xmtp/mls/1/g-24ce39d660600b3a98adff3075b6d1f4/proto")

type storedSubscription struct {
	ID             int64
	CreatedAt      time.Time
	InstallationID string
	Topic          []byte
	IsActive       bool
	IsSilent       bool
}

type storedHmacKey struct {
	Period int
	Key    []byte
}

func validHmacKey(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, sha256.Size)
}

func createService(t *testing.T, db *sql.DB) interfaces.Subscriptions {
	t.Helper()
	return NewSubscriptionsService(
		testutils.TestLogger(t),
		db,
	)
}

func fetchSubscriptions(t *testing.T, ctx context.Context, db *sql.DB, installationID string) []storedSubscription {
	t.Helper()

	rows, err := db.QueryContext(
		ctx,
		`SELECT id, created_at, installation_id, topic, is_active, is_silent
		 FROM subscriptions
		 WHERE installation_id = $1
		 ORDER BY id ASC`,
		installationID,
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, rows.Close())
	}()

	var results []storedSubscription
	for rows.Next() {
		var row storedSubscription
		require.NoError(t, rows.Scan(
			&row.ID,
			&row.CreatedAt,
			&row.InstallationID,
			&row.Topic,
			&row.IsActive,
			&row.IsSilent,
		))
		results = append(results, row)
	}
	require.NoError(t, rows.Err())

	return results
}

func fetchHmacKeys(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	installationID string,
	tp *topicpkg.Topic,
) []storedHmacKey {
	t.Helper()

	rows, err := db.QueryContext(
		ctx,
		`SELECT shk.thirty_day_periods_since_epoch, shk.key
		 FROM subscription_hmac_keys AS shk
		 JOIN subscriptions AS s ON s.id = shk.subscription_id
		 WHERE s.installation_id = $1 AND s.topic = $2
		 ORDER BY shk.thirty_day_periods_since_epoch`,
		installationID,
		tp.Bytes(),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, rows.Close())
	}()

	var results []storedHmacKey
	for rows.Next() {
		var row storedHmacKey
		require.NoError(t, rows.Scan(&row.Period, &row.Key))
		results = append(results, row)
	}
	require.NoError(t, rows.Err())
	return results
}

func Test_Subscribe(t *testing.T) {
	ctx := t.Context()
	db := testutils.CreateTestDb(t)

	svc := createService(t, db)

	err := svc.Subscribe(ctx, INSTALLATION_ID, []*topicpkg.Topic{TEST_TOPIC})
	require.NoError(t, err)

	stored := fetchSubscriptions(t, ctx, db, INSTALLATION_ID)
	require.Len(t, stored, 1)
	require.Equal(t, INSTALLATION_ID, stored[0].InstallationID)
	require.True(t, stored[0].IsActive)
	require.Equal(t, TEST_TOPIC.Bytes(), stored[0].Topic)
}

func Test_SubscribeMultiple(t *testing.T) {
	ctx := t.Context()
	db := testutils.CreateTestDb(t)
	svc := createService(t, db)

	topic1 := topicpkg.NewTopic(topicpkg.TopicKindGroupMessagesV1, []byte{0x01})
	topic2 := topicpkg.NewTopic(topicpkg.TopicKindGroupMessagesV1, []byte{0x02})
	topic3 := topicpkg.NewTopic(topicpkg.TopicKindGroupMessagesV1, []byte{0x03})
	topics := []*topicpkg.Topic{topic1, topic2, topic3}

	err := svc.Subscribe(ctx, INSTALLATION_ID, topics)
	require.NoError(t, err)

	stored := fetchSubscriptions(t, ctx, db, INSTALLATION_ID)
	require.Len(t, stored, 3)

	storedTopicBytes := make([][]byte, len(stored))
	for i, result := range stored {
		require.Equal(t, INSTALLATION_ID, result.InstallationID)
		require.NotZero(t, result.CreatedAt)
		storedTopicBytes[i] = result.Topic
	}
	for _, tp := range topics {
		require.Contains(t, storedTopicBytes, tp.Bytes())
	}
}

func Test_Unsubscribe(t *testing.T) {
	ctx := t.Context()
	db := testutils.CreateTestDb(t)
	svc := createService(t, db)

	err := svc.Subscribe(ctx, INSTALLATION_ID, []*topicpkg.Topic{TEST_TOPIC})
	require.NoError(t, err)

	err = svc.Unsubscribe(ctx, INSTALLATION_ID, []*topicpkg.Topic{TEST_TOPIC})
	require.NoError(t, err)

	stored := fetchSubscriptions(t, ctx, db, INSTALLATION_ID)
	require.Len(t, stored, 1)
	require.False(t, stored[0].IsActive)
}

func Test_UnsubscribeResubscribe(t *testing.T) {
	ctx := t.Context()
	db := testutils.CreateTestDb(t)
	svc := createService(t, db)

	require.NoError(t, svc.Subscribe(ctx, INSTALLATION_ID, []*topicpkg.Topic{TEST_TOPIC}))
	require.NoError(t, svc.Unsubscribe(ctx, INSTALLATION_ID, []*topicpkg.Topic{TEST_TOPIC}))
	require.NoError(t, svc.Subscribe(ctx, INSTALLATION_ID, []*topicpkg.Topic{TEST_TOPIC}))

	stored := fetchSubscriptions(t, ctx, db, INSTALLATION_ID)
	require.Len(t, stored, 1)
	require.True(t, stored[0].IsActive)
}

func Test_SubscribeWithMetadata(t *testing.T) {
	ctx := t.Context()
	db := testutils.CreateTestDb(t)
	svc := createService(t, db)

	key := validHmacKey(0x01)
	err := svc.SubscribeWithMetadata(ctx, INSTALLATION_ID, []interfaces.SubscriptionInput{{
		Topic:    TEST_TOPIC,
		IsSilent: true,
		HmacKeys: []interfaces.HmacKey{{
			ThirtyDayPeriodsSinceEpoch: 1,
			Key:                        key,
		}},
	}})
	require.NoError(t, err)

	results, err := svc.GetSubscriptions(ctx, TEST_TOPIC, 1)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, TEST_TOPIC.Kind(), results[0].TopicV4.Kind())
	require.Equal(t, TEST_TOPIC.Bytes(), results[0].TopicV4.Bytes())
	require.NotNil(t, results[0].HmacKey)
	require.NotNil(t, results[0].ExpectedHmacKeyPeriod)
	require.Equal(t, 1, *results[0].ExpectedHmacKeyPeriod)
	require.True(t, results[0].IsSilent)
	require.Equal(t, key, results[0].HmacKey.Key)
}

func Test_UpdateIsSilent(t *testing.T) {
	ctx := t.Context()
	db := testutils.CreateTestDb(t)
	svc := createService(t, db)

	require.NoError(t, svc.SubscribeWithMetadata(ctx, INSTALLATION_ID, []interfaces.SubscriptionInput{{
		Topic:    TEST_TOPIC,
		IsSilent: false,
	}}))

	results, err := svc.GetSubscriptions(ctx, TEST_TOPIC, 1)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.False(t, results[0].IsSilent)

	require.NoError(t, svc.SubscribeWithMetadata(ctx, INSTALLATION_ID, []interfaces.SubscriptionInput{{
		Topic:    TEST_TOPIC,
		IsSilent: true,
	}}))

	results, err = svc.GetSubscriptions(ctx, TEST_TOPIC, 1)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.True(t, results[0].IsSilent)
}

func Test_UpdateHmacKeys(t *testing.T) {
	ctx := t.Context()
	db := testutils.CreateTestDb(t)
	svc := createService(t, db)

	require.NoError(t, svc.SubscribeWithMetadata(ctx, INSTALLATION_ID, []interfaces.SubscriptionInput{{
		Topic:    TEST_TOPIC,
		IsSilent: true,
		HmacKeys: []interfaces.HmacKey{{
			ThirtyDayPeriodsSinceEpoch: 1,
			Key:                        validHmacKey(0x01),
		}},
	}}))

	require.NoError(t, svc.SubscribeWithMetadata(ctx, INSTALLATION_ID, []interfaces.SubscriptionInput{{
		Topic:    TEST_TOPIC,
		IsSilent: true,
		HmacKeys: []interfaces.HmacKey{{
			ThirtyDayPeriodsSinceEpoch: 1,
			Key:                        validHmacKey(0x02),
		}},
	}}))

	results, err := svc.GetSubscriptions(ctx, TEST_TOPIC, 1)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, validHmacKey(0x02), results[0].HmacKey.Key)
}

func Test_SubscribeWithMetadata_ReplacesHmacKeyPeriods(t *testing.T) {
	ctx := t.Context()
	db := testutils.CreateTestDb(t)
	svc := createService(t, db)

	require.NoError(t, svc.SubscribeWithMetadata(ctx, INSTALLATION_ID, []interfaces.SubscriptionInput{{
		Topic: TEST_TOPIC,
		HmacKeys: []interfaces.HmacKey{
			{ThirtyDayPeriodsSinceEpoch: 10, Key: validHmacKey(0x10)},
			{ThirtyDayPeriodsSinceEpoch: 11, Key: validHmacKey(0x11)},
		},
	}}))

	require.NoError(t, svc.SubscribeWithMetadata(ctx, INSTALLATION_ID, []interfaces.SubscriptionInput{{
		Topic: TEST_TOPIC,
		HmacKeys: []interfaces.HmacKey{
			{ThirtyDayPeriodsSinceEpoch: 11, Key: validHmacKey(0x21)},
			{ThirtyDayPeriodsSinceEpoch: 12, Key: validHmacKey(0x22)},
		},
	}}))

	require.Equal(t, []storedHmacKey{
		{Period: 11, Key: validHmacKey(0x21)},
		{Period: 12, Key: validHmacKey(0x22)},
	}, fetchHmacKeys(t, ctx, db, INSTALLATION_ID, TEST_TOPIC))

	stalePeriod, err := svc.GetSubscriptions(ctx, TEST_TOPIC, 10)
	require.NoError(t, err)
	require.Len(t, stalePeriod, 1)
	require.NotNil(t, stalePeriod[0].ExpectedHmacKeyPeriod)
	require.Equal(t, 10, *stalePeriod[0].ExpectedHmacKeyPeriod)
	require.Nil(t, stalePeriod[0].HmacKey)

	currentPeriod, err := svc.GetSubscriptions(ctx, TEST_TOPIC, 12)
	require.NoError(t, err)
	require.Len(t, currentPeriod, 1)
	require.NotNil(t, currentPeriod[0].HmacKey)
	require.Equal(t, validHmacKey(0x22), currentPeriod[0].HmacKey.Key)
}

func Test_SubscribeWithMetadata_EmptyKeySetClearsPriorPeriods(t *testing.T) {
	ctx := t.Context()
	db := testutils.CreateTestDb(t)
	svc := createService(t, db)

	require.NoError(t, svc.SubscribeWithMetadata(ctx, INSTALLATION_ID, []interfaces.SubscriptionInput{{
		Topic: TEST_TOPIC,
		HmacKeys: []interfaces.HmacKey{{
			ThirtyDayPeriodsSinceEpoch: 10,
			Key:                        validHmacKey(0x10),
		}},
	}}))
	require.NoError(t, svc.SubscribeWithMetadata(ctx, INSTALLATION_ID, []interfaces.SubscriptionInput{{
		Topic: TEST_TOPIC,
	}}))

	require.Empty(t, fetchHmacKeys(t, ctx, db, INSTALLATION_ID, TEST_TOPIC))
}

func Test_SubscribeWithMetadata_MalformedReplacementPreservesPriorKeys(t *testing.T) {
	ctx := t.Context()
	db := testutils.CreateTestDb(t)
	svc := createService(t, db)

	require.NoError(t, svc.SubscribeWithMetadata(ctx, INSTALLATION_ID, []interfaces.SubscriptionInput{{
		Topic: TEST_TOPIC,
		HmacKeys: []interfaces.HmacKey{{
			ThirtyDayPeriodsSinceEpoch: 10,
			Key:                        validHmacKey(0x10),
		}},
	}}))

	err := svc.SubscribeWithMetadata(ctx, INSTALLATION_ID, []interfaces.SubscriptionInput{{
		Topic: TEST_TOPIC,
		HmacKeys: []interfaces.HmacKey{{
			ThirtyDayPeriodsSinceEpoch: 11,
			Key:                        []byte("short"),
		}},
	}})
	require.ErrorContains(t, err, "malformed")
	require.Equal(t, []storedHmacKey{{
		Period: 10,
		Key:    validHmacKey(0x10),
	}}, fetchHmacKeys(t, ctx, db, INSTALLATION_ID, TEST_TOPIC))
}

func Test_SubscribeWithMetadata_RejectsDuplicateKeyPeriods(t *testing.T) {
	ctx := t.Context()
	db := testutils.CreateTestDb(t)
	svc := createService(t, db)

	err := svc.SubscribeWithMetadata(ctx, INSTALLATION_ID, []interfaces.SubscriptionInput{{
		Topic: TEST_TOPIC,
		HmacKeys: []interfaces.HmacKey{
			{ThirtyDayPeriodsSinceEpoch: 10, Key: validHmacKey(0x10)},
			{ThirtyDayPeriodsSinceEpoch: 10, Key: validHmacKey(0x11)},
		},
	}})
	require.ErrorContains(t, err, "duplicated")
	require.Empty(t, fetchSubscriptions(t, ctx, db, INSTALLATION_ID))
}

func Test_GetSubscriptions(t *testing.T) {
	ctx := t.Context()
	db := testutils.CreateTestDb(t)
	svc := createService(t, db)

	require.NoError(t, svc.Subscribe(ctx, INSTALLATION_ID, []*topicpkg.Topic{TEST_TOPIC}))

	subs, err := svc.GetSubscriptions(ctx, TEST_TOPIC, 1)
	require.NoError(t, err)
	require.Len(t, subs, 1)
}

func Test_SubscribeWithMetadata_NilTopic(t *testing.T) {
	ctx := t.Context()
	db := testutils.CreateTestDb(t)
	svc := createService(t, db)

	err := svc.SubscribeWithMetadata(ctx, INSTALLATION_ID, []interfaces.SubscriptionInput{{
		Topic:    nil,
		IsSilent: false,
	}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil")
}
