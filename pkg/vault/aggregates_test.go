package vault

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRandomizedAggregatePromotionUsesRoundedProbabilityBuckets(
	t *testing.T,
) {
	tests := []struct {
		name    string
		bucket  int16
		draw    []byte
		promote bool
	}{
		{
			name:    "bucket one promotes below half range",
			bucket:  1,
			draw:    []byte{0x7f, 0xff},
			promote: true,
		},
		{
			name:    "bucket one holds at half range",
			bucket:  1,
			draw:    []byte{0x80, 0x00},
			promote: false,
		},
		{
			name:    "bucket two promotes below quarter range",
			bucket:  2,
			draw:    []byte{0x3f, 0xff},
			promote: true,
		},
		{
			name:    "bucket two holds at quarter range",
			bucket:  2,
			draw:    []byte{0x40, 0x00},
			promote: false,
		},
		{
			name:    "bucket six promotes below one sixty-fourth",
			bucket:  6,
			draw:    []byte{0x03, 0xff},
			promote: true,
		},
		{
			name:    "bucket six holds at one sixty-fourth",
			bucket:  6,
			draw:    []byte{0x04, 0x00},
			promote: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			promote, err := randomizedAggregatePromotion(
				test.bucket,
				bytes.NewReader(test.draw),
			)
			require.NoError(t, err)
			require.Equal(t, test.promote, promote)
		})
	}
}

func TestRandomizedAggregatePromotionSaturatesWithoutEntropy(t *testing.T) {
	promote, err := randomizedAggregatePromotion(
		maxCountBucket,
		errorReader{},
	)
	require.NoError(t, err)
	require.False(t, promote)
}

func TestRandomizedAggregatePromotionFailsClosed(t *testing.T) {
	for _, bucket := range []int16{0, maxCountBucket + 1} {
		promote, err := randomizedAggregatePromotion(
			bucket,
			bytes.NewReader([]byte{0, 0}),
		)
		require.ErrorIs(t, err, ErrAggregateInvalid)
		require.False(t, promote)
	}

	promote, err := randomizedAggregatePromotion(1, errorReader{})
	require.Error(t, err)
	require.False(t, promote)
}

func TestRevocationLatencyBucketBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		bucket   int16
	}{
		{name: "negative", duration: -time.Nanosecond, bucket: 0},
		{name: "zero", duration: 0, bucket: 0},
		{name: "positive", duration: time.Nanosecond, bucket: 1},
		{name: "thirty seconds", duration: 30 * time.Second, bucket: 1},
		{
			name:     "over thirty seconds",
			duration: 30*time.Second + time.Nanosecond,
			bucket:   2,
		},
		{name: "one minute", duration: time.Minute, bucket: 2},
		{
			name:     "over one minute",
			duration: time.Minute + time.Nanosecond,
			bucket:   3,
		},
		{name: "two minutes", duration: 2 * time.Minute, bucket: 3},
		{
			name:     "over two minutes",
			duration: 2*time.Minute + time.Nanosecond,
			bucket:   4,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(
				t,
				test.bucket,
				revocationLatencyBucket(test.duration),
			)
		})
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}
