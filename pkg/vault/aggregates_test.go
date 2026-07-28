package vault

import (
	"bytes"
	"errors"
	"testing"

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

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}
