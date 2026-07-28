package logging

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLogTimeIsCoarsenedToUTCHour(t *testing.T) {
	value := time.Date(
		2026,
		time.July,
		26,
		12,
		34,
		56,
		789,
		time.FixedZone("offset", -5*60*60),
	)
	encoded := coarseLogTime(value)
	require.Equal(t, "2026-07-26T17Z", encoded)
	require.NotContains(t, encoded, "34")
	require.NotContains(t, encoded, "56")
}
