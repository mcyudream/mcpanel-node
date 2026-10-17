package dockerx

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// available skips when the daemon is unreachable so `go test ./...` passes in
// environments without Docker. Real-Docker assertions only; no fake switch.
func available(t *testing.T) *Client {
	t.Helper()
	c, err := New()
	if err != nil {
		t.Skipf("docker client unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Ping(ctx); err != nil {
		t.Skipf("docker daemon unreachable: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestVersionRealDocker(t *testing.T) {
	c := available(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	v, err := c.Version(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, v)
	// Cached on second call.
	v2, err := c.Version(ctx)
	require.NoError(t, err)
	require.Equal(t, v, v2)
}

func TestListRunningRealDocker(t *testing.T) {
	c := available(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	refs, err := c.ListRunning(ctx, "")
	require.NoError(t, err)
	for _, r := range refs {
		require.NotEmpty(t, r.ID)
		require.Equal(t, "running", r.State)
	}
}

func TestStatsOneShotRealDocker(t *testing.T) {
	c := available(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	refs, err := c.ListRunning(ctx, "")
	require.NoError(t, err)
	if len(refs) == 0 {
		t.Skip("no running containers to sample")
	}
	sample, err := c.StatsOneShot(ctx, refs[0].ID)
	require.NoError(t, err)
	require.GreaterOrEqual(t, sample.CPUPercent, 0.0)
}

func TestCPUPercentFormula(t *testing.T) {
	s := statsJSON{}
	s.CPUStats.CPUUsage.TotalUsage = 2_000_000_000
	s.CPUStats.SystemUsage = 10_000_000_000
	s.CPUStats.OnlineCPUs = 4
	s.PreCPUStats.CPUUsage.TotalUsage = 1_000_000_000
	s.PreCPUStats.SystemUsage = 7_500_000_000
	// cpuDelta=1s, sysDelta=2.5s, cpus=4 -> 160%
	require.Equal(t, 160.0, s.CPUPercent())
}

func TestCPUPercentZeroWhenNoDelta(t *testing.T) {
	s := statsJSON{}
	s.CPUStats.CPUUsage.TotalUsage = 1_000
	s.PreCPUStats.CPUUsage.TotalUsage = 1_000
	require.Equal(t, 0.0, s.CPUPercent())
}
