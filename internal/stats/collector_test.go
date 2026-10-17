package stats

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/yudream/mcpanel-node/internal/dockerx"
	"github.com/yudream/mcpanel-node/internal/version"
)

func TestCollectHostMetrics(t *testing.T) {
	c := New(t.TempDir(), nil, slog.Default())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	snap := c.Collect(ctx)

	require.Equal(t, version.Version, snap.AgentVersion)
	require.NotNil(t, snap.Containers)
	require.Empty(t, snap.Containers, "no docker client -> empty managed containers")
	require.GreaterOrEqual(t, snap.MemTotalMb, int64(0))
	require.GreaterOrEqual(t, snap.DiskTotalGb, int64(0))
	require.Less(t, snap.CPUPercent, 100.0001)
}

func TestCollectWithDockerIfAvailable(t *testing.T) {
	cli, err := dockerx.New()
	if err != nil {
		t.Skipf("docker client unavailable: %v", err)
	}
	pingCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := cli.Ping(pingCtx); err != nil {
		t.Skipf("docker daemon unreachable: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	c := New(t.TempDir(), cli, slog.Default())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	snap := c.Collect(ctx)
	require.Equal(t, version.Version, snap.AgentVersion)
	// dockerVersion present when daemon reachable (may be empty string on
	// probe failure, but with a successful ping it must be set).
	require.NotEmpty(t, snap.DockerVersion)
}

func TestCollectCancellable(t *testing.T) {
	c := New(t.TempDir(), nil, slog.Default())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = c.Collect(ctx)
		close(done)
	}()
	select {
	case <-done:
		// Collection returned (possibly with degraded fields) or was
		// cancelled promptly.
	case <-time.After(10 * time.Second):
		t.Fatal("collect did not honour cancellation")
	}
}

func TestNormalizeState(t *testing.T) {
	for _, s := range []string{"created", "running", "paused", "stopped", "exited"} {
		require.Equal(t, s, normalizeState(s))
	}
	require.Equal(t, "unknown", normalizeState("restarting"))
	require.Equal(t, "unknown", normalizeState(""))
}

func TestUnitConversions(t *testing.T) {
	require.Equal(t, int64(1024), bytesToMb(1024*1024*1024))
	require.Equal(t, int64(2), bytesToGb(2*1024*1024*1024))
}
