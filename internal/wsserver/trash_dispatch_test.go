package wsserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/yudream/mcpanel-node/internal/instances"
	"github.com/yudream/mcpanel-node/internal/stats"
	"github.com/stretchr/testify/require"
)

// trashDispatchHarness 构造仅带实例服务（无 Docker）的 Server，直接单测 Dispatch。
func trashDispatchHarness(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	instSvc, err := instances.New(dir, "", testNodeID, nil)
	require.NoError(t, err)
	srv := New(Options{
		Credential: testCredential(),
		Stats:      &fixedStats{snapshot: stats.Snapshot{AgentVersion: "0.1.0"}},
		Hostname:   "node-a.test.internal",
		Log:        slog.Default(),
		Instances:  instSvc,
	})
	return srv, dir
}

func TestCapsIncludeTrash(t *testing.T) {
	srv, _ := trashDispatchHarness(t)
	caps := srv.capsList()
	require.Contains(t, caps, "trash.list")
	require.Contains(t, caps, "trash.delete")
	// 无实例服务时回收站能力不得出现。
	bare := New(Options{Credential: testCredential(), Stats: &fixedStats{snapshot: stats.Snapshot{AgentVersion: "0.1.0"}},
		Hostname: "node-a.test.internal", Log: slog.Default()})
	require.NotContains(t, bare.capsList(), "trash.list")
}

func TestTrashDispatchListAndDelete(t *testing.T) {
	srv, dir := trashDispatchHarness(t)
	ctx := context.Background()

	// 手工造一个回收目录（面板删除实例后节点侧的真实形态）。
	trashID := "inst-abc-1700000000000"
	root := filepath.Join(dir, "trash", trashID)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "world"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "world", "level.dat"), []byte("d"), 0o644))
	meta, err := json.Marshal(map[string]any{"instanceId": "inst-abc", "name": "ABC 服", "deletedAt": int64(1700000000000)})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, ".mcpanel-trash.json"), meta, 0o600))

	res, err := srv.Dispatch(ctx, "trash.list", nil, "ik-trash-list-00001")
	require.NoError(t, err)
	m := res.(map[string]any)
	items := m["items"].([]instances.TrashItem)
	require.Len(t, items, 1)
	require.Equal(t, "inst-abc", items[0].InstanceID)
	require.Equal(t, "ABC 服", items[0].Name)
	require.Equal(t, trashID, items[0].TrashID)

	_, err = srv.Dispatch(ctx, "trash.delete", map[string]any{"trashId": trashID}, "ik-trash-del-000001")
	require.NoError(t, err)
	_, statErr := os.Stat(root)
	require.True(t, os.IsNotExist(statErr))

	_, err = srv.Dispatch(ctx, "trash.delete", map[string]any{"trashId": "../instances"}, "ik-trash-del-000002")
	require.Error(t, err)
}
