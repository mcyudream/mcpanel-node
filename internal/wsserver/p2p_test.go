package wsserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
	"github.com/yudream/mcpanel-node/internal/certutil"
	"github.com/yudream/mcpanel-node/internal/instances"
	"github.com/yudream/mcpanel-node/internal/p2p"
	"github.com/yudream/mcpanel-node/internal/proto"
	"github.com/yudream/mcpanel-node/internal/stats"
)

// P2P 会话在真实控制信道上的端到端链路（节点侧）：
// 面板下 open → 节点开临时入口 → 启动器带票据握手 → 字节流进实例端口 → 关会话即回收。
func TestP2PSessionOverControlChannel(t *testing.T) {
	instancePort, stopInstance := fakeP2PInstance(t)
	defer stopInstance()

	client := newP2PTestClient(t)

	// 面板下发开会话（容器端口被票据钉死）
	res, err := client.do("p2p.session.open", map[string]any{
		"sessionId":     "sess-e2e",
		"ticket":        "ticket-e2e",
		"instanceId":    "inst-p2p",
		"targetPort": instancePort,
		"rateKbps":      0,
		"expiresAt":     time.Now().Add(time.Minute).UnixMilli(),
	})
	require.NoError(t, err)

	var opened struct {
		Accepted   bool            `json:"accepted"`
		ListenPort int             `json:"listenPort"`
		Candidates []p2p.Candidate `json:"candidates"`
	}
	require.NoError(t, json.Unmarshal(res.P, &opened))
	require.True(t, opened.Accepted)
	require.NotZero(t, opened.ListenPort)
	require.Len(t, opened.Candidates, 1)
	require.Equal(t, opened.ListenPort, opened.Candidates[0].Port)

	// 启动器（sidecar 等价物）带票据握手 → 直连成功
	entry := net.JoinHostPort("127.0.0.1", strconv.Itoa(opened.ListenPort))
	conn, dialErr := net.DialTimeout("tcp", entry, 3*time.Second)
	require.NoError(t, dialErr)
	defer func() { _ = conn.Close() }()
	_, err = fmt.Fprintf(conn, "%s sess-e2e ticket-e2e\n", p2p.Magic)
	require.NoError(t, err)
	reader := bufio.NewReader(conn)
	ack, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "OK\n", ack)

	// 玩家流量：入口 → 实例（实例回显）
	_, err = conn.Write([]byte("hello-instance\n"))
	require.NoError(t, err)
	echoed, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "echo:hello-instance\n", echoed)

	// 错误票据：同一入口必须拒绝
	badConn, badErr := net.DialTimeout("tcp", entry, 3*time.Second)
	require.NoError(t, badErr)
	defer func() { _ = badConn.Close() }()
	_, _ = fmt.Fprintf(badConn, "%s sess-e2e wrong-ticket\n", p2p.Magic)
	badAck, _ := bufio.NewReader(badConn).ReadString('\n')
	require.Equal(t, "ERR unauthorized\n", badAck)

	// 关会话：入口立即下线（不留悬挂监听）
	closed, err := client.do("p2p.session.close", map[string]any{"sessionId": "sess-e2e", "reason": "测试结束"})
	require.NoError(t, err)
	require.Contains(t, string(closed.P), "true")
	_, retryErr := net.DialTimeout("tcp", entry, time.Second)
	require.Error(t, retryErr, "会话关闭后入口必须不再监听")
}

// fakeP2PInstance 模拟实例容器端口：回显收到的每一行。
func fakeP2PInstance(t *testing.T) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					_, _ = conn.Write([]byte("echo:" + line))
				}
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, func() { _ = listener.Close() }
}

// newP2PTestClient 起一个带实例能力的最小控制服务并完成 hello。
func newP2PTestClient(t *testing.T) *frameClient {
	t.Helper()
	dir := t.TempDir()
	instSvc, err := instances.New(dir, "", testNodeID, nil)
	require.NoError(t, err)

	mgr := &certutil.Manager{DataDir: dir, Hostname: "node-a.test.internal"}
	cert, leaf, err := mgr.Ensure()
	require.NoError(t, err)
	pin := certutil.FingerprintHex(leaf.Raw)

	srv := New(Options{
		Credential: testCredential(),
		Stats:      &fixedStats{snapshot: stats.Snapshot{AgentVersion: "0.1.0"}},
		Hostname:   "node-a.test.internal",
		Log:        slog.Default(),
		Instances:  instSvc,
	})
	t.Cleanup(func() { srv.p2p.CloseAll("test cleanup") })

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	})
	require.NoError(t, err)
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	conn := dialPinned(t, ln.Addr().String(), pin, testNodeID, testSecret)
	client := newFrameClient(t, conn)
	hello, err := client.do(proto.MethodNodeHello, map[string]string{"panelVersion": "0.1.0"})
	require.NoError(t, err)
	require.Equal(t, proto.TypeRes, hello.T)
	return client
}

var _ = context.Background
var _ = websocket.StatusNormalClosure
