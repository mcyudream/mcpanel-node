package frpc

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/coder/websocket"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	frpserver "github.com/fatedier/frp/server"
	"github.com/stretchr/testify/require"

	"github.com/yudream/mcpanel-node/internal/certutil"
	"github.com/yudream/mcpanel-node/internal/credential"
	"github.com/yudream/mcpanel-node/internal/proto"
	"github.com/yudream/mcpanel-node/internal/stats"
	"github.com/yudream/mcpanel-node/internal/wsserver"
)

// 43 base64url chars = 32 bytes entropy, test-only value.
const testSecret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"

const testToken = "node-specific-proxy-token-0123456789" // node-scoped, test-only

// testStats satisfies wsserver.StatsSource for the tunnel test.
type testStats struct{}

func (testStats) Collect(_ context.Context) stats.Snapshot {
	return stats.Snapshot{AgentVersion: "0.1.0", Containers: []stats.ContainerStat{}}
}
func (testStats) DockerVersion(_ context.Context) string { return "" }

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// startFrps launches an in-process frps bound to loopback with a random port.
// This is the real frp server library, not a mock.
func startFrps(t *testing.T, ctx context.Context, token string) int {
	t.Helper()
	port := freePort(t)
	cfg := &v1.ServerConfig{
		BindAddr:      "127.0.0.1",
		BindPort:      port,
		ProxyBindAddr: "127.0.0.1",
	}
	cfg.Auth = v1.AuthServerConfig{Method: "token", Token: token}
	require.NoError(t, cfg.Complete())

	svr, err := frpserver.NewService(cfg)
	require.NoError(t, err)
	go svr.Run(ctx)
	t.Cleanup(func() { _ = svr.Close() })
	return port
}

func TestTunnelEndToEndTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("tunnel integration test")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	frpsPort := startFrps(t, ctx, testToken)
	remotePort := freePort(t)

	// Node TLS endpoint on a random loopback port.
	dir := t.TempDir()
	mgr := &certutil.Manager{DataDir: dir, Hostname: "node-a.test.internal"}
	tlsCert, leaf, err := mgr.Ensure()
	require.NoError(t, err)
	pin := certutil.FingerprintHex(leaf.Raw)

	cred := credential.Credential{
		NodeID:       "193700000000000000000000",
		NodeSecret:   testSecret,
		ControlPlan:  credential.ControlPlan{Mode: "direct"},
		EnrolledAtMs: 1,
	}
	nodeLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{tlsCert},
	})
	require.NoError(t, err)
	nodePort := nodeLn.Addr().(*net.TCPAddr).Port
	nodeSrv := &http.Server{
		Handler: wsserver.New(wsserver.Options{Credential: cred, Stats: testStats{}, Hostname: "node-a", Log: slog.Default()}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = nodeSrv.Serve(nodeLn) }()
	t.Cleanup(func() { _ = nodeSrv.Close() })

	// Embedded frpc dials out to frps and maps remotePort -> node TLS port.
	runner, err := Start(ctx, Config{
		ServerAddr: "127.0.0.1",
		ServerPort: frpsPort,
		User:       "node-1937",
		ProxyName:  "control-1937",
		Token:      testToken,
		RemotePort: remotePort,
		LocalIP:    "127.0.0.1",
		LocalPort:  nodePort,
	}, slog.Default())
	require.NoError(t, err)
	t.Cleanup(runner.Stop)

	// Panel stub dials the frps ingress; TLS must terminate at the node
	// (end-to-end through the raw TCP tunnel), verified by the pin check.
	dialTunnel := func() (*websocket.Conn, error) {
		dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
		defer dcancel()
		tlsCfg := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // pinned fingerprint replaces PKIX
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return context.Canceled
				}
				sum := sha256.Sum256(rawCerts[0])
				if hex.EncodeToString(sum[:]) != pin {
					return context.Canceled
				}
				return nil
			},
		}
		httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
		header := http.Header{}
		header.Set("X-Mcpanel-Node-Id", cred.NodeID)
		header.Set("Authorization", "Bearer "+cred.NodeSecret)
		conn, _, err := websocket.Dial(dctx, "wss://127.0.0.1:"+itoa(remotePort)+wsserver.ControlPath, &websocket.DialOptions{
			HTTPClient: httpClient,
			HTTPHeader: header,
		})
		return conn, err
	}

	var conn *websocket.Conn
	require.Eventually(t, func() bool {
		c, err := dialTunnel()
		if err != nil {
			return false
		}
		conn = c
		return true
	}, 20*time.Second, 300*time.Millisecond, "panel stub must reach the node through the frp tunnel")
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Opening exchange over the tunnel.
	req, err := proto.NewReq(proto.MethodNodeHello, map[string]string{"panelVersion": "0.1.0"})
	require.NoError(t, err)
	data, err := req.Encode()
	require.NoError(t, err)
	wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
	defer wcancel()
	require.NoError(t, conn.Write(wctx, websocket.MessageText, data))

	rctx, rcancel := context.WithTimeout(ctx, 10*time.Second)
	defer rcancel()
	_, raw, err := conn.Read(rctx)
	require.NoError(t, err)
	env, err := proto.Decode(raw)
	require.NoError(t, err)
	require.Equal(t, proto.TypeRes, env.T)
	require.Equal(t, req.ID, env.ID)
	var hello struct {
		NodeID    string   `json:"nodeId"`
		SessionID string   `json:"sessionId"`
		Caps      []string `json:"caps"`
	}
	require.NoError(t, json.Unmarshal(env.P, &hello))
	require.Equal(t, cred.NodeID, hello.NodeID)
	require.NotEmpty(t, hello.SessionID)
	require.Equal(t, []string{"node.hello", "node.stats"}, hello.Caps)
}

func TestRunnerRejectsMissingToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := Start(ctx, Config{
		ServerAddr: "127.0.0.1", ServerPort: 7000,
		User: "u", ProxyName: "p", RemotePort: 7101,
		LocalIP: "127.0.0.1", LocalPort: 7443,
	}, slog.Default())
	require.Error(t, err, "missing node-specific frp token must be refused")
	require.ErrorContains(t, err, "token")
}

func itoa(v int) string { return strconv.Itoa(v) }
