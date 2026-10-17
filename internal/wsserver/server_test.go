package wsserver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/yudream/mcpanel-node/internal/certutil"
	"github.com/yudream/mcpanel-node/internal/credential"
	"github.com/yudream/mcpanel-node/internal/proto"
	"github.com/yudream/mcpanel-node/internal/stats"
	"github.com/yudream/mcpanel-node/internal/version"
)

// 43 base64url chars = 32 bytes entropy, test-only value.
const testSecret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"

const testNodeID = "193700000000000000000000"

func testCredential() credential.Credential {
	return credential.Credential{
		NodeID:       testNodeID,
		NodeSecret:   testSecret,
		ControlPlan:  credential.ControlPlan{Mode: "direct"},
		EnrolledAtMs: 1,
	}
}

// fixedStats is a deterministic in-memory source for tests only. Production
// has no fake-stats switch (real Docker or nothing).
type fixedStats struct {
	mu       sync.Mutex
	snapshot stats.Snapshot
	calls    int
}

func (f *fixedStats) Collect(_ context.Context) stats.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.snapshot
}

func (f *fixedStats) DockerVersion(_ context.Context) string { return "29.2.1" }

func (f *fixedStats) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type harness struct {
	t       *testing.T
	baseURL string // wss://127.0.0.1:<random>/control
	pin     string
	stats   *fixedStats
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWithStats(t, &fixedStats{snapshot: stats.Snapshot{
		CPUPercent: 12.5, MemUsedMb: 1024, MemTotalMb: 8192,
		DiskUsedGb: 51, DiskTotalGb: 204,
		Containers:   []stats.ContainerStat{},
		AgentVersion: "0.1.0",
	}})
}

func newHarnessWithStats(t *testing.T, src *fixedStats) *harness {
	t.Helper()

	dir := t.TempDir()
	mgr := &certutil.Manager{DataDir: dir, Hostname: "node-a.test.internal"}
	cert, leaf, err := mgr.Ensure()
	require.NoError(t, err)
	pin := certutil.FingerprintHex(leaf.Raw)

	srv := New(Options{Credential: testCredential(), Stats: src, Hostname: "node-a.test.internal", Log: slog.Default()})

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	})
	require.NoError(t, err)

	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	return &harness{
		t:       t,
		baseURL: "wss://" + ln.Addr().String() + ControlPath,
		pin:     pin,
		stats:   src,
	}
}

func (h *harness) dial(nodeID, secret string) (*websocket.Conn, *http.Response, error) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	h.t.Cleanup(cancel)

	pin := h.pin
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Pin replaces PKIX for the self-signed test certificate.
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
	if nodeID != "" {
		header.Set("X-Mcpanel-Node-Id", nodeID)
	}
	if secret != "" {
		header.Set("Authorization", "Bearer "+secret)
	}
	return websocket.Dial(ctx, h.baseURL, &websocket.DialOptions{
		HTTPClient: httpClient,
		HTTPHeader: header,
	})
}

func (h *harness) dialOK(nodeID, secret string) *websocket.Conn {
	h.t.Helper()
	conn, _, err := h.dial(nodeID, secret)
	require.NoError(h.t, err)
	return conn
}

func (h *harness) expect401(nodeID, secret string) {
	h.t.Helper()
	conn, resp, err := h.dial(nodeID, secret)
	require.Error(h.t, err, "handshake must fail")
	require.NotNil(h.t, resp)
	require.Equal(h.t, http.StatusUnauthorized, resp.StatusCode)
	if conn != nil {
		_ = conn.Close(websocket.StatusInternalError, "")
	}
}

func readFrame(t *testing.T, conn *websocket.Conn) *proto.Envelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, data, err := conn.Read(ctx)
	require.NoError(t, err)
	env, err := proto.Decode(data)
	require.NoError(t, err)
	return env
}

func sendHello(t *testing.T, conn *websocket.Conn) string {
	t.Helper()
	req, err := proto.NewReq(proto.MethodNodeHello, map[string]string{"panelVersion": "0.1.0"})
	require.NoError(t, err)
	data, err := req.Encode()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, conn.Write(ctx, websocket.MessageText, data))
	return req.ID
}

// helloAndFirstStats performs the frozen opening exchange and returns the
// hello res payload plus the immediate first node.stats evt.
func helloAndFirstStats(t *testing.T, conn *websocket.Conn) (nodeInfoPayload, *proto.Envelope) {
	t.Helper()
	reqID := sendHello(t, conn)

	res := readFrame(t, conn)
	require.Equal(t, proto.TypeRes, res.T)
	require.Equal(t, reqID, res.ID)
	var hello nodeInfoPayload
	require.NoError(t, json.Unmarshal(res.P, &hello))

	statsEvt := readFrame(t, conn)
	require.Equal(t, proto.TypeEvt, statsEvt.T)
	require.Equal(t, proto.TopicNodeStats, statsEvt.M)
	require.NotNil(t, statsEvt.Seq)
	require.Equal(t, int64(0), *statsEvt.Seq)
	return hello, statsEvt
}

func TestHelloResAndImmediateStats(t *testing.T) {
	h := newHarness(t)
	conn := h.dialOK(testNodeID, testSecret)
	defer conn.Close(websocket.StatusNormalClosure, "")

	hello, statsEvt := helloAndFirstStats(t, conn)

	require.Equal(t, testNodeID, hello.NodeID)
	require.NotEmpty(t, hello.SessionID)
	require.Equal(t, "node-a.test.internal", hello.Hostname)
	require.Equal(t, version.Version, hello.AgentVersion)
	require.Equal(t, []string{"node.hello", "node.stats"}, hello.Caps)
	require.Equal(t, "29.2.1", hello.DockerVersion)

	var snap stats.Snapshot
	require.NoError(t, json.Unmarshal(statsEvt.P, &snap))
	require.Equal(t, 12.5, snap.CPUPercent)
	require.Equal(t, int64(1024), snap.MemUsedMb)
	require.Equal(t, int64(8192), snap.MemTotalMb)
	require.Equal(t, int64(51), snap.DiskUsedGb)
	require.Equal(t, int64(204), snap.DiskTotalGb)
	require.Equal(t, "0.1.0", snap.AgentVersion)
}

func TestStatsContinuesEveryFiveSeconds(t *testing.T) {
	h := newHarness(t)
	conn := h.dialOK(testNodeID, testSecret)
	defer conn.Close(websocket.StatusNormalClosure, "")

	sendHello(t, conn)
	res := readFrame(t, conn)
	require.Equal(t, proto.TypeRes, res.T)
	first := readFrame(t, conn)
	require.Equal(t, proto.TypeEvt, first.T)
	require.Equal(t, int64(0), *first.Seq)

	// Second stats frame arrives around 5s later with seq 1.
	second := readFrame(t, conn)
	require.Equal(t, proto.TypeEvt, second.T)
	require.Equal(t, int64(1), *second.Seq)
}

func TestHandshakeAuthFailures(t *testing.T) {
	h := newHarness(t)

	h.expect401(testNodeID, "wrong-secret-000000000000000000000000000") // len 43, wrong value
	h.expect401("unknown-node", testSecret)
	h.expect401("", testSecret)
	h.expect401(testNodeID, "")

	// Correct headers succeed afterwards (failures only counted, no lockout
	// below the limit).
	conn := h.dialOK(testNodeID, testSecret)
	defer conn.Close(websocket.StatusNormalClosure, "")
	_, statsEvt := helloAndFirstStats(t, conn)
	require.NotNil(t, statsEvt)
}

func TestHandshakeRateLimit429(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < failLimit; i++ {
		h.expect401(testNodeID, "wrong-secret-000000000000000000000000000")
	}
	// Budget exhausted: even the correct secret now yields 429.
	_, resp, err := h.dial(testNodeID, testSecret)
	require.Error(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
}

func TestUnknownMethodErrFrame(t *testing.T) {
	h := newHarness(t)
	conn := h.dialOK(testNodeID, testSecret)
	defer conn.Close(websocket.StatusNormalClosure, "")

	req, err := proto.NewReq("no.such.method", map[string]any{})
	require.NoError(t, err)
	data, err := req.Encode()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, conn.Write(ctx, websocket.MessageText, data))

	env := readFrame(t, conn)
	require.Equal(t, proto.TypeErr, env.T)
	require.Equal(t, req.ID, env.ID)
	require.Equal(t, "no.such.method", env.M)
	p := proto.ErrPayloadOf(env)
	require.Equal(t, proto.CodeUnknownMethod, p.Code)
	require.False(t, p.Retryable)
}

func TestOversizedFrameCloses1009(t *testing.T) {
	h := newHarness(t)
	conn := h.dialOK(testNodeID, testSecret)
	defer conn.Close(websocket.StatusNormalClosure, "")

	big := make([]byte, proto.MaxFrameBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The client has no read limit; the server must reject on its side.
	err := conn.Write(ctx, websocket.MessageText, big)
	require.NoError(t, err)

	for {
		_, _, err = conn.Read(ctx)
		if err != nil {
			require.Equal(t, websocket.StatusMessageTooBig, websocket.CloseStatus(err),
				"server must close with 1009 on oversized frames, got %v", err)
			return
		}
	}
}

func TestAbruptClientCloseThenReconnect(t *testing.T) {
	h := newHarness(t)

	conn1 := h.dialOK(testNodeID, testSecret)
	helloAndFirstStats(t, conn1)
	_ = conn1.Close(websocket.StatusAbnormalClosure, "")

	// The server must clean up and accept a fresh session.
	var conn2 *websocket.Conn
	require.Eventually(t, func() bool {
		c, _, err := h.dial(testNodeID, testSecret)
		if err != nil {
			return false
		}
		conn2 = c
		return true
	}, 10*time.Second, 200*time.Millisecond)
	defer conn2.Close(websocket.StatusNormalClosure, "")

	hello, _ := helloAndFirstStats(t, conn2)
	require.Equal(t, testNodeID, hello.NodeID)
}

func TestSessionReplacementClose4000(t *testing.T) {
	h := newHarness(t)

	conn1 := h.dialOK(testNodeID, testSecret)
	defer func() {
		_ = conn1.Close(websocket.StatusNormalClosure, "")
	}()
	_, firstStats := helloAndFirstStats(t, conn1)
	require.NotNil(t, firstStats)

	conn2 := h.dialOK(testNodeID, testSecret)
	defer conn2.Close(websocket.StatusNormalClosure, "")
	hello2, _ := helloAndFirstStats(t, conn2)
	require.NotEmpty(t, hello2.SessionID)

	// Old session must be closed with 4000 replaced.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		_, _, err := conn1.Read(ctx)
		if err != nil {
			require.Equal(t, websocket.StatusCode(closeReplaced), websocket.CloseStatus(err))
			return
		}
	}
}

func TestNonTLSPathRejected(t *testing.T) {
	h := newHarness(t)
	// Plain ws:// (no TLS) must fail: endpoint is TLS-only.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(h.baseURL, "wss")
	_, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{})
	require.Error(t, err, "plaintext ws to the TLS port must not succeed")
}

func TestHelloTwiceRejected(t *testing.T) {
	h := newHarness(t)
	conn := h.dialOK(testNodeID, testSecret)
	defer conn.Close(websocket.StatusNormalClosure, "")

	helloAndFirstStats(t, conn)

	// Second hello on the same session must be answered with err, and the
	// stats pump must not restart.
	reqID := sendHello(t, conn)
	env := readFrame(t, conn)
	require.Equal(t, proto.TypeErr, env.T)
	require.Equal(t, reqID, env.ID)
	p := proto.ErrPayloadOf(env)
	require.Equal(t, proto.CodeBadFrame, p.Code)
}

func TestHelloRequiresPanelVersion(t *testing.T) {
	h := newHarness(t)
	conn := h.dialOK(testNodeID, testSecret)
	defer conn.Close(websocket.StatusNormalClosure, "")

	for _, payload := range []any{nil, map[string]string{"panelVersion": " "}, map[string]string{}} {
		req, err := proto.NewReq(proto.MethodNodeHello, payload)
		require.NoError(t, err)
		data, err := req.Encode()
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		require.NoError(t, conn.Write(ctx, websocket.MessageText, data))
		env := readFrame(t, conn)
		require.Equal(t, proto.TypeErr, env.T)
		require.Equal(t, proto.CodeBadPayload, proto.ErrPayloadOf(env).Code)
		cancel()
	}
}

func TestBinaryFrameRejected1003(t *testing.T) {
	h := newHarness(t)
	conn := h.dialOK(testNodeID, testSecret)
	defer conn.Close(websocket.StatusNormalClosure, "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := conn.Write(ctx, websocket.MessageBinary, []byte(`{"v":1}`))
	require.NoError(t, err)

	for {
		_, _, err = conn.Read(ctx)
		if err != nil {
			require.Equal(t, websocket.StatusUnsupportedData, websocket.CloseStatus(err),
				"binary frames must be rejected with 1003, got %v", err)
			return
		}
	}
}

func TestServerShutdownClosesActiveSession(t *testing.T) {
	h := newHarness(t)

	// Build a raw server handle so we can call Shutdown explicitly.
	dir := t.TempDir()
	mgr := &certutil.Manager{DataDir: dir, Hostname: "node-a.test.internal"}
	cert, leaf, err := mgr.Ensure()
	require.NoError(t, err)

	srv := New(Options{Credential: testCredential(), Stats: h.stats, Hostname: "node-a", Log: slog.Default()})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	})
	require.NoError(t, err)
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()

	pin := certutil.FingerprintHex(leaf.Raw)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // pinned test cert
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != pin {
				return context.Canceled
			}
			return nil
		},
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	header := http.Header{}
	header.Set("X-Mcpanel-Node-Id", testNodeID)
	header.Set("Authorization", "Bearer "+testSecret)
	conn, _, err := websocket.Dial(dialCtx, "wss://"+ln.Addr().String()+ControlPath, &websocket.DialOptions{
		HTTPClient: httpClient,
		HTTPHeader: header,
	})
	require.NoError(t, err)

	// Server.Shutdown must cancel and force-close the hijacked websocket,
	// observable as a read error on the client.
	readDone := make(chan error, 1)
	go func() {
		_, _, err := conn.Read(dialCtx)
		readDone <- err
	}()

	srv.Shutdown()
	_ = httpSrv.Close()

	select {
	case err := <-readDone:
		require.Error(t, err, "active session must be closed by Server.Shutdown")
	case <-time.After(10 * time.Second):
		t.Fatal("session was not closed after Server.Shutdown")
	}
}
