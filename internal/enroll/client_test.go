package enroll

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/yudream/mcpanel-node/internal/credential"
)

const testToken = "one-time-enroll-token-value-0123456789"

// 43 base64url chars decoding to 32 bytes of entropy, test-only value.
const issuedSecret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"

const nodeCertFP = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"

func testRequest() Request {
	return Request{
		EnrollToken:   testToken,
		Hostname:      "node-a",
		AgentVersion:  "0.1.0",
		Caps:          []string{"node.hello", "node.stats"},
		TLSCertSha256: nodeCertFP,
	}
}

// panelHandler asserts the request shape and replies with raw JSON.
func panelHandler(t *testing.T, hits *atomic.Int64, status int, body string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		require.Equal(t, BootstrapPath, r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
		var req Request
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.Equal(t, testToken, req.EnrollToken)
		require.Equal(t, "node-a", req.Hostname)
		require.Equal(t, []string{"node.hello", "node.stats"}, req.Caps)
		require.Equal(t, nodeCertFP, req.TLSCertSha256)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"nodeId": "node-123",
			"nodeSecret": "` + issuedSecret + `",
			"serverTimeMs": 1737619200000,
			"controlPlan": {"mode": "direct"}
		}`))
	}
}

func TestBootstrapSuccessWithPin(t *testing.T) {
	srv := httptest.NewTLSServer(panelHandler(t, &atomic.Int64{}, http.StatusOK, ""))
	defer srv.Close()

	pin := fingerprintOf(t, srv)
	c, err := NewClient(srv.URL, pin, nil)
	require.NoError(t, err)

	cred, err := c.Bootstrap(context.Background(), testRequest())
	require.NoError(t, err)
	require.Equal(t, "node-123", cred.NodeID)
	require.Equal(t, issuedSecret, cred.NodeSecret)
	require.Equal(t, "direct", cred.ControlPlan.Mode)
	require.NoError(t, cred.Validate())
}

func TestBootstrapWrongPinFailsBeforeSendingToken(t *testing.T) {
	srv := httptest.NewTLSServer(panelHandler(t, &atomic.Int64{}, http.StatusOK, ""))
	defer srv.Close()

	var hits atomic.Int64
	srv.Config.Handler = panelHandler(t, &hits, http.StatusOK, "")

	c, err := NewClient(srv.URL, "0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd", nil)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = c.Bootstrap(ctx, testRequest())
	require.Error(t, err)

	require.Equal(t, int64(0), hits.Load(),
		"token must never be transmitted to a server whose cert does not match the pin")
}

func TestBootstrapPKIXRejectsUntrustedSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(panelHandler(t, &atomic.Int64{}, http.StatusOK, ""))
	defer srv.Close()

	// No pin configured: standard verification must reject httptest's
	// self-signed cert (unknown CA).
	c, err := NewClient(srv.URL, "", nil)
	require.NoError(t, err)

	_, err = c.Bootstrap(context.Background(), testRequest())
	require.Error(t, err)
}

func TestBootstrap4xxNoRetry(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewTLSServer(panelHandler(t, &hits, http.StatusUnauthorized, `{"error":"bad token"}`))
	defer srv.Close()
	pin := fingerprintOf(t, srv)

	c, err := NewClient(srv.URL, pin, nil)
	require.NoError(t, err)

	_, err = c.Bootstrap(context.Background(), testRequest())
	require.Error(t, err)
	var rejected *ErrRejected
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, http.StatusUnauthorized, rejected.StatusCode)
	require.Equal(t, int64(1), hits.Load(), "4xx must not be retried (one-time token)")
}

func TestBootstrap5xxRetriesThenSucceeds(t *testing.T) {
	var hits atomic.Int64
	var failures atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n <= 2 {
			failures.Add(1)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"nodeId": "node-123",
			"nodeSecret": "` + issuedSecret + `",
			"serverTimeMs": 1737619200000,
			"controlPlan": {"mode": "direct"}
		}`))
	}))
	defer srv.Close()
	pin := fingerprintOf(t, srv)

	c, err := NewClient(srv.URL, pin, nil)
	require.NoError(t, err)

	cred, err := c.Bootstrap(context.Background(), testRequest())
	require.NoError(t, err)
	require.Equal(t, "node-123", cred.NodeID)
	require.Equal(t, int64(2), failures.Load())
	require.Equal(t, int64(3), hits.Load())
}

func TestBootstrapRejectsHostWrappedEnvelope(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":{"nodeId":"n","nodeSecret":"x"}}`))
	}))
	defer srv.Close()
	pin := fingerprintOf(t, srv)

	c, err := NewClient(srv.URL, pin, nil)
	require.NoError(t, err)

	_, err = c.Bootstrap(context.Background(), testRequest())
	require.Error(t, err, "host-wrapped envelope bodies must be rejected for machine endpoints")
}

func TestBootstrapRejectsWeakSecret(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"nodeId":"n","nodeSecret":"short","controlPlan":{"mode":"direct"}}`))
	}))
	defer srv.Close()
	pin := fingerprintOf(t, srv)

	c, err := NewClient(srv.URL, pin, nil)
	require.NoError(t, err)

	_, err = c.Bootstrap(context.Background(), testRequest())
	require.Error(t, err)
}

func TestBootstrapEmptyTokenRefused(t *testing.T) {
	srv := httptest.NewTLSServer(panelHandler(t, &atomic.Int64{}, http.StatusOK, ""))
	defer srv.Close()
	pin := fingerprintOf(t, srv)
	c, err := NewClient(srv.URL, pin, nil)
	require.NoError(t, err)

	req := testRequest()
	req.EnrollToken = " "
	_, err = c.Bootstrap(context.Background(), req)
	require.Error(t, err)
}

func TestCredentialMinLengthConstantMatches(t *testing.T) {
	require.Equal(t, 43, credential.MinSecretLen)
	_ = tls.VersionTLS12
	require.Equal(t, 32, credential.SecretEntropyBytes)
}

func fingerprintOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	cert := srv.Certificate()
	require.NotNil(t, cert)
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func TestHTTPOriginAndURLPartsRejected(t *testing.T) {
	for _, u := range []string{
		"http://panel.example.com",
		"https://panel.example.com/path",
		"https://user:pw@panel.example.com",
		"https://panel.example.com/?x=1",
		"https://panel.example.com/#frag",
		"https://panel.example.com:99999",
		"ftp://panel.example.com",
		"https://panel.example.com:abc",
	} {
		_, err := NewClient(u, "", nil)
		require.Error(t, err, "origin %s must be rejected", u)
	}
	for _, u := range []string{"https://panel.example.com", "https://panel.example.com:8443", "https://panel.example.com/"} {
		_, err := NewClient(u, "", nil)
		require.NoError(t, err, "origin %s must be accepted", u)
	}
	// 明文 http 例外：回环、Docker 宿主别名与私网地址（内网部署直连面板）。
	for _, u := range []string{
		"http://127.0.0.1:8080",
		"http://localhost:8080",
		"http://host.docker.internal:8080",
		"http://192.168.1.10:8080",
		"http://10.0.0.2:9002",
		"http://172.16.5.5:9002",
		"http://[fd00::10]:9002",
	} {
		_, err := NewClient(u, "", nil)
		require.NoError(t, err, "private origin %s must be accepted", u)
	}
	// 例外不得扩大：公网 IP、普通域名与链路本地（云元数据 169.254.169.254）仍然拒绝。
	for _, u := range []string{
		"http://8.8.8.8:8080",
		"http://169.254.169.254:80",
		"http://panel.example.com",
	} {
		_, err := NewClient(u, "", nil)
		require.Error(t, err, "non-private http %s must be rejected", u)
	}
}

func TestServerTimeMsAcceptsStringAndNumber(t *testing.T) {
	var stringForm Response
	require.NoError(t, json.Unmarshal([]byte(`{"nodeId":"n","nodeSecret":"`+issuedSecret+`","serverTimeMs":"1789819341887","controlPlan":{"mode":"direct"}}`), &stringForm))
	require.EqualValues(t, 1789819341887, stringForm.ServerTimeMs)
	var numberForm Response
	require.NoError(t, json.Unmarshal([]byte(`{"nodeId":"n","nodeSecret":"`+issuedSecret+`","serverTimeMs":1789819341887,"controlPlan":{"mode":"direct"}}`), &numberForm))
	require.EqualValues(t, 1789819341887, numberForm.ServerTimeMs)
	var invalid Response
	require.Error(t, json.Unmarshal([]byte(`{"serverTimeMs":"not-a-number"}`), &invalid))
}

func TestMalformedSuccessBodyIsPermanent(t *testing.T) {
	// 200 + 非 JSON 响应体：必须归为 ErrRejected（重试只会烧掉一次性令牌）。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("<html>not json</html>"))
	}))
	defer srv.Close()
	client, err := NewClient(srv.URL, "", nil)
	require.NoError(t, err)
	_, err = client.Bootstrap(context.Background(), Request{EnrollToken: testToken})
	require.Error(t, err)
	var rejected *ErrRejected
	require.ErrorAs(t, err, &rejected)
}

func TestPinRequires64Hex(t *testing.T) {
	srv := httptest.NewTLSServer(panelHandler(t, &atomic.Int64{}, http.StatusOK, ""))
	defer srv.Close()
	for _, bad := range []string{"aa.bb", "00112233", strings.Repeat("a", 63), strings.Repeat("g", 64)} {
		_, err := NewClient(srv.URL, bad, nil)
		require.Error(t, err, "pin %q must be rejected", bad)
	}
	_, err := NewClient(srv.URL, strings.Repeat("0", 64), nil)
	require.NoError(t, err)
}

func TestRedirectNeverFollowedAndLocationNotLeaked(t *testing.T) {
	secretInLocation := "http://evil.example/capture?token=" + testToken
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Location", secretInLocation)
		w.WriteHeader(http.StatusTemporaryRedirect) // 307 would replay the body
	}))
	defer srv.Close()
	pin := fingerprintOf(t, srv)

	c, err := NewClient(srv.URL, pin, nil)
	require.NoError(t, err)

	var logBuf safeBuffer
	c.log = newTestLogger(&logBuf)

	_, err = c.Bootstrap(context.Background(), testRequest())
	require.Error(t, err, "redirects must never be followed")
	require.Equal(t, int64(1), hits.Load(), "the request must not be replayed to the redirect target")

	out := logBuf.String()
	require.NotContains(t, out, secretInLocation, "redirect Location must not be logged")
	require.NotContains(t, out, "evil.example", "redirect target must not be logged")
	require.NotContains(t, err.Error(), "evil.example")
}

// safeBuffer is a mutex-protected bytes.Buffer for logger output.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newTestLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
