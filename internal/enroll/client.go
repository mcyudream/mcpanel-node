// Package enroll implements the node -> panel HTTPS bootstrap.
//
// Trust model (frozen): the panel TLS certificate is verified BEFORE the
// one-time enrollToken is transmitted — either via standard PKIX/hostname
// verification, or via an admin-provided leaf SHA-256 pin
// (panel.tlsPinSha256 / MCNODE_PANEL_TLS_PIN_SHA256). The pin is never
// learned from or updated by the bootstrap response.
//
// Endpoint: POST {panel.url}/api/plugins/mcpanel/node/bootstrap
// Request:  raw JSON {enrollToken, hostname, agentVersion, caps, tlsCertSha256}
// Response: raw JSON {nodeId, nodeSecret, serverTimeMs, controlPlan:{mode}}
// The panel emits machine-protocol responses as unwrapped raw JSON; the node
// rejects host-wrapped envelope bodies.
package enroll

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yudream/mcpanel-node/internal/credential"
)

// BootstrapPath is the frozen panel bootstrap endpoint path.
const BootstrapPath = "/api/plugins/mcpanel/node/bootstrap"

// Caps is the exact capability list this agent version implements. Methods
// that are not implemented must not be declared (M1: hello + stats only).
var Caps = []string{"node.hello", "node.stats"}

// Request is the bootstrap request body.
type Request struct {
	EnrollToken   string   `json:"enrollToken"`
	Hostname      string   `json:"hostname"`
	AgentVersion  string   `json:"agentVersion"`
	Caps          []string `json:"caps"`
	TLSCertSha256 string   `json:"tlsCertSha256"`
}

// ControlPlan mirrors protocol §2: "direct" (M1a baseline) or "frp"
// (M1b, experimental, not production enabled).
type ControlPlan struct {
	Mode string              `json:"mode"`
	FRP  *credential.FRPPlan `json:"frp,omitempty"`
}

// Response is the bootstrap response body (raw JSON, no host envelope).
type Response struct {
	NodeID       string      `json:"nodeId"`
	NodeSecret   string      `json:"nodeSecret"`
	ServerTimeMs FlexMs      `json:"serverTimeMs"`
	ControlPlan  ControlPlan `json:"controlPlan"`
}

// FlexMs accepts epoch-ms as either a JSON number or a numeric string: the
// host serializes long values as strings by global convention, and
// serverTimeMs is diagnostic-only. Both forms must parse.
type FlexMs int64

func (f *FlexMs) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("serverTimeMs is not a number: %w", err)
	}
	*f = FlexMs(n)
	return nil
}

// ErrRejected marks a permanent bootstrap rejection (HTTP 4xx). Retry will
// not help; the token is one-time and admin action is required.
type ErrRejected struct {
	StatusCode int
}

func (e *ErrRejected) Error() string {
	return fmt.Sprintf("bootstrap rejected by panel (http %d)", e.StatusCode)
}

// Client performs the bootstrap call.
type Client struct {
	baseURL string
	http    *http.Client
	log     *slog.Logger
}

// NewClient builds a bootstrap client.
//
// baseURL must be a bare origin. https is required in every environment:
// the enroll token is transmitted in the body and must never cross a
// plaintext hop. The only carve-out is local development: plain http is
// accepted when the target is a loopback address or the Docker-provided
// host alias (host.docker.internal), which always points at the developer's
// own machine — a container-side node bootstrapping into a locally run panel.
//
// pinSha256 is an optional 64-hex-char (32 bytes decoded) leaf pin; when set,
// TLS verification is replaced by an exact leaf fingerprint match (PKIX is
// skipped).
//
// Redirect following is fully disabled: a 307/308 would otherwise replay the
// enroll token body to a different origin (or downgrade to http under PKIX).
func NewClient(baseURL, pinSha256 string, log *slog.Logger) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		return nil, errors.New("panel base url is empty")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("panel.url is not a valid URL: %w", err)
	}
	if u.Scheme == "http" {
		if !plainHTTPAllowed(u.Hostname()) {
			return nil, errors.New("panel.url must use https (plain http is only allowed for loopback, host.docker.internal and private-network addresses)")
		}
	} else if u.Scheme != "https" {
		return nil, errors.New("panel.url must use http(s)")
	}
	if u.User != nil {
		return nil, errors.New("panel.url must not contain userinfo")
	}
	if u.Host == "" {
		return nil, errors.New("panel.url is missing a host")
	}
	if port := u.Port(); port != "" {
		n, convErr := strconv.Atoi(port)
		if convErr != nil || n <= 0 || n > 65535 {
			return nil, errors.New("panel.url has an invalid port")
		}
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("panel.url must be a bare origin without a path (the bootstrap path is fixed by the protocol)")
	}
	if u.RawQuery != "" {
		return nil, errors.New("panel.url must not contain a query string")
	}
	if u.Fragment != "" {
		return nil, errors.New("panel.url must not contain a fragment")
	}

	var tlsCfg *tls.Config
	if pinSha256 != "" {
		if len(pinSha256) != 64 {
			return nil, errors.New("panel tls pin must be 64 hex chars (32 bytes)")
		}
		pinBytes, err := hex.DecodeString(strings.ToLower(pinSha256))
		if err != nil || len(pinBytes) != 32 {
			return nil, errors.New("panel tls pin must be 64 hex chars (32 bytes)")
		}
		tlsCfg = &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Verification is fully replaced by the pin check below.
			InsecureSkipVerify: true, //nolint:gosec // pinned fingerprint replaces PKIX
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("server sent no certificate")
				}
				sum := sha256.Sum256(rawCerts[0])
				if !equalBytes(pinBytes, sum[:]) {
					return errors.New("panel certificate fingerprint does not match configured pin")
				}
				return nil
			},
		}
	} else {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	return &Client{
		baseURL: baseURL,
		http: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			// Never follow redirects: the token-bearing body must not be
			// replayed to another origin. ErrUseLastResponse makes Do return
			// the redirect response itself without leaking the Location URL
			// through error strings.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		log: log,
	}, nil
}

// plainHTTPAllowed reports whether a plain-http panel URL stays within a
// trusted context: loopback, the Docker host alias, or a private-network
// address (RFC 1918 / IPv6 ULA). Intranet deployments routinely reach the
// panel over plain http on a LAN IP; enrolling over such a link is a
// deployment-time trust decision (one-time token, LAN confidentiality).
// Public addresses and resolvable hostnames still require https.
// 169.254/16 link-local stays rejected: cloud metadata services live there.
func plainHTTPAllowed(hostname string) bool {
	if hostname == "" {
		return false
	}
	if strings.EqualFold(hostname, "localhost") || strings.EqualFold(hostname, "host.docker.internal") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// Bootstrap executes the enroll flow with retry on transient failures.
// 4xx responses fail immediately (one-time token semantics).
func (c *Client) Bootstrap(ctx context.Context, req Request) (credential.Credential, error) {
	if strings.TrimSpace(req.EnrollToken) == "" {
		return credential.Credential{}, errors.New("enroll token is empty")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return credential.Credential{}, fmt.Errorf("marshal request: %w", err)
	}

	var lastErr error
	backoff := []time.Duration{0, time.Second, 2 * time.Second}
	for attempt, delay := range backoff {
		select {
		case <-ctx.Done():
			return credential.Credential{}, ctx.Err()
		case <-time.After(delay):
		}

		resp, err := c.attempt(ctx, body)
		if err == nil {
			return *resp, nil
		}
		lastErr = err

		var rejected *ErrRejected
		if errors.As(err, &rejected) {
			// Permanent: one-time token was either consumed or invalid.
			return credential.Credential{}, lastErr
		}
		if c.log != nil {
			c.log.WarnContext(ctx, "bootstrap attempt failed",
				"attempt", attempt+1, "err", safeErrText(err))
		}
	}
	return credential.Credential{}, fmt.Errorf("bootstrap failed after retries: %s", safeErrText(lastErr))
}

func (c *Client) attempt(ctx context.Context, body []byte) (*credential.Credential, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+BootstrapPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err // transient (network/TLS); retry
	}
	defer func() {
		_ = httpResp.Body.Close()
	}()

	switch {
	case httpResp.StatusCode >= 200 && httpResp.StatusCode < 300:
		return c.decodeSuccess(httpResp)
	case isRedirect(httpResp.StatusCode):
		// ErrUseLastResponse hands us the redirect response itself. We never
		// follow it and never include the Location header in errors: it may
		// point at an attacker-chosen origin and can carry query secrets.
		return nil, &ErrRejected{StatusCode: httpResp.StatusCode}
	case httpResp.StatusCode >= 400 && httpResp.StatusCode < 500:
		// Drain a bounded amount for diagnostics but never log the body:
		// it may echo the token.
		_, _ = io.CopyN(io.Discard, httpResp.Body, 4<<10)
		return nil, &ErrRejected{StatusCode: httpResp.StatusCode}
	default:
		_, _ = io.CopyN(io.Discard, httpResp.Body, 4<<10)
		return nil, fmt.Errorf("panel returned http %d", httpResp.StatusCode)
	}
}

func isRedirect(status int) bool {
	return status == http.StatusMovedPermanently ||
		status == http.StatusFound ||
		status == http.StatusSeeOther ||
		status == http.StatusTemporaryRedirect ||
		status == http.StatusPermanentRedirect
}

func (c *Client) decodeSuccess(resp *http.Response) (*credential.Credential, error) {
	limited := io.LimitReader(resp.Body, 64<<10)
	var out Response
	dec := json.NewDecoder(limited)
	if err := dec.Decode(&out); err != nil {
		// Body is not the expected raw JSON (possibly a host-wrapped
		// envelope). Deterministic failure: retried requests would burn the
		// one-time token against an unchanged body, so mark it permanent.
		return nil, &ErrRejected{StatusCode: resp.StatusCode}
	}
	if out.NodeID == "" || len(out.NodeSecret) < credential.MinSecretLen {
		return nil, errors.New("bootstrap response missing nodeId or secret below entropy floor")
	}
	switch out.ControlPlan.Mode {
	case "direct":
	case "frp":
		if out.ControlPlan.FRP == nil {
			return nil, errors.New("controlPlan frp mode requires frp section")
		}
	default:
		return nil, fmt.Errorf("unsupported control plan mode %q (supported: direct, frp)", out.ControlPlan.Mode)
	}
	return &credential.Credential{
		NodeID:       out.NodeID,
		NodeSecret:   out.NodeSecret,
		ServerTimeMs: int64(out.ServerTimeMs),
		ControlPlan: credential.ControlPlan{
			Mode: out.ControlPlan.Mode,
			FRP:  out.ControlPlan.FRP,
		},
		EnrolledAtMs: time.Now().UnixMilli(),
	}, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// safeErrText strips any portion of an error that could carry response body
// bytes. HTTP body data is never embedded in enroll errors by construction;
// this is defense in depth for log emission.
func safeErrText(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return strings.ReplaceAll(msg, "\n", " ")
}

func parseOrigin(rawURL string) (*string, error) {
	// Minimal sanity: require scheme://host form. Full URL parsing happens
	// in http.NewRequest; this guards against clearly malformed config.
	scheme, rest, ok := strings.Cut(rawURL, "://")
	if !ok || (scheme != "https" && scheme != "http") || strings.TrimSpace(rest) == "" {
		return nil, errors.New("panel.url must be an absolute http(s) origin")
	}
	return &rawURL, nil
}
