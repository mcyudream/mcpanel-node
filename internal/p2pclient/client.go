// Package p2pclient 是启动器 P2P 直连的**客户端侧**（sidecar）实现：
// 向面板开会话拿票据与节点候选 → 本地只监听 127.0.0.1 → 玩家客户端连本地端口后，
// 带票据与节点握手并双向转发。协议与约束见 docs/mc-panel-p2p-protocol.md（宿主仓）。
//
// 安全要点：只监听 loopback（不做任何公网监听）；票据由面板下发且绑定实例端口，
// sidecar 无法指定目标地址——节点侧只把流量送进票据钉死的端口。
package p2pclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Magic 与节点握手前缀（必须与 mcpanel-node internal/p2p 一致）。
const Magic = "MCP2P1"

const (
	handshakeTimeout     = 5 * time.Second
	defaultStatusEvery   = 2 * time.Second
	defaultLocalBindAddr = "127.0.0.1:0"
	// defaultApiPath 是启动器适配器（ymcl-adapter）暴露的 P2P 接口前缀。
	defaultApiPath = "/api/plugins/ymcl-adapter/v1/p2p"
)

// Candidate 节点候选（打洞双方互见；TCP 直连只用 host:port）。
type Candidate struct {
	Proto    string `json:"proto"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Priority int    `json:"priority"`
}

// Session 会话响应（适配器 YAP 载荷：snake_case）。
type Session struct {
	SessionID      string      `json:"session_id"`
	InstanceID     string      `json:"instance_id"`
	NodeID         string      `json:"node_id"`
	State          string      `json:"state"`
	Terminal       bool        `json:"terminal"`
	Ticket         string      `json:"ticket"`
	TargetPort     int         `json:"target_port"`
	RateKbps       int         `json:"rate_kbps"`
	ExpiresAt      int64       `json:"expires_at"`
	NodeCandidates []Candidate `json:"candidates"`
	Reason         string      `json:"reason"`
}

// Status 会话状态（与 Session 同形，便于直接复用解析）。
type Status = Session

// Error 面板业务错误（含机器码，便于给玩家可读提示）。
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("面板返回 HTTP %d：%s", e.Status, e.Message)
	}
	return fmt.Sprintf("%s：%s", e.Code, e.Message)
}

// Client 面板玩家面 API 客户端。
type Client struct {
	base       string
	token      string
	authScheme string
	http       *http.Client
}

// NewClient 创建客户端。base 是启动器提供的域接口基址（如
// `https://panel/api/plugins/ymcl-adapter/v1/p2p`）；token 原样放进
// `Authorization` 头——宿主与启动器都用裸 token，不带 scheme 前缀。
// 传纯站点根地址时会自动补全适配器 P2P 路径前缀。
func NewClient(base, token string) *Client {
	trimmed := strings.TrimRight(strings.TrimSpace(base), "/")
	// 允许直接传适配器宣告的 session_url（…/p2p/session）：基址去掉后缀。
	trimmed = strings.TrimSuffix(trimmed, "/session")
	if !strings.Contains(trimmed, "/p2p") {
		trimmed += defaultApiPath
	}
	return &Client{
		base:  trimmed,
		token: token,
		http:  &http.Client{Timeout: 15 * time.Second},
	}
}

// WithAuthScheme 在 token 前加 scheme（如 "Bearer"）；空值 = 裸 token。
func (c *Client) WithAuthScheme(scheme string) *Client {
	c.authScheme = strings.TrimSpace(scheme)
	return c
}

// OpenSession 开会话：返回票据与节点候选。
func (c *Client) OpenSession(ctx context.Context, instanceID string) (*Session, error) {
	body, err := c.do(ctx, http.MethodPost, "/session", map[string]any{"instance_id": instanceID})
	if err != nil {
		return nil, err
	}
	var session Session
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, fmt.Errorf("会话响应解析失败：%w", err)
	}
	if session.SessionID == "" || session.Ticket == "" {
		return nil, errors.New("面板未返回有效票据")
	}
	return &session, nil
}

// SignalCandidates 上报本端候选（打洞用；TCP 直连路径可省略，但留痕便于排障）。
func (c *Client) SignalCandidates(ctx context.Context, sessionID string, candidates []Candidate) (*Session, error) {
	body, err := c.do(ctx, http.MethodPost, "/session/signal", map[string]any{
		"session_id": sessionID,
		"candidates": candidates,
	})
	if err != nil {
		return nil, err
	}
	var session Session
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, fmt.Errorf("候选响应解析失败：%w", err)
	}
	return &session, nil
}

// Status 查询会话状态（启动器轮询：failed/closed 时停止转发）。
func (c *Client) Status(ctx context.Context, sessionID string) (*Status, error) {
	body, err := c.do(ctx, http.MethodGet, "/session?session_id="+url.QueryEscape(sessionID), nil)
	if err != nil {
		return nil, err
	}
	var status Status
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("状态响应解析失败：%w", err)
	}
	return &status, nil
}

// CloseSession 关闭会话（幂等；进程被强杀时由节点按 TTL 兜底回收）。
func (c *Client) CloseSession(ctx context.Context, sessionID, reason string) error {
	_, err := c.do(ctx, http.MethodDelete,
		"/session?session_id="+url.QueryEscape(sessionID)+"&reason="+url.QueryEscape(reason), nil)
	return err
}

func (c *Client) do(ctx context.Context, method, path string, payload any) ([]byte, error) {
	var reader io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		value := c.token
		if c.authScheme != "" {
			value = c.authScheme + " " + c.token
		}
		request.Header.Set("Authorization", value)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("面板不可达：%w", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode/100 != 2 {
		return nil, decodeError(response.StatusCode, body)
	}
	return body, nil
}

func decodeError(status int, body []byte) error {
	var envelope struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && (envelope.Code != "" || envelope.Message != "") {
		return &Error{Status: status, Code: envelope.Code, Message: envelope.Message}
	}
	text := strings.TrimSpace(string(body))
	if len(text) > 200 {
		text = text[:200] + "…"
	}
	return &Error{Status: status, Message: text}
}

// ---------- 与节点建流 ----------

// Dial 按优先级依次尝试候选，完成票据握手后返回可用的双向连接。
func Dial(ctx context.Context, sessionID, ticket string, candidates []Candidate) (net.Conn, Candidate, error) {
	if len(candidates) == 0 {
		return nil, Candidate{}, errors.New("节点未提供可直连的候选地址（打洞路径尚未实现时需节点公网可达或已做端口映射）")
	}
	ordered := orderCandidates(candidates)
	var lastErr error
	for _, candidate := range ordered {
		if candidate.Host == "" || candidate.Port <= 0 {
			continue
		}
		conn, err := dialCandidate(ctx, sessionID, ticket, candidate)
		if err == nil {
			return conn, candidate, nil
		}
		var nodeErr *nodeHandshakeError
		if errors.As(err, &nodeErr) && nodeErr.Code == "unauthorized" {
			// 票据被拒：换候选也没用（可能已被管理员吊销/过期）
			return nil, candidate, err
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的候选地址")
	}
	return nil, Candidate{}, lastErr
}

type nodeHandshakeError struct {
	Code string
}

func (e *nodeHandshakeError) Error() string {
	return "节点拒绝握手：" + e.Code
}

func dialCandidate(ctx context.Context, sessionID, ticket string, candidate Candidate) (net.Conn, error) {
	address := net.JoinHostPort(candidate.Host, fmt.Sprintf("%d", candidate.Port))
	dialer := &net.Dialer{Timeout: handshakeTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("连接候选 %s 失败：%w", address, err)
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if _, err := fmt.Fprintf(conn, "%s %s %s\n", Magic, sessionID, ticket); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("握手写入失败：%w", err)
	}
	reader := bufio.NewReaderSize(conn, 256)
	line, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("握手应答读取失败：%w", err)
	}
	answer := strings.TrimSpace(line)
	if answer != "OK" {
		_ = conn.Close()
		code := strings.TrimSpace(strings.TrimPrefix(answer, "ERR"))
		return nil, &nodeHandshakeError{Code: code}
	}
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

// bufferedConn 保留握手后可能已被 bufio 预读的字节（节点侧 ACK 与数据可能同一批到达）。
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func orderCandidates(candidates []Candidate) []Candidate {
	ordered := make([]Candidate, len(candidates))
	copy(ordered, candidates)
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && ordered[j].Priority < ordered[j-1].Priority; j-- {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
		}
	}
	return ordered
}

// ---------- 本地入口（sidecar 主体） ----------

// Config sidecar 运行参数。
type Config struct {
	PanelBase       string
	Token           string
	AuthScheme      string // 空 = 裸 token（宿主与启动器约定）
	InstanceID      string
	LocalAddr       string // 默认 127.0.0.1:0（只监听 loopback）
	StatusEvery     time.Duration
	LocalCandidates []Candidate // 可选：上报给面板的本端候选（TCP 直连可空）
	OnReady         func(localAddr string, session *Session)
	Logf            func(format string, args ...any)
}

// Run 运行 sidecar：开会话 → 本地监听 → 转发玩家流量 → 面板状态驱动退出。
// ctx 取消即回收会话（并通知节点关闭入口）。
func Run(ctx context.Context, config Config) error {
	logf := config.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if strings.TrimSpace(config.PanelBase) == "" || strings.TrimSpace(config.InstanceID) == "" {
		return errors.New("缺少面板地址或实例 ID")
	}
	localAddr := config.LocalAddr
	if strings.TrimSpace(localAddr) == "" {
		localAddr = defaultLocalBindAddr
	}
	statusEvery := config.StatusEvery
	if statusEvery <= 0 {
		statusEvery = defaultStatusEvery
	}

	client := NewClient(config.PanelBase, config.Token).WithAuthScheme(config.AuthScheme)
	session, err := client.OpenSession(ctx, config.InstanceID)
	if err != nil {
		return err
	}
	logf("会话已开启 sessionId=%s 目标端口=%d 速率档=%d kbps", session.SessionID, session.TargetPort, session.RateKbps)
	if len(config.LocalCandidates) > 0 {
		if _, err := client.SignalCandidates(ctx, session.SessionID, config.LocalCandidates); err != nil {
			logf("候选中继失败（不影响 TCP 直连）：%v", err)
		}
	}

	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		_ = client.CloseSession(context.Background(), session.SessionID, "本地监听失败")
		return fmt.Errorf("本地监听失败：%w", err)
	}
	defer func() { _ = listener.Close() }()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var conns sync.WaitGroup
	var mu sync.Mutex
	active := map[net.Conn]struct{}{}
	track := func(conn net.Conn, add bool) {
		mu.Lock()
		defer mu.Unlock()
		if add {
			active[conn] = struct{}{}
			return
		}
		delete(active, conn)
	}
	closeAll := func() {
		mu.Lock()
		defer mu.Unlock()
		for conn := range active {
			_ = conn.Close()
		}
		active = map[net.Conn]struct{}{}
	}

	if config.OnReady != nil {
		config.OnReady(listener.Addr().String(), session)
	}
	logf("本地入口已就绪 %s（只监听 loopback）", listener.Addr().String())

	candidates := session.NodeCandidates
	go watchStatus(runCtx, cancel, client, session.SessionID, statusEvery, logf,
		func(latest []Candidate) {
			mu.Lock()
			candidates = latest
			mu.Unlock()
		}, closeAll)

	go func() {
		<-runCtx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			break // runCtx 取消或监听关闭
		}
		mu.Lock()
		latest := candidates
		mu.Unlock()
		track(conn, true)
		conns.Add(1)
		go func() {
			defer conns.Done()
			defer track(conn, false)
			defer func() { _ = conn.Close() }()
			upstream, candidate, err := Dial(runCtx, session.SessionID, session.Ticket, latest)
			if err != nil {
				logf("建立 P2P 链路失败：%v", err)
				return
			}
			defer func() { _ = upstream.Close() }()
			track(upstream, true)
			defer track(upstream, false)
			logf("已直连节点 %s:%d", candidate.Host, candidate.Port)
			pump(conn, upstream)
		}()
	}
	closeAll()
	conns.Wait()
	_ = client.CloseSession(context.Background(), session.SessionID, "启动器退出")
	return nil
}

// watchStatus 轮询面板状态：终态（failed/closed/expired）立即停止转发并向玩家给出原因。
func watchStatus(ctx context.Context, cancel context.CancelFunc, client *Client, sessionID string,
	every time.Duration, logf func(string, ...any), updateCandidates func([]Candidate), closeAll func()) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		status, err := client.Status(ctx, sessionID)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logf("会话状态查询失败：%v", err)
			continue
		}
		if len(status.NodeCandidates) > 0 {
			updateCandidates(status.NodeCandidates)
		}
		switch status.State {
		case "failed", "closed", "expired":
			reason := status.Reason
			if reason == "" {
				reason = status.State
			}
			logf("会话已结束（%s）：%s；已断开本地连接", status.State, reason)
			closeAll()
			cancel()
			return
		}
	}
}

// pump 双向转发（Java 客户端断开时结束整条链路）。
func pump(local, upstream net.Conn) {
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		_, _ = io.Copy(upstream, local)
		closeWrite(upstream)
	}()
	go func() {
		defer waitGroup.Done()
		_, _ = io.Copy(local, upstream)
		closeWrite(local)
	}()
	waitGroup.Wait()
}

func closeWrite(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
		return
	}
	if wrapped, ok := conn.(*bufferedConn); ok {
		if tcp, ok := wrapped.Conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
			return
		}
	}
	_ = conn.Close()
}
