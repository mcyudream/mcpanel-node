// Package p2p 实现启动器 P2P 直连的节点侧传输（设计 §5.9）。
//
// 面板即 rendezvous：面板校验授权后把 (sessionId, ticket, instanceId, targetPort, rateKbps)
// 下发到节点；节点按票据开一个**仅本会话有效**的入口，启动器（或其 sidecar）带票据握手成功后才
// 可能被转发——且**只转发到票据钉死的实例端口**（目的端钉死，协议上无法被当通用代理使用）。
//
// 传输选型：MVP 为 TCP 直连（节点开临时端口，配合公网/映射即可用）；后续把候选生成换成
// UDP 打洞 + QUIC（模块图里已有 quic-go），面板信令协议不变（双方互报 candidates）。
package p2p

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Magic 握手前缀：启动器 → 节点 `MCP2P1 <sessionId> <ticket>\n`。
	Magic = "MCP2P1"
	// 握手行上限（sessionId/ticket 均为 base64url，正常 < 128 字节）。
	maxHandshakeBytes = 512
	handshakeTimeout  = 5 * time.Second
	dialTimeout       = 5 * time.Second
	// 单会话并发连接上限（Java 服通常 1-2 条：游戏 + 查询）。
	maxConnsPerSession = 8
	// 空闲回收：双方都没数据流动超过该时长即断开本条连接。
	idleTimeout = 5 * time.Minute
	// 候选优先级：TCP 直连是 MVP 唯一路径，UDP 打洞落地后优先级更低（先试直连）。
	priorityTCP = 10
)

// OpenCommand 面板下发的开会话指令。
type OpenCommand struct {
	SessionID  string `json:"sessionId"`
	Ticket     string `json:"ticket"`
	InstanceID string `json:"instanceId"`
	// TargetPort 是**节点本机可达的实例端口**（面板分配的宿主端口；容器端口经 Docker 端口映射暴露）。
	TargetPort int   `json:"targetPort"`
	RateKbps   int   `json:"rateKbps"`
	ExpiresAt  int64 `json:"expiresAt"` // epoch ms
}

// Candidate 连接候选（打洞双方互见；MVP 只有节点自己的 TCP 入口）。
type Candidate struct {
	Proto    string `json:"proto"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Priority int    `json:"priority"`
}

// Session 一条 P2P 会话：票据 + 钉死的实例端口 + 会话期监听。
type Session struct {
	ID         string
	Ticket     string
	InstanceID string
	TargetPort int
	RateKbps   int
	ExpiresAt  time.Time

	listener  net.Listener
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	peer      []Candidate
	bytesUp   atomic.Int64 // 启动器 → 实例
	bytesDown atomic.Int64 // 实例 → 启动器
	closed    bool
	started   bool
}

// Manager 会话表与生命周期（并发安全）。
type Manager struct {
	mu            sync.Mutex
	sessions      map[string]*Session
	listenHost    string
	advertiseHost string
	dial          func(network, address string, timeout time.Duration) (net.Conn, error)
	emit          func(state string, session *Session, reason string)
}

// New 创建管理器。advertiseHost 为空时候选不下发主机，由面板按节点对外地址补齐；
// emit 用于向面板回报会话状态（connecting/direct/closed/failed + 字节数）。
func New(advertiseHost string, emit func(state string, session *Session, reason string)) *Manager {
	return &Manager{
		sessions:      map[string]*Session{},
		listenHost:    "0.0.0.0",
		advertiseHost: advertiseHost,
		dial:          net.DialTimeout,
		emit:          emit,
	}
}

// Open 按票据开面：校验参数 → 监听临时端口 → 回报候选并进入 connecting。
func (m *Manager) Open(cmd OpenCommand) (map[string]any, error) {
	if strings.TrimSpace(cmd.SessionID) == "" || strings.TrimSpace(cmd.Ticket) == "" {
		return nil, errors.New("p2p.badPayload：缺少 sessionId 或 ticket")
	}
	if cmd.TargetPort < 1 || cmd.TargetPort > 65535 {
		return nil, errors.New("p2p.badPayload：容器端口非法")
	}
	if cmd.ExpiresAt > 0 && time.Now().After(time.UnixMilli(cmd.ExpiresAt)) {
		return nil, errors.New("p2p.expired：票据已过期")
	}
	m.mu.Lock()
	if _, exists := m.sessions[cmd.SessionID]; exists {
		m.mu.Unlock()
		return nil, errors.New("p2p.exists：会话已存在")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(m.listenHost, "0"))
	if err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("p2p.listen：%w", err)
	}
	session := &Session{
		ID:         cmd.SessionID,
		Ticket:     cmd.Ticket,
		InstanceID: cmd.InstanceID,
		TargetPort: cmd.TargetPort,
		RateKbps:   cmd.RateKbps,
		ExpiresAt:  time.UnixMilli(cmd.ExpiresAt),
		listener:   listener,
		conns:      map[net.Conn]struct{}{},
	}
	m.sessions[session.ID] = session
	m.mu.Unlock()

	go m.acceptLoop(session)
	go m.expiryLoop(session)

	port := listener.Addr().(*net.TCPAddr).Port
	candidates := []Candidate{{Proto: "tcp", Host: m.advertiseHost, Port: port, Priority: priorityTCP}}
	m.report("connecting", session, "")
	return map[string]any{
		"accepted":   true,
		"sessionId":  session.ID,
		"listenPort": port,
		"candidates": candidates,
	}, nil
}

// Signal 记录启动器候选（打洞用；MVP 的 TCP 直连路径不使用，但候选必须留痕以便排障与升级）。
func (m *Manager) Signal(sessionID string, candidates []Candidate) (map[string]any, error) {
	session := m.get(sessionID)
	if session == nil {
		return nil, errors.New("p2p.notFound：会话不存在")
	}
	session.mu.Lock()
	session.peer = append([]Candidate(nil), candidates...)
	port := 0
	if session.listener != nil {
		port = session.listener.Addr().(*net.TCPAddr).Port
	}
	session.mu.Unlock()
	return map[string]any{
		"sessionId":  session.ID,
		"peerCount":  len(candidates),
		"candidates": []Candidate{{Proto: "tcp", Host: m.advertiseHost, Port: port, Priority: priorityTCP}},
	}, nil
}

// Close 关闭会话（幂等）：停止监听、断开连接、回报 closed。
func (m *Manager) Close(sessionID, reason string) bool {
	m.mu.Lock()
	session := m.sessions[sessionID]
	delete(m.sessions, sessionID)
	m.mu.Unlock()
	if session == nil {
		return false
	}
	session.shutdown(reason)
	m.report("closed", session, reason)
	return true
}

// CloseAll 控制信道断开/进程退出时回收全部会话（节点侧不留悬挂监听）。
func (m *Manager) CloseAll(reason string) {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.sessions = map[string]*Session{}
	m.mu.Unlock()
	for _, session := range sessions {
		session.shutdown(reason)
		m.report("closed", session, reason)
	}
}

// Snapshot 会话视图（面板/排障用；不含票据明文）。
func (m *Manager) Snapshot() []map[string]any {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.mu.Unlock()
	out := make([]map[string]any, 0, len(sessions))
	for _, session := range sessions {
		session.mu.Lock()
		conns := len(session.conns)
		session.mu.Unlock()
		out = append(out, map[string]any{
			"sessionId":  session.ID,
			"instanceId": session.InstanceID,
			"targetPort": session.TargetPort,
			"rateKbps":   session.RateKbps,
			"conns":      conns,
			"bytesUp":    session.bytesUp.Load(),
			"bytesDown":  session.bytesDown.Load(),
			"state":      session.state(),
		})
	}
	return out
}

// ---------- 内部 ----------

func (m *Manager) get(sessionID string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[sessionID]
}

func (s *Session) state() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "closed"
	}
	if s.started {
		return "direct"
	}
	return "connecting"
}

func (m *Manager) report(state string, session *Session, reason string) {
	if m.emit != nil {
		m.emit(state, session, reason)
	}
}

func (m *Manager) acceptLoop(session *Session) {
	for {
		conn, err := session.listener.Accept()
		if err != nil {
			return // listener 已关闭
		}
		go m.serveConn(session, conn)
	}
}

// serveConn 校验握手 → 钉死目标转发。任何失败都回一行 ERR，便于启动器给出可读提示。
func (m *Manager) serveConn(session *Session, conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()
	session.mu.Lock()
	if session.closed || len(session.conns) >= maxConnsPerSession {
		session.mu.Unlock()
		writeLine(conn, "ERR busy")
		return
	}
	session.conns[conn] = struct{}{}
	session.mu.Unlock()
	defer func() {
		session.mu.Lock()
		delete(session.conns, conn)
		session.mu.Unlock()
	}()

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	reader := bufio.NewReaderSize(conn, maxHandshakeBytes)
	line, err := reader.ReadString('\n')
	if err != nil || len(line) > maxHandshakeBytes {
		writeLine(conn, "ERR bad_handshake")
		return
	}
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) != 3 || fields[0] != Magic {
		writeLine(conn, "ERR bad_handshake")
		return
	}
	if fields[1] != session.ID || subtle.ConstantTimeCompare([]byte(fields[2]), []byte(session.Ticket)) != 1 {
		// 票据/会话不匹配：不泄露是哪一个不对
		writeLine(conn, "ERR unauthorized")
		return
	}
	// 目的端钉死：目标只来自票据（targetPort = 面板分配的宿主端口），启动器无法指定任何其它地址。
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(session.TargetPort))
	upstream, err := m.dial("tcp", target, dialTimeout)
	if err != nil {
		writeLine(conn, "ERR upstream_unreachable")
		m.report("failed", session, "实例端口不可达："+err.Error())
		return
	}
	defer func() {
		_ = upstream.Close()
	}()

	_ = conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte("OK\n")); err != nil {
		return
	}
	// 有读者可能已经在握手行之后又发了数据：bufio 里剩余字节先冲给上游。
	if buffered := reader.Buffered(); buffered > 0 {
		peeked, _ := reader.Peek(buffered)
		if _, err := upstream.Write(peeked); err != nil {
			return
		}
		_, _ = reader.Discard(buffered)
	}

	session.mu.Lock()
	firstStream := !session.started
	session.started = true
	session.mu.Unlock()
	if firstStream {
		m.report("direct", session, "")
	}

	limiter := newBucket(session.RateKbps)
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	go func() { // 启动器 → 实例
		defer waitGroup.Done()
		copyPump(upstream, conn, limiter, &session.bytesUp)
		closeWrite(upstream)
	}()
	go func() { // 实例 → 启动器
		defer waitGroup.Done()
		copyPump(conn, upstream, limiter, &session.bytesDown)
		closeWrite(conn)
	}()
	waitGroup.Wait()
	m.report(session.state(), session, "")
}

func writeLine(conn net.Conn, line string) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	_, _ = conn.Write([]byte(line + "\n"))
}

func closeWrite(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
		return
	}
	_ = conn.Close()
}

func (s *Session) shutdown(reason string) {
	s.mu.Lock()
	alreadyClosed := s.closed
	s.closed = true
	listener := s.listener
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.conns = map[net.Conn]struct{}{}
	s.mu.Unlock()
	if alreadyClosed {
		return
	}
	if listener != nil {
		_ = listener.Close()
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	_ = reason
}

func (m *Manager) expiryLoop(session *Session) {
	if session.ExpiresAt.IsZero() {
		return
	}
	timer := time.NewTimer(time.Until(session.ExpiresAt))
	defer timer.Stop()
	<-timer.C
	m.mu.Lock()
	_, exists := m.sessions[session.ID]
	if exists {
		delete(m.sessions, session.ID)
	}
	m.mu.Unlock()
	if !exists {
		return
	}
	session.shutdown("票据过期")
	m.report("closed", session, "票据过期")
	if m.emit != nil {
		// 额外回报一次失败原因，便于面板审计区分"过期回收"
		m.emit("closed", session, "票据过期")
	}
}

// ---------- 限速（每连接字节级 token bucket，节点本地执行） ----------

type bucket struct {
	mu        sync.Mutex
	tokens    float64
	burst     float64
	ratePerMs float64
	last      time.Time
}

func newBucket(rateKbps int) *bucket {
	if rateKbps <= 0 {
		return nil
	}
	burst := float64(rateKbps) * 1024 / 4 // 250ms 突发
	return &bucket{tokens: burst, burst: burst, ratePerMs: float64(rateKbps) * 1024 / 1000, last: time.Now()}
}

// take 返回需要等待的时长（0 = 立即放行）。
func (b *bucket) take(n int) time.Duration {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += float64(now.Sub(b.last).Milliseconds()) * b.ratePerMs
	b.last = now
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	if b.tokens >= float64(n) {
		b.tokens -= float64(n)
		return 0
	}
	missing := float64(n) - b.tokens
	b.tokens = 0
	return time.Duration(missing/b.ratePerMs) * time.Millisecond
}

// copyPump 双向泵的一侧：整块搬运 + 限速 + 空闲回收 + 计量。
func copyPump(dst, src net.Conn, limiter *bucket, counter *atomic.Int64) {
	buffer := make([]byte, 32*1024)
	for {
		_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := src.Read(buffer)
		if n > 0 {
			if wait := limiter.take(n); wait > 0 {
				time.Sleep(wait)
			}
			written, writeErr := dst.Write(buffer[:n])
			counter.Add(int64(written))
			_ = dst.SetReadDeadline(time.Now().Add(idleTimeout))
			if writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// BytesUp 启动器 → 实例 的累计字节（面板审计/展示用）。
func (s *Session) BytesUp() int64 {
	return s.bytesUp.Load()
}

// BytesDown 实例 → 启动器 的累计字节。
func (s *Session) BytesDown() int64 {
	return s.bytesDown.Load()
}

// MarshalCandidates 便于 wsserver 回包（保持 JSON 字段与面板一致）。
func MarshalCandidates(candidates []Candidate) []map[string]any {
	out := make([]map[string]any, 0, len(candidates))
	for _, candidate := range candidates {
		raw, _ := json.Marshal(candidate)
		var item map[string]any
		_ = json.Unmarshal(raw, &item)
		out = append(out, item)
	}
	return out
}
