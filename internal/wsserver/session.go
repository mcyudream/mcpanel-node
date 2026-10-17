package wsserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/oklog/ulid/v2"

	"github.com/yudream/mcpanel-node/internal/proto"
)

// session is one established control connection. A node serves at most one
// active session: a newer authenticated connection replaces the older one,
// which is closed with 4000 (protocol §3).
type session struct {
	id   string
	conn *websocket.Conn
	log  *slog.Logger

	ctx     context.Context
	cancel  context.CancelFunc
	writeCh chan []byte

	// 并发分发闸门：慢操作（大目录 file.list、备份等）不得阻塞读循环，
	// 否则控制台 output.read 轮询与终端推送被队头阻塞。出站帧仍由
	// writer goroutine 串行化；Mutate 自带实例级串行与 ik 幂等。
	dispatchSem chan struct{}

	seqMu       sync.Mutex
	seqByTopic  map[string]int64
	helloSeen   bool
	statsCancel context.CancelFunc

	outputMu   sync.Mutex
	outputSubs map[string]context.CancelFunc
}

func newSession(conn *websocket.Conn) *session {
	// ctx is derived from the request context by serve(); the placeholder
	// here is replaced before any use (see serve).
	ctx, cancel := context.WithCancel(context.Background())
	return &session{
		id:          ulid.Make().String(),
		conn:        conn,
		log:         slog.Default(),
		ctx:         ctx,
		cancel:      cancel,
		writeCh:     make(chan []byte, 32),
		dispatchSem: make(chan struct{}, maxConcurrentDispatch),
		seqByTopic:  map[string]int64{},
		outputSubs:  map[string]context.CancelFunc{},
	}
}

func (s *session) replace() {
	// 先以 4000 关闭再 cancel：serve() 的 writer goroutine 在 ctx.Done 后会以
	// 1000 兜底关闭，二者并发时只有先到者生效；协议 §3 要求被替换会话必须
	// 以 4000 关闭，顺序颠倒会让面板看到 1000（TestSessionReplacementClose4000）。
	_ = s.conn.Close(closeReplaced, "replaced by newer control connection")
	s.cancel()
}

func (s *session) shutdown() {
	s.cancel()
}

// serve runs the read loop and the writer until the connection dies.
// serveCtx is the HTTP request context: process shutdown propagates through
// it, and Server.Shutdown force-closes the hijacked connection on top.
func (s *session) serve(serveCtx context.Context, srv *Server) {
	// Re-derive the session context from the live request context so both
	// request-level and process-level cancellation reach the stats pump and
	// the writer.
	ctx, cancel := context.WithCancel(serveCtx)
	s.cancel() // release the placeholder pair from newSession
	s.cancel = cancel
	s.ctx = ctx
	s.log = srv.log

	// Writer goroutine serializes all outbound frames.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-s.ctx.Done():
				_ = s.conn.Close(websocket.StatusNormalClosure, "session closed")
				return
			case frame := <-s.writeCh:
				wctx, wcancel := context.WithTimeout(s.ctx, writeTimeout)
				err := s.conn.Write(wctx, websocket.MessageText, frame)
				wcancel()
				if err != nil {
					s.log.Debug("write failed", "err", err)
					s.cancel()
					_ = s.conn.CloseNow()
					return
				}
			}
		}
	}()
	defer func() {
		s.cancel()
		<-writerDone
	}()

	// Read loop: bounded by conn read limit (set before session creation).
	for {
		if s.ctx.Err() != nil {
			break
		}
		msgType, data, err := s.conn.Read(s.ctx)
		if err != nil {
			if websocket.CloseStatus(err) == websocket.StatusMessageTooBig {
				s.log.Warn("frame exceeded read limit", "sessionId", s.id)
				_ = s.conn.Close(websocket.StatusMessageTooBig, "proto.badFrame: frame exceeds read limit")
			} else {
				s.log.Debug("read ended", "sessionId", s.id, "err", err)
			}
			break
		}
		// The protocol is JSON text-only; binary frames are rejected with
		// 1003 (unsupported data).
		if msgType != websocket.MessageText {
			s.log.Warn("binary frame rejected", "sessionId", s.id)
			_ = s.conn.Close(websocket.StatusUnsupportedData, "protocol is text-only")
			break
		}
		if !s.handleFrame(data, srv) {
			break
		}
	}
}

// handleFrame dispatches one inbound frame. Returns false to terminate the
// read loop.
func (s *session) handleFrame(data []byte, srv *Server) bool {
	env, err := proto.Decode(data)
	if err != nil {
		// Cannot correlate without a decodable envelope; ignore and keep the
		// session (panel is the trusted authenticated peer).
		s.log.Warn("undecodable frame", "sessionId", s.id, "err", err)
		return true
	}

	switch env.T {
	case proto.TypeReq:
		if env.M == proto.MethodNodeHello {
			s.handleHello(env, srv)
			return true
		}
		var p map[string]any
		if len(env.P) > 0 {
			if err := json.Unmarshal(env.P, &p); err != nil {
				s.sendErr(env.ID, env.M, "proto.badPayload", "payload must be a JSON object", false)
				return true
			}
		}
		ik := strField(p, "ik")
		// 并发分发：慢操作（大目录 file.list、压缩、备份）不得队头阻塞
		// 后续帧——控制台 output.read 轮询的低延迟依赖于此。响应可能乱序
		// 返回，面板按请求 id 匹配（pending map），乱序无影响。
		// 超过并发上限的请求排队等待（而非立即拒绝）：日常突发在槽位释放
		// 的毫秒级窗口内即可入列，node.busy 只在真正过载（等待超 8s）时出现。
		select {
		case s.dispatchSem <- struct{}{}:
		case <-time.After(dispatchQueueWait):
			s.sendErr(env.ID, env.M, "node.busy", "节点并发处理已达上限（排队 8s 未获槽位），请稍后重试", true)
			return true
		case <-s.ctx.Done():
			return true
		}
		go func() {
			defer func() { <-s.dispatchSem }()
			result, derr := srv.Dispatch(s.ctx, env.M, p, ik)
			if derr != nil {
				code, message, retryable := AsProtocolError(derr)
				s.sendErr(env.ID, env.M, code, message, retryable)
				return
			}
			raw, merr := json.Marshal(result)
			if merr != nil {
				s.sendErr(env.ID, env.M, "internal.error", "marshal res failed", false)
				return
			}
			// 超过帧上限的响应必须显式回错（如未分页的大目录 file.list），
			// 否则 Encode 静默丢帧、面板只能等到超时，问题无法定位。
			if len(raw) > proto.MaxFrameBytes-128 {
				s.sendErr(env.ID, env.M, "node.responseTooLarge",
					"响应超过单帧上限（proto.MaxFrameBytes），请使用分页/过滤缩小结果", false)
				return
			}
			s.send(&proto.Envelope{V: proto.ProtocolVersion, ID: env.ID, T: proto.TypeRes, M: env.M, P: raw})
		}()
		return true
	case proto.TypeRes, proto.TypeErr, proto.TypeEvt:
		// Node-initiated traffic is evt-only; inbound res/err/evt from the
		// panel has no handler. Ignore.
	default:
		s.sendErr(env.ID, env.M, "proto.badFrame", "unknown frame type", false)
	}
	return true
}

func strField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

// sendWithSeq assigns the next per-topic sequence number and queues an evt.
func (s *session) sendWithSeq(env *proto.Envelope) {
	seq := s.nextSeq(env.M)
	env.Seq = &seq
	s.send(env)
}

// handleHello answers the panel identity request exactly once per session
// and kicks the stats pump: first stats immediately after hello, then every
// 5s (protocol §5.2). Repeated hello on the same session is a protocol
// violation and is answered with err; the pump is never restarted.
func (s *session) handleHello(req *proto.Envelope, srv *Server) {
	var p struct {
		PanelVersion string `json:"panelVersion"`
	}
	if len(req.P) == 0 {
		s.sendErr(req.ID, req.M, proto.CodeBadPayload, "node.hello requires {panelVersion}", false)
		return
	}
	if err := json.Unmarshal(req.P, &p); err != nil || strings.TrimSpace(p.PanelVersion) == "" {
		s.sendErr(req.ID, req.M, proto.CodeBadPayload, "node.hello requires a non-empty panelVersion", false)
		return
	}

	s.seqMu.Lock()
	if s.helloSeen {
		s.seqMu.Unlock()
		s.sendErr(req.ID, req.M, proto.CodeBadFrame,
			"node.hello must be sent exactly once per session", false)
		return
	}
	s.helloSeen = true
	s.seqMu.Unlock()

	// srv.hostname is authoritative: the app layer resolves config
	// tls.hostname with the OS hostname fallback before constructing the
	// Server, so the session must not re-derive it.
	resPayload := nodeInfoPayload{
		NodeID:       srv.cred.NodeID,
		SessionID:    s.id,
		Hostname:     srv.hostname,
		AgentVersion: srv.agentVersion(),
		Caps:         srv.capsList(),
	}
	if dvs, ok := srv.stats.(DockerVersionSource); ok {
		if v := dvs.DockerVersion(s.ctx); v != "" {
			resPayload.DockerVersion = v
		}
	}

	raw, err := json.Marshal(resPayload)
	if err != nil {
		s.sendErr(req.ID, req.M, proto.CodeInternal, "marshal hello res failed", false)
		return
	}
	res := &proto.Envelope{V: proto.ProtocolVersion, ID: req.ID, T: proto.TypeRes, M: req.M}
	res.P = raw
	if !s.send(res) {
		return
	}

	s.startStats(srv)
}

// startStats launches the single per-session stats pump. It is only invoked
// from the first successful hello.
func (s *session) startStats(srv *Server) {
	s.seqMu.Lock()
	if s.statsCancel != nil { // belt and braces: hello-once already guards this
		s.seqMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	s.statsCancel = cancel
	s.seqMu.Unlock()

	go func() {
		ticker := time.NewTicker(statsInterval)
		defer ticker.Stop()
		send := func() {
			if srv.stats == nil {
				return
			}
			snap := srv.stats.Collect(ctx)
			seq := s.nextSeq(proto.TopicNodeStats)
			evt, err := proto.NewEvt(proto.TopicNodeStats, seq, snap)
			if err != nil {
				s.log.Warn("marshal stats failed", "err", err)
				return
			}
			s.send(evt)
		}
		send() // immediate first frame after hello
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				send()
			}
		}
	}()
}

func (s *session) nextSeq(topic string) int64 {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	s.seqByTopic[topic]++
	return s.seqByTopic[topic] - 1
}

func (s *session) sendErr(reqID, method, code, message string, retryable bool) {
	s.send(proto.NewErr(reqID, method, code, message, retryable))
}

// send queues a frame for the writer. A full outbound queue means the peer
// cannot keep up: the connection is closed instead of silently dropping
// frames (req must always be answered — dropping a res would hang the peer).
func (s *session) send(env *proto.Envelope) bool {
	data, err := env.Encode()
	if err != nil {
		s.log.Warn("encode frame failed", "err", err)
		return false
	}
	select {
	case <-s.ctx.Done():
		return false
	case s.writeCh <- data:
		return true
	default:
		s.log.Warn("outbound queue full; closing slow connection", "sessionId", s.id)
		s.cancel()
		_ = s.conn.Close(websocket.StatusPolicyViolation, "slow consumer")
		return false
	}
}
