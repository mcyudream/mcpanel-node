// Package wsserver implements the node side of the control channel
// (protocol docs/mc-panel-protocol-v1.md §3-§9).
package wsserver

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/yudream/mcpanel-node/internal/config"
	"github.com/yudream/mcpanel-node/internal/credential"
	"github.com/yudream/mcpanel-node/internal/dockerx"
	"github.com/yudream/mcpanel-node/internal/fileutil"
	"github.com/yudream/mcpanel-node/internal/ftpserv"
	"github.com/yudream/mcpanel-node/internal/instances"
	"github.com/yudream/mcpanel-node/internal/p2p"
	"github.com/yudream/mcpanel-node/internal/proto"
	"github.com/yudream/mcpanel-node/internal/shellterm"
	"github.com/yudream/mcpanel-node/internal/stats"
	"github.com/yudream/mcpanel-node/internal/tasks"
	"github.com/yudream/mcpanel-node/internal/version"
)

// ControlPath is the frozen control channel path. The panel stores the node
// endpoint as authority-only (wss://host[:port]) and appends this path.
const ControlPath = "/control"

// StatsSource produces node.stats snapshots. Production wiring uses
// *stats.Collector; tests may substitute an in-memory source.
type StatsSource interface {
	Collect(ctx context.Context) stats.Snapshot
}

// DockerVersionSource is optionally implemented by StatsSource providers to
// expose the daemon version for node.hello (omitted when unavailable).
type DockerVersionSource interface {
	DockerVersion(ctx context.Context) string
}

// DockerEngine is the mutable surface used by business operations; nil means
// Docker is unavailable and all business methods answer a clean error.
type DockerEngine interface {
	instances.Engine
	Pull(ctx context.Context, image string) error
	ListImages(ctx context.Context) ([]dockerx.ImageInfo, error)
	RemoveImage(ctx context.Context, image string, force bool) error
	ListAllContainers(ctx context.Context) ([]map[string]any, error)
	Events(ctx context.Context, since string, sink func(containerID, action, instanceID string)) error
	AttachStream(ctx context.Context, containerID string, includeHistory bool) (io.ReadCloser, error)
}

const (
	failWindow    = time.Minute
	failLimit     = 10
	maxTrackedIPs = 1024 // bounded failure map; overflow resets expired/all
	writeTimeout  = 10 * time.Second
	statsInterval = 5 * time.Second
	// Per-session concurrent request dispatch cap (protocol: read-only ops
	// must not queue behind slow ops; Mutate stays instance-serialized).
	maxConcurrentDispatch = 32
	// 排队等待窗口：快操作毫秒级释放槽位，突发只排队不拒绝。
	dispatchQueueWait = 8 * time.Second
	closeReplaced = 4000 // protocol §3: session replacement close code
)

// Server is the node control channel endpoint.
type Server struct {
	cred     credential.Credential
	stats    StatsSource
	hostname string
	log      *slog.Logger

	engine      DockerEngine
	instances   *instances.Service
	files       *fileutil.Manager
	backupFiles *fileutil.Manager
	tasks       *tasks.Registry
	backupDir   string
	ftp         *ftpserv.Manager
	ftpBasePort int
	shellterm   *shellterm.Manager
	p2p         *p2p.Manager
	fileRoots   []config.FileRootConfig
	termEnabled bool
	completer   shellCompleter
	lifecycle   context.Context

	failMu      sync.Mutex
	failIP      map[string]*failRecord
	rejectCount uint64
	lastRejLog  time.Time

	sessionMu sync.Mutex
	current   *session
	closed    bool
}

type failRecord struct {
	count  int
	window time.Time
}

// Options carries the business wiring; Engine/Instances may be nil (Docker off).
type Options struct {
	Credential      credential.Credential
	Stats           StatsSource
	Hostname        string
	Log             *slog.Logger
	Engine          DockerEngine
	Instances       *instances.Service
	Files           *fileutil.Manager
	Tasks           *tasks.Registry
	FTP             *ftpserv.Manager
	FTPBasePort     int
	ShellTerm       *shellterm.Manager
	FileRoots       []config.FileRootConfig
	TerminalEnabled bool
	BackupDir       string
	Lifecycle       context.Context
}

// New builds the control channel server.
func New(opts Options) *Server {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	hostname := opts.Hostname
	if hostname == "" {
		hostname = "unknown"
	}
	lifecycle := opts.Lifecycle
	if lifecycle == nil {
		lifecycle = context.Background()
	}
	s := &Server{
		cred:        opts.Credential,
		stats:       opts.Stats,
		hostname:    hostname,
		log:         log,
		engine:      opts.Engine,
		instances:   opts.Instances,
		files:       opts.Files,
		tasks:       opts.Tasks,
		backupDir:   opts.BackupDir,
		lifecycle:   lifecycle,
		ftp:         opts.FTP,
		ftpBasePort: opts.FTPBasePort,
		shellterm:   opts.ShellTerm,
		fileRoots:   opts.FileRoots,
		termEnabled: opts.TerminalEnabled,
		failIP:      map[string]*failRecord{},
	}
	// 备份目录分块上传会话：与实例文件上传同一 Manager，但根固定为全局备份目录
	// （面板整包拉取/回灌实例归档专用；backupDir 未配置时不启用，相关 RPC 一律拒绝）。
	if opts.BackupDir != "" {
		s.backupFiles = fileutil.NewManager(func(string) (string, error) { return opts.BackupDir, nil })
	}
	// P2P 会话入口：候选主机留空由面板按节点对外地址补齐（节点不知道自己的公网地址）
	s.p2p = p2p.New("", s.emitP2PSessionState)
	// 启动成功检测窗口结束（命中标记/超时）→ 把 running 回推给面板；
	// 无活动连接时静默丢弃（面板重连后由快照/Inspect 给出权威状态）。
	if s.instances != nil {
		s.instances.SetOnStateChange(func(instanceID, state string) {
			s.pushInstanceState(instanceID, state)
		})
	}
	return s
}

// emitP2PSessionState 把会话状态推给面板（无活动连接时静默丢弃，面板按 TTL 兜底回收）。
func (s *Server) emitP2PSessionState(state string, session *p2p.Session, reason string) {
	if session == nil {
		return
	}
	s.sessionMu.Lock()
	current := s.current
	s.sessionMu.Unlock()
	if current == nil {
		return
	}
	payload := map[string]any{
		"sessionId":     session.ID,
		"instanceId":    session.InstanceID,
		"state":         state,
		"targetPort": session.TargetPort,
		"bytesSent":     session.BytesUp(),
		"bytesReceived": session.BytesDown(),
	}
	if reason != "" {
		payload["reason"] = reason
	}
	env, err := proto.NewEvt(proto.TopicP2PSessionState, current.nextSeq(proto.TopicP2PSessionState), payload)
	if err != nil {
		return
	}
	current.send(env)
}

// StartEvents subscribes to Docker container events and pushes
// evt instance.state to the active session. Safe to call once at startup.
func (s *Server) StartEvents() {
	if s.engine == nil || s.lifecycle == nil {
		return
	}
	go func() {
		for s.lifecycle.Err() == nil {
			err := s.engine.Events(s.lifecycle, "", func(containerID, action, instanceID string) {
				if instanceID == "" {
					return
				}
				s.handleContainerEvent(instanceID, action)
			})
			if s.lifecycle.Err() != nil {
				return
			}
			s.log.Warn("docker events stream ended; retrying", "err", err)
			select {
			case <-s.lifecycle.Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
	}()
}

// handleContainerEvent 单个 docker 容器事件 → 面板状态：
// - start/unpause：若实例配置了启动成功标记则进入 starting 窗口（命中/超时后
//   由 instances.Service 回推 running），否则维持原映射直接报 running；
// - die/stop/destroy/pause：先收口启动检测窗口再按原映射报 exited/stopped 等。
func (s *Server) handleContainerEvent(instanceID, action string) {
	switch action {
	case "start", "unpause":
		if s.instances != nil && s.instances.BeginStartWatch(instanceID) {
			s.pushInstanceState(instanceID, "starting")
			return
		}
		s.pushInstanceState(instanceID, "running")
	case "die", "stop", "destroy", "pause":
		if s.instances != nil {
			s.instances.CancelStartWatch(instanceID)
		}
		state := map[string]string{"die": "exited", "stop": "stopped",
			"destroy": "removed", "pause": "paused"}[action]
		if state != "" {
			s.pushInstanceState(instanceID, state)
		}
	}
}

// pushInstanceState 推送一条实例状态事件（无活动连接时静默丢弃）。
func (s *Server) pushInstanceState(instanceID, state string) {
	s.sessionMu.Lock()
	sess := s.current
	s.sessionMu.Unlock()
	if sess == nil {
		return
	}
	payload, _ := json.Marshal(map[string]any{"instanceId": instanceID, "state": state})
	env := &proto.Envelope{V: proto.ProtocolVersion, T: proto.TypeEvt, M: "instance.state", TS: time.Now().UnixMilli(), P: payload}
	sess.sendWithSeq(env)
}

// Handler returns the HTTP handler serving /control over TLS.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(ControlPath, s.handleControl)
	return mux
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip, _, _ := splitHostPort(r.RemoteAddr)

	if s.isClosed() {
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		return
	}
	if !s.authenticate(w, r, ip) {
		return // response already written (generic 401/429)
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Not a browser surface: origin enforcement does not apply. Auth is
		// performed explicitly via the handshake headers above.
		InsecureSkipVerify: true,
	})
	if err != nil {
		s.log.WarnContext(r.Context(), "websocket accept failed", "err", err)
		return
	}
	conn.SetReadLimit(proto.MaxFrameBytes)

	sess := s.registerSession(conn)
	defer s.unregisterSession(sess)

	s.log.InfoContext(r.Context(), "control session established",
		"sessionId", sess.id, "remote", ip)

	sess.serve(r.Context(), s)
}

// Shutdown cancels the active session and force-closes its hijacked
// connection.
func (s *Server) Shutdown() {
	s.sessionMu.Lock()
	s.closed = true
	sess := s.current
	s.sessionMu.Unlock()
	if sess != nil {
		sess.cancel()
		_ = sess.conn.CloseNow()
	}
}

func (s *Server) isClosed() bool {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	return s.closed
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, ip string) bool {
	if s.failureLimited(ip) {
		s.log.WarnContext(r.Context(), "handshake rate limited", "remote", ip)
		http.Error(w, "too many failed handshakes", http.StatusTooManyRequests)
		return false
	}

	nodeID := r.Header.Get("X-Mcpanel-Node-Id")
	auth := r.Header.Get("Authorization")

	nodeIDOK := constantTimeEquals(nodeID, s.cred.NodeID)
	secretOK := false
	if strings.HasPrefix(auth, "Bearer ") {
		secretOK = constantTimeEquals(strings.TrimPrefix(auth, "Bearer "), s.cred.NodeSecret)
	}

	if !nodeIDOK || !secretOK {
		s.recordFailure(ip)
		s.throttledRejectionLog(ip)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Server) failureLimited(ip string) bool {
	s.failMu.Lock()
	defer s.failMu.Unlock()
	rec, ok := s.failIP[ip]
	if !ok {
		return false
	}
	if time.Since(rec.window) > failWindow {
		delete(s.failIP, ip)
		return false
	}
	return rec.count >= failLimit
}

func (s *Server) recordFailure(ip string) {
	s.failMu.Lock()
	defer s.failMu.Unlock()

	s.rejectCount++
	now := time.Now()
	if len(s.failIP) >= maxTrackedIPs {
		for k, rec := range s.failIP {
			if now.Sub(rec.window) > failWindow {
				delete(s.failIP, k)
			}
		}
		if len(s.failIP) >= maxTrackedIPs {
			s.failIP = map[string]*failRecord{}
		}
	}

	rec, ok := s.failIP[ip]
	if !ok || now.Sub(rec.window) > failWindow {
		s.failIP[ip] = &failRecord{count: 1, window: now}
		return
	}
	rec.count++
}

func (s *Server) throttledRejectionLog(ip string) {
	s.failMu.Lock()
	defer s.failMu.Unlock()
	now := time.Now()
	if now.Sub(s.lastRejLog) < time.Second {
		return
	}
	s.lastRejLog = now
	s.log.Warn("handshake rejected (throttled audit, 1/s)",
		"remote", ip, "totalRejections", s.rejectCount)
}

func (s *Server) registerSession(conn *websocket.Conn) *session {
	sess := newSession(conn)

	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if s.current != nil {
		s.log.Info("replacing existing control session", "old", s.current.id, "new", sess.id)
		s.current.replace() // closes old conn with 4000
	}
	s.current = sess
	return sess
}

func (s *Server) unregisterSession(sess *session) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if s.current == sess {
		s.current = nil
	}
	sess.shutdown()
}

// capsList returns the exact implemented method/event names.
func (s *Server) capsList() []string {
	caps := []string{proto.MethodNodeHello, proto.TopicNodeStats}
	if s.instances != nil && s.engine != nil {
		caps = append(caps,
			"instance.create", "instance.update", "instance.delete", "instance.purge",
			"instance.start", "instance.stop", "instance.restart", "instance.kill",
			"instance.list", "instance.inspect", "instance.command", "instance.output.read",
			"port.check", "evt:instance.state")
	}
	if s.files != nil {
		caps = append(caps, "file.list", "file.read", "file.write", "file.mkdir",
			"file.rename", "file.delete", "file.upload.begin", "file.upload.chunk",
			"file.upload.commit", "file.upload.abort", "file.download.chunk",
			"file.zip", "file.unzip")
	}
	if s.backupDir != "" {
		caps = append(caps, "backup.create", "backup.list", "backup.restore", "backup.delete",
			"backup.prune", "backup.download.chunk", "backup.upload.begin", "backup.upload.chunk",
			"backup.upload.commit", "backup.upload.abort")
	}
	if s.engine != nil && s.tasks != nil {
		caps = append(caps, "image.pull", "image.list", "image.remove", "node.containers.list", "install.run", "task.get")
	}
	if s.p2p != nil && s.instances != nil && s.engine != nil {
		// P2P 会话转发到实例容器端口：没有实例能力时无从谈起（与 instance.* 同门禁）
		caps = append(caps, "p2p.session.open", "p2p.signal", "p2p.session.close", "evt:p2p.session.state")
	}
	if s.engine != nil {
		caps = append(caps,
			"instance.output.subscribe", "instance.output.unsubscribe", "evt:instance.output")
	}
	if s.ftp != nil {
		caps = append(caps, "ftp.open", "ftp.close", "ftp.close.live", "ftp.open.node", "ftp.close.node")
	}
	if s.termEnabled && s.shellterm != nil {
		caps = append(caps, "node.terminal.open", "node.terminal.input", "node.terminal.close",
			"node.term.complete", "evt:node.terminal.output")
	}
	if len(s.fileRoots) > 0 {
		caps = append(caps, "node.file.list", "node.file.read", "node.file.write", "node.file.mkdir",
			"node.file.rename", "node.file.delete", "node.file.zip", "node.file.download.chunk")
	}
	if s.instances != nil {
		// 回收站能力与 Docker 无关（目录操作），只要实例服务在即可；面板以
		// trash.list 是否在 caps 中判断节点是否支持回收站/找回。
		caps = append(caps, "trash.list", "trash.delete")
	}
	return caps
}

func (s *Server) agentVersion() string { return version.Version }

// nodeInfoPayload is the node.hello res payload (protocol §5.1).
type nodeInfoPayload struct {
	NodeID        string   `json:"nodeId"`
	SessionID     string   `json:"sessionId"`
	Hostname      string   `json:"hostname"`
	AgentVersion  string   `json:"agentVersion"`
	Caps          []string `json:"caps"`
	DockerVersion string   `json:"dockerVersion,omitempty"`
	// MaxFrame 告知面板本节点的单帧入站上限（字节）：面板据此放宽 install.run
	// 等大载荷出站检查；旧面板忽略该字段、仍自限 256KiB。
	MaxFrame int64 `json:"maxFrame"`
}

func splitHostPort(addr string) (string, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, "", err
	}
	return host, port, nil
}

func fnv32(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

func constantTimeEquals(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---------- 业务方法分派（§9） ----------

type reqBody struct {
	IK string `json:"ik"`
	P  map[string]any
}

func str(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	v, _ := m[k].(string)
	return v
}

func integer(m map[string]any, k string, def int64) int64 {
	if m == nil {
		return def
	}
	switch v := m[k].(type) {
	case float64:
		return int64(v)
	case int:
		return int64(v)
	case int64:
		return v
	case string:
		var n int64
		fmt.Sscanf(v, "%d", &n)
		return n
	}
	return def
}

func requireEngine(s *Server) error {
	if s.engine == nil || s.instances == nil {
		return errors.New("Docker 不可用")
	}
	return nil
}

// Dispatch executes one req and returns the res payload.
func (s *Server) Dispatch(ctx context.Context, method string, p map[string]any, ik string) (any, error) {
	switch method {
	case "p2p.session.open":
		if s.p2p == nil {
			return nil, errors.New("p2p.unavailable：节点未启用 P2P 会话")
		}
		raw, _ := json.Marshal(p)
		var cmd p2p.OpenCommand
		if err := json.Unmarshal(raw, &cmd); err != nil {
			return nil, errors.New("proto.badPayload：P2P 会话参数解析失败")
		}
		return s.p2p.Open(cmd)
	case "p2p.signal":
		if s.p2p == nil {
			return nil, errors.New("p2p.unavailable：节点未启用 P2P 会话")
		}
		sessionID, _ := p["sessionId"].(string)
		var candidates []p2p.Candidate
		if raw, ok := p["candidates"]; ok && raw != nil {
			encoded, _ := json.Marshal(raw)
			_ = json.Unmarshal(encoded, &candidates)
		}
		return s.p2p.Signal(sessionID, candidates)
	case "p2p.session.close":
		if s.p2p == nil {
			return nil, errors.New("p2p.unavailable：节点未启用 P2P 会话")
		}
		sessionID, _ := p["sessionId"].(string)
		reason, _ := p["reason"].(string)
		return map[string]any{"closed": s.p2p.Close(sessionID, reason)}, nil
	case "instance.create", "instance.update":
		if err := requireEngine(s); err != nil {
			return nil, err
		}
		raw, _ := json.Marshal(p)
		var spec instances.Spec
		if err := json.Unmarshal(raw, &spec); err != nil {
			return nil, errors.New("proto.badPayload：实例规格解析失败")
		}
		return s.instances.Mutate(ctx, method, ik, spec.InstanceID, raw, func() (any, error) {
			if method == "instance.create" {
				// fromTrash：找回实例——先把回收目录改名回 instances/<id> 再创建容器，
				// 与容器创建在同一 Mutate 内保证原子；目录已存在会被拒绝而不是覆盖。
				if from := str(p, "fromTrash"); from != "" {
					if err := s.instances.RestoreFromTrash(from, spec.InstanceID); err != nil {
						return nil, err
					}
				}
				return s.instances.Create(ctx, spec)
			}
			return s.instances.Update(ctx, spec)
		})
	case "instance.delete", "instance.purge":
		if err := requireEngine(s); err != nil {
			return nil, err
		}
		id := str(p, "instanceId")
		raw, _ := json.Marshal(p)
		return s.instances.Mutate(ctx, method, ik, id, raw, func() (any, error) {
			// 数据目录迁移/删除前必须先释放文件句柄：SFTP 会话与进行中的分块
			// 上传在 Windows 上会以 sharing violation 卡死 rename/RemoveAll。
			s.releaseInstanceHandles(id)
			if method == "instance.purge" {
				// 记录可能已在半失败的删除中移除（重试场景）：目录清理仍要继续。
				if _, err := s.instances.Action(ctx, id, "delete", 30); err != nil && !os.IsNotExist(err) {
					return nil, err
				}
				return map[string]bool{"purged": true}, s.instances.Purge(id)
			}
			return s.instances.Action(ctx, id, "delete", 30)
		})
	case "trash.list":
		if s.instances == nil {
			return nil, errors.New("实例服务不可用")
		}
		return s.instances.TrashList()
	case "trash.delete":
		if s.instances == nil {
			return nil, errors.New("实例服务不可用")
		}
		trashID := str(p, "trashId")
		return map[string]bool{"deleted": true}, s.instances.TrashDelete(trashID)
	case "instance.start", "instance.stop", "instance.restart", "instance.kill":
		if err := requireEngine(s); err != nil {
			return nil, err
		}
		id := str(p, "instanceId")
		raw, _ := json.Marshal(p)
		timeout := int(integer(p, "timeoutSec", 30))
		return s.instances.Mutate(ctx, method, ik, id, raw, func() (any, error) {
			return s.instances.Action(ctx, id, strings.TrimPrefix(method, "instance."), timeout)
		})
	case "instance.command":
		if err := requireEngine(s); err != nil {
			return nil, err
		}
		id := str(p, "instanceId")
		raw, _ := json.Marshal(p)
		return s.instances.Mutate(ctx, method, ik, id, raw, func() (any, error) {
			return s.instances.Command(ctx, id, str(p, "command"))
		})
	case "node.containers.list":
		if s.engine == nil {
			return nil, errors.New("Docker 不可用")
		}
		list, err := s.engine.ListAllContainers(ctx)
		if err != nil {
			return nil, err
		}
		if list == nil {
			list = []map[string]any{}
		}
		return map[string]any{"containers": list}, nil
	case "instance.list":
		if err := requireEngine(s); err != nil {
			return nil, err
		}
		return s.instances.List(ctx, int(integer(p, "page", 1)), int(integer(p, "size", 10)))
	case "instance.inspect":
		if err := requireEngine(s); err != nil {
			return nil, err
		}
		return s.instances.Inspect(ctx, str(p, "instanceId"))
	case "instance.output.read":
		if err := requireEngine(s); err != nil {
			return nil, err
		}
		return s.instances.Output(ctx, str(p, "instanceId"), instances.SinceCursor(str(p, "since")), int(integer(p, "tail", 200)))
	case "port.check":
		if err := requireEngine(s); err != nil {
			return nil, err
		}
		checks := []struct {
			Port  int
			Proto string
		}{}
		if raw, ok := p["checks"].([]any); ok {
			for _, item := range raw {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				proto := str(m, "proto")
				if proto == "" {
					proto = "tcp"
				}
				checks = append(checks, struct {
					Port  int
					Proto string
				}{Port: int(integer(m, "port", 0)), Proto: proto})
			}
		}
		return map[string]any{"results": fileutil.CheckPorts(checks)}, nil
	case "file.list":
		root, err := s.instanceRoot(str(p, "instanceId"))
		if err != nil {
			return nil, err
		}
		size := integer(p, "size", 0)
		page := integer(p, "page", 1)
		if page < 1 {
			page = 1
		}
		entries, total, err := fileutil.ListPage(root, str(p, "path"), str(p, "keyword"), page, size)
		if err != nil {
			return nil, err
		}
		return map[string]any{"entries": entries, "total": total, "page": page, "size": size}, nil
	case "file.zip":
		id := str(p, "instanceId")
		raw, _ := json.Marshal(p)
		return s.instances.Mutate(ctx, method, ik, id, raw, func() (any, error) {
			root, err := s.instanceRoot(id)
			if err != nil {
				return nil, err
			}
			var rels []string
			if rawList, ok := p["paths"].([]any); ok {
				for _, item := range rawList {
					if one, ok := item.(string); ok && one != "" {
						rels = append(rels, one)
					}
				}
			}
			if len(rels) == 0 {
				if one := str(p, "path"); one != "" {
					rels = []string{one}
				}
			}
			name, err := fileutil.ZipPaths(root, rels, str(p, "dest"))
			if err != nil {
				return nil, err
			}
			return map[string]any{"zip": name}, nil
		})
	case "file.unzip":
		id := str(p, "instanceId")
		raw, _ := json.Marshal(p)
		return s.instances.Mutate(ctx, method, ik, id, raw, func() (any, error) {
			root, err := s.instanceRoot(id)
			if err != nil {
				return nil, err
			}
			return fileutil.UnzipPath(root, str(p, "path"), str(p, "dest"))
		})
	case "file.read":
		root, err := s.instanceRoot(str(p, "instanceId"))
		if err != nil {
			return nil, err
		}
		return fileutil.Read(root, str(p, "path"))
	case "file.write":
		id := str(p, "instanceId")
		raw, _ := json.Marshal(p)
		return s.instances.Mutate(ctx, method, ik, id, raw, func() (any, error) {
			root, err := s.instanceRoot(id)
			if err != nil {
				return nil, err
			}
			encoding := str(p, "encoding")
			if encoding == "" {
				encoding = "base64"
			}
			return map[string]bool{"written": true}, fileutil.Write(root, str(p, "path"), str(p, "content"), encoding)
		})
	case "file.mkdir":
		id := str(p, "instanceId")
		raw, _ := json.Marshal(p)
		return s.instances.Mutate(ctx, method, ik, id, raw, func() (any, error) {
			root, err := s.instanceRoot(id)
			if err != nil {
				return nil, err
			}
			return map[string]bool{"created": true}, fileutil.Mkdir(root, str(p, "path"))
		})
	case "file.rename":
		id := str(p, "instanceId")
		raw, _ := json.Marshal(p)
		return s.instances.Mutate(ctx, method, ik, id, raw, func() (any, error) {
			root, err := s.instanceRoot(id)
			if err != nil {
				return nil, err
			}
			return map[string]bool{"renamed": true}, fileutil.Rename(root, str(p, "from"), str(p, "to"))
		})
	case "file.delete":
		id := str(p, "instanceId")
		raw, _ := json.Marshal(p)
		return s.instances.Mutate(ctx, method, ik, id, raw, func() (any, error) {
			root, err := s.instanceRoot(id)
			if err != nil {
				return nil, err
			}
			return map[string]bool{"deleted": true}, fileutil.Delete(root, str(p, "path"))
		})
	case "file.upload.begin":
		uploadID, err := s.files.Begin(str(p, "instanceId"), str(p, "path"), integer(p, "size", -1), str(p, "sha256"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"uploadId": uploadID}, nil
	case "file.upload.chunk":
		if err := s.files.Chunk(str(p, "uploadId"), integer(p, "offset", -1), str(p, "content")); err != nil {
			return nil, err
		}
		return map[string]bool{"accepted": true}, nil
	case "file.upload.commit":
		return s.files.Commit(str(p, "uploadId"))
	case "file.upload.abort":
		if err := s.files.Abort(str(p, "uploadId")); err != nil {
			return nil, err
		}
		return map[string]bool{"aborted": true}, nil
	case "file.download.chunk":
		root, err := s.instanceRoot(str(p, "instanceId"))
		if err != nil {
			return nil, err
		}
		return fileutil.DownloadChunk(root, str(p, "path"), integer(p, "offset", 0), integer(p, "length", fileutil.MaxDataBytes))
	case "backup.create":
		if s.backupDir == "" {
			return nil, errors.New("备份目录未配置")
		}
		id := str(p, "instanceId")
		keepCount := int(integer(p, "keepCount", 0))
		keepDays := int(integer(p, "keepDays", 0))
		raw, _ := json.Marshal(p)
		return s.instances.Mutate(ctx, method, ik, id, raw, func() (any, error) {
			root, err := s.instanceRoot(id)
			if err != nil {
				return nil, err
			}
			target, err := fileutil.CreateBackup(root, s.backupDir, id)
			if err != nil {
				return nil, err
			}
			// 面板下发的保留策略（0=不限）：打包成功即清理超额/过期旧档。
			if keepCount > 0 || keepDays > 0 {
				_, _ = fileutil.PruneBackups(s.backupDir, id, keepCount, keepDays)
			}
			info, err := os.Stat(target)
			if err != nil {
				return nil, err
			}
			return map[string]any{"file": filepath.Base(target), "size": info.Size(), "at": info.ModTime().UnixMilli()}, nil
		})
	case "backup.list":
		if s.backupDir == "" {
			return nil, errors.New("备份目录未配置")
		}
		var items []map[string]any
		var err error
		if id := str(p, "instanceId"); id != "" {
			items, err = fileutil.ListInstanceBackups(s.backupDir, id)
		} else {
			items, err = fileutil.ListBackups(s.backupDir)
		}
		if err != nil {
			return nil, err
		}
		return map[string]any{"backups": items}, nil
	case "backup.prune":
		// 按保留策略立即清理单实例旧档（保存策略时面板调用）；纯备份目录文件操作，不入实例互斥。
		if s.backupDir == "" {
			return nil, errors.New("备份目录未配置")
		}
		id := str(p, "instanceId")
		if id == "" {
			return nil, errors.New("缺少实例 ID")
		}
		removed, err := fileutil.PruneBackups(s.backupDir, id, int(integer(p, "keepCount", 0)), int(integer(p, "keepDays", 0)))
		if err != nil {
			return nil, err
		}
		return map[string]any{"removed": removed}, nil
	case "backup.restore":
		if s.backupDir == "" {
			return nil, errors.New("备份目录未配置")
		}
		id := str(p, "instanceId")
		raw, _ := json.Marshal(p)
		return s.instances.Mutate(ctx, method, ik, id, raw, func() (any, error) {
			rec, err := s.instances.Inspect(ctx, id)
			if err != nil {
				return nil, err
			}
			if rec.State == "running" {
				return nil, errors.New("恢复备份前必须停止实例")
			}
			root, err := s.instanceRoot(id)
			if err != nil {
				return nil, err
			}
			return map[string]bool{"restored": true}, fileutil.RestoreBackup(s.backupDir, str(p, "file"), root)
		})
	case "backup.delete":
		if s.backupDir == "" {
			return nil, errors.New("备份目录未配置")
		}
		raw, _ := json.Marshal(p)
		return s.instances.Mutate(ctx, method, ik, str(p, "instanceId"), raw, func() (any, error) {
			return map[string]bool{"deleted": true}, fileutil.DeleteBackup(s.backupDir, str(p, "file"))
		})
	case "backup.download.chunk":
		// 面板整包拉取备份归档：与 file.download.chunk 同形，但根为全局备份目录。
		// 纯读，不走 Mutate/审计（与文件分块读取同一口径）。
		if s.backupDir == "" {
			return nil, errors.New("备份目录未配置")
		}
		return fileutil.DownloadChunk(s.backupDir, str(p, "file"), integer(p, "offset", 0), integer(p, "length", fileutil.MaxDataBytes))
	case "backup.upload.begin":
		if s.backupFiles == nil {
			return nil, errors.New("备份目录未配置")
		}
		uploadID, err := s.backupFiles.Begin("backup", str(p, "file"), integer(p, "size", -1), str(p, "sha256"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"uploadId": uploadID}, nil
	case "backup.upload.chunk":
		if s.backupFiles == nil {
			return nil, errors.New("备份目录未配置")
		}
		if err := s.backupFiles.Chunk(str(p, "uploadId"), integer(p, "offset", -1), str(p, "content")); err != nil {
			return nil, err
		}
		return map[string]bool{"accepted": true}, nil
	case "backup.upload.commit":
		if s.backupFiles == nil {
			return nil, errors.New("备份目录未配置")
		}
		return s.backupFiles.Commit(str(p, "uploadId"))
	case "backup.upload.abort":
		if s.backupFiles == nil {
			return nil, errors.New("备份目录未配置")
		}
		if err := s.backupFiles.Abort(str(p, "uploadId")); err != nil {
			return nil, err
		}
		return map[string]bool{"aborted": true}, nil
	case "instance.output.subscribe":
		if err := requireEngine(s); err != nil {
			return nil, err
		}
		if err := s.startOutputSub(ctx, str(p, "instanceId")); err != nil {
			return nil, err
		}
		return map[string]bool{"subscribed": true}, nil
	case "instance.output.unsubscribe":
		s.stopOutputSub(str(p, "instanceId"))
		return map[string]bool{"unsubscribed": true}, nil
	case "ftp.open":
		if s.ftp == nil {
			return nil, errors.New("SFTP 服务不可用")
		}
		id := str(p, "instanceId")
		root, err := s.instanceRoot(id)
		if err != nil {
			return nil, err
		}
		ttl := int(integer(p, "ttlMinutes", 120))
		port := s.ftpBasePort + int(fnv32(id)%uint32(max(1, 16)))
		opened, err := s.ftp.Open(id, root, port, ttl)
		if err != nil {
			return nil, err
		}
		s.pushSimpleEvent("ftp.opened", map[string]any{"instanceId": id, "port": opened.Port, "expiresAt": opened.ExpiresAt})
		return map[string]any{"instanceId": id, "port": opened.Port, "user": opened.User,
			"password": opened.Password, "expiresAt": opened.ExpiresAt}, nil
	case "ftp.close", "ftp.close.live":
		if s.ftp == nil {
			return nil, errors.New("SFTP 服务不可用")
		}
		id := str(p, "instanceId")
		closed := s.ftp.Close(id)
		if closed {
			s.pushSimpleEvent("ftp.closed", map[string]any{"instanceId": id})
		}
		return map[string]bool{"closed": closed}, nil
	case "node.terminal.open":
		if !s.termEnabled || s.shellterm == nil {
			return nil, errors.New("节点终端未启用（config: security.terminalEnabled=true）")
		}
		id := normalizeTerminalId(str(p, "terminalId"))
		if id == "" {
			return nil, errBadPayload("缺少 terminalId")
		}
		shell := str(p, "shell")
		_, err := s.shellterm.Open(ctx, id, shell)
		if err != nil {
			return nil, err
		}
		go func() {
			ch, ok := s.shellterm.OutputChan(id)
			if !ok {
				return
			}
			for {
				select {
				case <-ctx.Done():
					return
				case text, ok := <-ch:
					// data 承载原始字节 base64：JSON 会损坏非法 UTF-8，终端按编码重解码
					data := base64.StdEncoding.EncodeToString([]byte(text))
					if !ok {
						s.pushSimpleEvent("node.terminal.output", map[string]any{"terminalId": id, "text": text, "data": data, "closed": true})
						return
					}
					s.pushSimpleEvent("node.terminal.output", map[string]any{"terminalId": id, "text": text, "data": data})
				}
			}
		}()
		return map[string]any{"terminalId": id}, nil
	case "node.terminal.input":
		if s.shellterm == nil {
			return nil, errors.New("节点终端未启用")
		}
		id := normalizeTerminalId(str(p, "terminalId"))
		if err := s.shellterm.Input(id, str(p, "data")); err != nil {
			return nil, err
		}
		return map[string]bool{"sent": true}, nil
	case "node.terminal.close":
		if s.shellterm == nil {
			return nil, errors.New("节点终端未启用")
		}
		return map[string]bool{"closed": s.shellterm.Close(normalizeTerminalId(str(p, "terminalId")))}, nil
	case "node.term.complete":
		if !s.termEnabled {
			return nil, errors.New("节点终端未启用")
		}
		limit := int(integer(p, "limit", completionDefaultLimit))
		if limit <= 0 || limit > completionMaxLimit {
			limit = completionDefaultLimit
		}
		return map[string]any{"completions": s.completer.complete(str(p, "prefix"), limit)}, nil
	case "node.file.list":
		rootName, rootPath, err := s.nodeRoot(str(p, "root"))
		if err != nil {
			return nil, err
		}
		size := integer(p, "size", 0)
		page := integer(p, "page", 1)
		if page < 1 {
			page = 1
		}
		entries, total, err := fileutil.ListPage(filepath.Join(rootPath), str(p, "path"), str(p, "keyword"), page, size)
		if err != nil {
			return nil, err
		}
		return map[string]any{"entries": entries, "total": total, "page": page, "size": size, "root": rootName}, nil
	case "node.file.read":
		_, rootPath, err := s.nodeRoot(str(p, "root"))
		if err != nil {
			return nil, err
		}
		full, err := fileutil.Resolve(rootPath, str(p, "path"), true)
		if err != nil {
			return nil, err
		}
		fi, ferr := os.Lstat(full)
		if ferr != nil {
			return nil, ferr
		}
		if fi.Size() > 96*1024 {
			return nil, errors.New("文件超过 96KiB，请使用 SFTP")
		}
		b, rerr := os.ReadFile(full)
		if rerr != nil {
			return nil, rerr
		}
		return map[string]any{"content": base64.StdEncoding.EncodeToString(b), "encoding": "base64", "size": len(b)}, nil
	case "node.file.write":
		_, rootPath, err := s.nodeRoot(str(p, "root"))
		if err != nil {
			return nil, err
		}
		full, werr := fileutil.Resolve(rootPath, str(p, "path"), false)
		if werr != nil {
			return nil, werr
		}
		raw, dcerr := base64.StdEncoding.DecodeString(str(p, "content"))
		if dcerr != nil {
			return nil, errors.New("base64 内容无效")
		}
		if len(raw) > 96*1024 {
			return nil, errors.New("单次写入超过 96KiB，请使用 SFTP")
		}
		return map[string]bool{"written": true}, os.WriteFile(full, raw, 0644)
	case "node.file.mkdir":
		_, rootPath, err := s.nodeRoot(str(p, "root"))
		if err != nil {
			return nil, err
		}
		full, merr := fileutil.Resolve(rootPath, str(p, "path"), false)
		if merr != nil {
			return nil, merr
		}
		return map[string]bool{"created": true}, os.MkdirAll(full, 0755)
	case "node.file.rename":
		_, rootPath, err := s.nodeRoot(str(p, "root"))
		if err != nil {
			return nil, err
		}
		src, serr := fileutil.Resolve(rootPath, str(p, "from"), true)
		if serr != nil {
			return nil, serr
		}
		dst, derr := fileutil.Resolve(rootPath, str(p, "to"), false)
		if derr != nil {
			return nil, derr
		}
		return map[string]bool{"renamed": true}, os.Rename(src, dst)
	case "node.file.delete":
		_, rootPath, err := s.nodeRoot(str(p, "root"))
		if err != nil {
			return nil, err
		}
		full, derr := fileutil.Resolve(rootPath, str(p, "path"), true)
		if derr != nil {
			return nil, derr
		}
		if full == rootPath {
			return nil, errors.New("不允许删除文件根目录")
		}
		return map[string]bool{"deleted": true}, os.RemoveAll(full)
	case "node.file.zip":
		_, rootPath, err := s.nodeRoot(str(p, "root"))
		if err != nil {
			return nil, err
		}
		var rels []string
		if rawList, ok := p["paths"].([]any); ok {
			for _, item := range rawList {
				if one, ok := item.(string); ok && one != "" {
					rels = append(rels, one)
				}
			}
		}
		if len(rels) == 0 {
			if one := str(p, "path"); one != "" {
				rels = []string{one}
			}
		}
		name, err := fileutil.ZipPaths(rootPath, rels, str(p, "dest"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"zip": name}, nil
	case "node.file.download.chunk":
		_, rootPath, err := s.nodeRoot(str(p, "root"))
		if err != nil {
			return nil, err
		}
		return fileutil.DownloadChunk(rootPath, str(p, "path"), integer(p, "offset", 0), integer(p, "length", 96*1024))
	case "ftp.open.node":
		if s.ftp == nil {
			return nil, errors.New("SFTP 服务不可用")
		}
		rootName, rootPath, err := s.nodeRoot(str(p, "root"))
		if err != nil {
			return nil, err
		}
		ttl := int(integer(p, "ttlMinutes", 120))
		port := s.ftpBasePort + int(fnv32("node:"+rootName)%16)
		opened, err := s.ftp.Open("node:"+rootName, rootPath, port, ttl)
		if err != nil {
			return nil, err
		}
		return map[string]any{"root": rootName, "port": opened.Port, "user": opened.User,
			"password": opened.Password, "expiresAt": opened.ExpiresAt}, nil
	case "ftp.close.node":
		if s.ftp == nil {
			return nil, errors.New("SFTP 服务不可用")
		}
		rootName := str(p, "root")
		return map[string]bool{"closed": s.ftp.Close("node:" + rootName)}, nil
	case "image.pull":
		if s.engine == nil || s.tasks == nil {
			return nil, errors.New("Docker 不可用")
		}
		image := str(p, "image")
		if image == "" {
			return nil, errors.New("proto.badPayload：缺少 image")
		}
		taskID := s.tasks.PullImage(s.lifecycle, s.engine.Pull, image)
		return map[string]any{"taskId": taskID, "state": "running", "image": image}, nil
	case "image.list":
		if s.engine == nil {
			return nil, errors.New("Docker 不可用")
		}
		list, err := s.engine.ListImages(ctx)
		if err != nil {
			return nil, err
		}
		if list == nil {
			list = []dockerx.ImageInfo{}
		}
		return map[string]any{"images": list}, nil
	case "image.remove":
		if s.engine == nil {
			return nil, errors.New("Docker 不可用")
		}
		image := str(p, "image")
		if image == "" {
			return nil, errors.New("proto.badPayload：缺少 image")
		}
		force, _ := p["force"].(bool)
		if err := s.engine.RemoveImage(ctx, image, force); err != nil {
			return nil, err
		}
		return map[string]any{"deleted": true, "image": image}, nil
	case "install.run":
		if s.tasks == nil {
			return nil, errors.New("任务器不可用")
		}
		root, err := s.instanceRoot(str(p, "instanceId"))
		if err != nil {
			return nil, err
		}
		plan := []tasks.PlanItem{}
		if raw, ok := p["files"].([]any); ok {
			b, _ := json.Marshal(raw)
			if err := json.Unmarshal(b, &plan); err != nil {
				return nil, errors.New("proto.badPayload：安装计划解析失败")
			}
		}
		taskID := s.tasks.RunInstall(s.lifecycle, root, plan)
		return map[string]any{"taskId": taskID, "state": "running"}, nil
	case "task.get":
		if s.tasks == nil {
			return nil, errors.New("任务器不可用")
		}
		st, ok := s.tasks.Get(str(p, "taskId"))
		if !ok {
			return nil, os.ErrNotExist
		}
		return st, nil
	default:
		return nil, errUnknownMethod(method)
	}
}

func errBadPayload(msg string) error {
	return &protocolError{code: "proto.badPayload", message: msg}
}

func errInternal(msg string) error {
	return &protocolError{code: "internal.error", message: msg}
}

func errUnknownMethod(method string) error {
	return &protocolError{code: "proto.unknownMethod", message: method + " not implemented by this agent"}
}

// normalizeTerminalId：面板与节点共用同一 terminalId；兼容历史客户端已带 term- 前缀。
func normalizeTerminalId(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "term-") {
		return raw
	}
	return "term-" + raw
}

type protocolError struct {
	code      string
	message   string
	retryable bool
}

func (e *protocolError) Error() string { return e.message }

// AsProtocolError 把业务错误映射为协议 err 载荷。
func AsProtocolError(err error) (code, message string, retryable bool) {
	var pe *protocolError
	if errors.As(err, &pe) {
		return pe.code, pe.message, pe.retryable
	}
	msg := err.Error()
	if strings.Contains(msg, "operation.conflict") {
		return "operation.conflict", msg, false
	}
	if strings.Contains(msg, "operation.uncertain") {
		return "operation.uncertain", msg, true
	}
	if os.IsNotExist(err) || dockerx.IsNotFound(err) {
		return "instance.notFound", "目标不存在", false
	}
	if strings.Contains(msg, "proto.badPayload") {
		return "proto.badPayload", msg, false
	}
	return "internal.error", msg, false
}

// nodeRoot 按名称解析节点文件根（白名单）；空名称取第一个。
func (s *Server) nodeRoot(name string) (string, string, error) {
	for _, r := range s.fileRoots {
		if r.Path == "" {
			continue
		}
		if name == "" || name == r.Name {
			return r.Name, r.Path, nil
		}
	}
	if name == "" {
		return "", "", errors.New("节点未配置文件根")
	}
	return "", "", fmt.Errorf("文件根不存在：%s", name)
}

func (s *Server) instanceRoot(instanceID string) (string, error) {
	if s.instances == nil {
		return "", errors.New("实例服务不可用")
	}
	if instanceID == "" {
		return "", errors.New("proto.badPayload：缺少 instanceId")
	}
	return s.instances.Root(instanceID)
}

// releaseInstanceHandles 释放节点持有的、钉在实例数据目录上的句柄：
// 临时 SFTP 会话与进行中的分块上传临时文件。实例删除/回收迁移前必须调用，
// 否则 Windows 上 rename/RemoveAll 会因 sharing violation 失败。
func (s *Server) releaseInstanceHandles(instanceID string) {
	if s.ftp != nil {
		if s.ftp.Close(instanceID) {
			s.pushSimpleEvent("ftp.closed", map[string]any{"instanceId": instanceID})
		}
	}
	if s.files != nil {
		s.files.AbortInstance(instanceID)
	}
}
