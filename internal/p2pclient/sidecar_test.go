package p2pclient

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yudream/mcpanel-node/internal/p2p"
)

// fakePanel 面板玩家面 API 的等价物：开会话发票据 + 状态 + 关闭。
type fakePanel struct {
	mu       sync.Mutex
	sessions map[string]string // sessionId → ticket
	state    string
	closed   bool
	nodeHost string
	nodePort int

	openCalls, signalCalls, statusCalls, closeCalls int
	authorization                                   string
}

func newFakePanel(nodeHost string, nodePort int) *fakePanel {
	return &fakePanel{sessions: map[string]string{}, state: "waiting", nodeHost: nodeHost, nodePort: nodePort}
}

func (f *fakePanel) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/plugins/ymcl-adapter/v1/p2p/session", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.authorization = r.Header.Get("Authorization")
		switch r.Method {
		case http.MethodPost:
			f.openCalls++
			var body struct {
				InstanceID string `json:"instance_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			sessionID := "sess-test"
			f.sessions[sessionID] = "ticket-test"
			writeJSON(w, map[string]any{
				"session_id": sessionID, "instance_id": body.InstanceID, "node_id": "node-1",
				"state": f.state, "ticket": f.sessions[sessionID], "target_port": 25600, "rate_kbps": 2048,
				"expires_at": time.Now().Add(time.Minute).UnixMilli(),
				"candidates": []Candidate{
					{Proto: "tcp", Host: f.nodeHost, Port: f.nodePort, Priority: 10},
				},
			})
		case http.MethodGet:
			f.statusCalls++
			writeJSON(w, map[string]any{
				"session_id": "sess-test", "state": f.state, "terminal": f.state == "failed",
				"candidates": []Candidate{
					{Proto: "tcp", Host: f.nodeHost, Port: f.nodePort, Priority: 10},
				},
			})
		case http.MethodDelete:
			f.closeCalls++
			f.closed = true
			f.state = "closed"
			writeJSON(w, map[string]any{"closed": true})
		}
	})
	mux.HandleFunc("/api/plugins/ymcl-adapter/v1/p2p/session/signal", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.signalCalls++
		writeJSON(w, map[string]any{"sessionId": "sess-test"})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func (f *fakePanel) counts() (int, int, int, int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.openCalls, f.signalCalls, f.statusCalls, f.closeCalls, f.closed
}

func (f *fakePanel) setState(state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = state
}

// fakeInstance 模拟实例服务端口（回显）。
func fakeInstance(t *testing.T) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake instance: %v", err)
	}
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

// 端到端（本机回环）：sidecar → 假面板开会话 → 真 p2p.Manager 节点入口 → 假实例端口。
func TestSidecarRelaysPlayerTrafficThroughNodeSession(t *testing.T) {
	instancePort, stopInstance := fakeInstance(t)
	defer stopInstance()

	// 真节点侧管理器（与生产同一份代码）：票据由面板下发，目标端口钉死
	manager := p2p.New("127.0.0.1", nil)
	defer manager.CloseAll("test cleanup")

	session, err := manager.Open(p2p.OpenCommand{
		SessionID:  "sess-test",
		Ticket:     "ticket-test",
		InstanceID: "inst-1",
		TargetPort: instancePort,
		ExpiresAt:  time.Now().Add(time.Minute).UnixMilli(),
	})
	if err != nil {
		t.Fatalf("open node session: %v", err)
	}
	entryPort := session["listenPort"].(int)

	panel := newFakePanel("127.0.0.1", entryPort)
	server := httptest.NewServer(panel.handler())
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, Config{
			PanelBase:   server.URL,
			Token:       "player-token",
			InstanceID:  "inst-1",
			LocalAddr:   "127.0.0.1:0",
			StatusEvery: 200 * time.Millisecond,
			LocalCandidates: []Candidate{
				{Proto: "udp", Host: "198.51.100.7", Port: 52100},
			},
			OnReady: func(localAddr string, _ *Session) { ready <- localAddr },
		})
	}()

	var localAddr string
	select {
	case localAddr = <-ready:
	case err := <-runErr:
		t.Fatalf("sidecar 启动失败：%v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("sidecar 未在 5 秒内就绪")
	}

	// 只监听 loopback
	host, _, splitErr := net.SplitHostPort(localAddr)
	if splitErr != nil || host != "127.0.0.1" {
		t.Fatalf("本地入口必须只监听 loopback，实际 %s", localAddr)
	}

	// 玩家客户端（MC 等价物）连本地入口 → 流量应经节点到达实例
	conn, err := net.DialTimeout("tcp", localAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial local entry: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("player-packet\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echoed, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if echoed != "echo:player-packet\n" {
		t.Fatalf("echo = %q", echoed)
	}

	open, signal, _, _, _ := panel.counts()
	if open != 1 || signal != 1 {
		t.Fatalf("面板调用 open=%d signal=%d（都应各一次）", open, signal)
	}

	// 关掉 sidecar：必须回收会话（DELETE）
	cancel()
	select {
	case <-runErr:
	case <-time.After(5 * time.Second):
		t.Fatal("sidecar 未在取消后退出")
	}
	time.Sleep(100 * time.Millisecond)
	_, _, _, closeCalls, closed := panel.counts()
	if closeCalls == 0 || !closed {
		t.Fatalf("退出必须关闭会话 closeCalls=%d closed=%v", closeCalls, closed)
	}
}

// 面板报告会话 failed：sidecar 必须停止转发并自行退出。
func TestSidecarStopsWhenPanelReportsFailure(t *testing.T) {
	instancePort, stopInstance := fakeInstance(t)
	defer stopInstance()
	manager := p2p.New("127.0.0.1", nil)
	defer manager.CloseAll("test cleanup")
	opened, err := manager.Open(p2p.OpenCommand{SessionID: "sess-test", Ticket: "ticket-test",
		InstanceID: "inst-1", TargetPort: instancePort, ExpiresAt: time.Now().Add(time.Minute).UnixMilli()})
	if err != nil {
		t.Fatalf("open node session: %v", err)
	}
	panel := newFakePanel("127.0.0.1", opened["listenPort"].(int))
	server := httptest.NewServer(panel.handler())
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	ready := make(chan struct{})
	go func() {
		runErr <- Run(ctx, Config{PanelBase: server.URL, InstanceID: "inst-1", LocalAddr: "127.0.0.1:0",
			StatusEvery: 100 * time.Millisecond,
			OnReady:     func(string, *Session) { close(ready) }})
	}()
	<-ready

	panel.setState("failed")
	select {
	case <-runErr: // 面板判定失败 → sidecar 退出
	case <-time.After(5 * time.Second):
		t.Fatal("面板报告 failed 后 sidecar 必须停止")
	}
	_, _, statusCalls, _, _ := panel.counts()
	if statusCalls == 0 {
		t.Fatal("必须轮询过状态")
	}
}

// 能力缺口/业务错误要给出可读原因，而不是静默失败。
func TestOpenSessionReportsErrorsReadably(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/plugins/ymcl-adapter/v1/p2p/session", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":"p2p.instance-disabled","message":"该实例未开启 P2P 接入"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	_, err := NewClient(server.URL, "token").OpenSession(context.Background(), "inst-1")
	if err == nil || !strings.Contains(err.Error(), "该实例未开启 P2P 接入") {
		t.Fatalf("err = %v（必须透出面板原因）", err)
	}

	// 上游不可用（适配器 501）
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/api/plugins/ymcl-adapter/v1/p2p/session", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte(`{"error":"p2p.upstream-unavailable","message":"未安装或未启用 mcpanel 插件"}`))
	})
	server2 := httptest.NewServer(mux2)
	defer server2.Close()
	_, err = NewClient(server2.URL, "token").OpenSession(context.Background(), "inst-1")
	if err == nil || !strings.Contains(err.Error(), "未安装或未启用 mcpanel") {
		t.Fatalf("upstream unavailable err = %v", err)
	}
}

// 面板地址既接受站点根，也接受适配器宣告的 session_url；两者都归一化到
// `/p2p` 基址，否则 sidecar 会把请求打到 /session/session。
func TestPanelBaseNormalization(t *testing.T) {
	const want = "https://panel.example.com/api/plugins/ymcl-adapter/v1/p2p"
	cases := map[string]string{
		"https://panel.example.com":                                               want,
		"https://panel.example.com/":                                              want,
		"https://panel.example.com" + "/api/plugins/ymcl-adapter/v1/p2p":          want,
		"https://panel.example.com" + "/api/plugins/ymcl-adapter/v1/p2p/session":  want,
		"https://panel.example.com" + "/api/plugins/ymcl-adapter/v1/p2p/session/": want,
	}
	for input, expected := range cases {
		if got := NewClient(input, "token").base; got != expected {
			t.Fatalf("NewClient(%q).base = %q，期望 %q", input, got, expected)
		}
	}
}

// 宿主与启动器都用裸 token：Authorization 头必须原样透传（不带 Bearer 前缀），
// 需要 scheme 时才由调用方显式声明。
func TestAuthorizationHeaderFollowsLauncherConvention(t *testing.T) {
	instancePort, stopInstance := fakeInstance(t)
	defer stopInstance()
	manager := p2p.New("127.0.0.1", nil)
	defer manager.CloseAll("test cleanup")
	opened, err := manager.Open(p2p.OpenCommand{SessionID: "sess-test", Ticket: "ticket-test",
		InstanceID: "inst-1", TargetPort: instancePort, ExpiresAt: time.Now().Add(time.Minute).UnixMilli()})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	panel := newFakePanel("127.0.0.1", opened["listenPort"].(int))
	server := httptest.NewServer(panel.handler())
	defer server.Close()

	client := NewClient(server.URL, "domain-access-token")
	if _, err := client.OpenSession(context.Background(), "inst-1"); err != nil {
		t.Fatalf("open session: %v", err)
	}
	panel.mu.Lock()
	bare := panel.authorization
	panel.mu.Unlock()
	if bare != "domain-access-token" {
		t.Fatalf("Authorization = %q，应为裸 token", bare)
	}

	schemed := NewClient(server.URL, "domain-access-token").WithAuthScheme("Bearer")
	if _, err := schemed.OpenSession(context.Background(), "inst-1"); err != nil {
		t.Fatalf("open session: %v", err)
	}
	panel.mu.Lock()
	withScheme := panel.authorization
	panel.mu.Unlock()
	if withScheme != "Bearer domain-access-token" {
		t.Fatalf("Authorization = %q，显式 scheme 时应带前缀", withScheme)
	}
}

// 票据被拒（unauthorized）不得继续试其它候选；连接失败则按优先级换候选。
func TestDialBehaviourOnTicketRejectionAndFailover(t *testing.T) {
	// 票据不符的节点入口
	manager := p2p.New("127.0.0.1", nil)
	defer manager.CloseAll("test cleanup")
	opened, err := manager.Open(p2p.OpenCommand{SessionID: "sess-1", Ticket: "real-ticket",
		InstanceID: "i", TargetPort: 1, ExpiresAt: time.Now().Add(time.Minute).UnixMilli()})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	entryPort := opened["listenPort"].(int)

	if _, _, err := Dial(context.Background(), "sess-1", "wrong-ticket",
		[]Candidate{{Proto: "tcp", Host: "127.0.0.1", Port: entryPort}}); err == nil ||
		!strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("err = %v（票据被拒必须直接失败）", err)
	}

	// 不可达候选 → 换到可用候选
	instancePort, stopInstance := fakeInstance(t)
	defer stopInstance()
	good := p2p.New("127.0.0.1", nil)
	defer good.CloseAll("test cleanup")
	openedGood, err := good.Open(p2p.OpenCommand{SessionID: "sess-2", Ticket: "ticket-2",
		InstanceID: "i", TargetPort: instancePort, ExpiresAt: time.Now().Add(time.Minute).UnixMilli()})
	if err != nil {
		t.Fatalf("open good: %v", err)
	}
	conn, picked, err := Dial(context.Background(), "sess-2", "ticket-2", []Candidate{
		{Proto: "tcp", Host: "127.0.0.1", Port: 1, Priority: 20}, // 不可达：先试
		{Proto: "tcp", Host: "127.0.0.1", Port: openedGood["listenPort"].(int), Priority: 30},
	})
	if err != nil {
		t.Fatalf("dial with failover: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if picked.Priority != 30 {
		t.Fatalf("picked = %+v（应跳过不可达候选）", picked)
	}

	if _, _, err := Dial(context.Background(), "sess-2", "ticket-2", nil); err == nil {
		t.Fatal("无候选必须报错（提示需节点公网可达或端口映射）")
	}
}
