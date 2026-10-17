package p2p

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"
)

// fakeInstance 模拟实例容器端口（节点侧 P2P 只允许 dial 到这个被票据钉死的端口）。
func fakeInstance(t *testing.T) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake instance listen: %v", err)
	}
	done := make(chan struct{})
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
					// 回显：证明「启动器 → 实例」方向通了，并回一条实例侧数据
					_, _ = conn.Write([]byte("echo:" + line))
				}
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, func() {
		_ = listener.Close()
		close(done)
	}
}

func openSession(t *testing.T, manager *Manager, port int, ttl time.Duration) map[string]any {
	t.Helper()
	result, err := manager.Open(OpenCommand{
		SessionID:  "sess-1",
		Ticket:     "ticket-abc",
		InstanceID: "inst-1",
		TargetPort: port,
		RateKbps:   0,
		ExpiresAt:  time.Now().Add(ttl).UnixMilli(),
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return result
}

// handshakeAndEcho 走一次完整链路：握手 → OK → 收发字节。
func handshakeAndEcho(t *testing.T, entryPort int, sessionID, ticket string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(entryPort)), 3*time.Second)
	if err != nil {
		t.Fatalf("dial entry: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "%s %s %s\n", Magic, sessionID, ticket); err != nil {
		t.Fatalf("handshake write: %v", err)
	}
	reader := bufio.NewReader(conn)
	ack, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("handshake read: %v", err)
	}
	if ack != "OK\n" {
		t.Fatalf("handshake ack = %q, want OK", ack)
	}
	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	echoed, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	return echoed
}

func TestOpenAcceptsTicketAndPumpsBytesBothWays(t *testing.T) {
	instancePort, stopInstance := fakeInstance(t)
	defer stopInstance()

	var states []string
	manager := New("203.0.113.9", func(state string, session *Session, reason string) {
		states = append(states, state)
	})
	defer manager.CloseAll("test done")

	result := openSession(t, manager, instancePort, time.Minute)
	entryPort := int(result["listenPort"].(int))

	candidates := result["candidates"].([]Candidate)
	if len(candidates) != 1 || candidates[0].Port != entryPort || candidates[0].Host != "203.0.113.9" {
		t.Fatalf("candidates = %+v", candidates)
	}

	echoed := handshakeAndEcho(t, entryPort, "sess-1", "ticket-abc")
	if echoed != "echo:ping\n" {
		t.Fatalf("echo = %q", echoed)
	}

	snapshot := manager.Snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if snapshot[0]["bytesUp"].(int64) < 5 || snapshot[0]["bytesDown"].(int64) < 10 {
		t.Fatalf("bytes not accounted: %+v", snapshot[0])
	}
	if states[0] != "connecting" {
		t.Fatalf("first state = %s", states[0])
	}
}

func TestHandshakeRejectsWrongTicketAndUnknownSession(t *testing.T) {
	instancePort, stopInstance := fakeInstance(t)
	defer stopInstance()
	manager := New("", nil)
	defer manager.CloseAll("test done")
	result := openSession(t, manager, instancePort, time.Minute)
	entryPort := int(result["listenPort"].(int))

	for name, handshake := range map[string]string{
		"wrong-ticket":    fmt.Sprintf("%s sess-1 not-the-ticket\n", Magic),
		"unknown-session": fmt.Sprintf("%s sess-9 ticket-abc\n", Magic),
		"bad-magic":       fmt.Sprintf("NOPE sess-1 ticket-abc\n"),
		"malformed":       "garbage\n",
	} {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(entryPort)), 3*time.Second)
		if err != nil {
			t.Fatalf("%s: dial: %v", name, err)
		}
		_, _ = conn.Write([]byte(handshake))
		line, _ := bufio.NewReader(conn).ReadString('\n')
		_ = conn.Close()
		if line != "ERR unauthorized\n" && line != "ERR bad_handshake\n" {
			t.Fatalf("%s: response = %q（必须被拒绝）", name, line)
		}
	}
	// 拒绝的连接不得计入会话
	if conns := manager.Snapshot()[0]["conns"].(int); conns != 0 {
		t.Fatalf("rejected connections must not be tracked, got %d", conns)
	}
}

// 目的端钉死：即使启动器握手成功，节点也只 dial 票据里的实例端口（这里用 dial 钩子断言）。
func TestDialTargetIsPinnedToTicketPort(t *testing.T) {
	instancePort, stopInstance := fakeInstance(t)
	defer stopInstance()
	manager := New("", nil)
	defer manager.CloseAll("test done")

	var dialed []string
	manager.dial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		dialed = append(dialed, address)
		return net.DialTimeout(network, address, timeout)
	}
	result := openSession(t, manager, instancePort, time.Minute)
	entryPort := int(result["listenPort"].(int))
	_ = handshakeAndEcho(t, entryPort, "sess-1", "ticket-abc")

	want := net.JoinHostPort("127.0.0.1", strconv.Itoa(instancePort))
	if len(dialed) == 0 || dialed[0] != want {
		t.Fatalf("dialed = %v, want %s（目的端必须钉死在票据端口）", dialed, want)
	}
}

func TestCloseTearsDownListenerAndConnections(t *testing.T) {
	instancePort, stopInstance := fakeInstance(t)
	defer stopInstance()
	manager := New("", nil)

	result := openSession(t, manager, instancePort, time.Minute)
	entryPort := int(result["listenPort"].(int))
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(entryPort)), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = fmt.Fprintf(conn, "%s sess-1 ticket-abc\n", Magic)
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	if !manager.Close("sess-1", "启动器退出") {
		t.Fatal("close must report handled")
	}
	if manager.Close("sess-1", "重复关闭") {
		t.Fatal("second close must be a no-op")
	}
	// 入口端口不再监听
	if _, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(entryPort)), time.Second); err == nil {
		t.Fatal("listener must be closed")
	}
	// 已有连接被断开
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 16)); err == nil {
		t.Fatal("existing connection must be closed")
	}
}

func TestExpiredSessionIsRecycled(t *testing.T) {
	instancePort, stopInstance := fakeInstance(t)
	defer stopInstance()
	manager := New("", nil)
	defer manager.CloseAll("test done")

	result := openSession(t, manager, instancePort, 50*time.Millisecond)
	entryPort := int(result["listenPort"].(int))
	time.Sleep(250 * time.Millisecond)

	if len(manager.Snapshot()) != 0 {
		t.Fatal("expired session must be recycled")
	}
	if _, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(entryPort)), time.Second); err == nil {
		t.Fatal("expired session listener must be closed")
	}
}

func TestSignalRecordsPeerCandidates(t *testing.T) {
	instancePort, stopInstance := fakeInstance(t)
	defer stopInstance()
	manager := New("node.example.com", nil)
	defer manager.CloseAll("test done")
	openSession(t, manager, instancePort, time.Minute)

	response, err := manager.Signal("sess-1", []Candidate{{Proto: "udp", Host: "198.51.100.7", Port: 52100}})
	if err != nil {
		t.Fatalf("signal: %v", err)
	}
	if response["peerCount"].(int) != 1 {
		t.Fatalf("peerCount = %v", response["peerCount"])
	}
	if _, err := manager.Signal("missing", nil); err == nil {
		t.Fatal("unknown session must error")
	}
	// 候选回包仍带节点自己的入口（启动器据此直连）
	nodeCandidates := manager.Snapshot()
	if len(nodeCandidates) != 1 || nodeCandidates[0]["sessionId"] != "sess-1" {
		t.Fatalf("snapshot = %+v", nodeCandidates)
	}
}

func TestUpstreamUnreachableReportsFailed(t *testing.T) {
	manager := New("", nil)
	defer manager.CloseAll("test done")
	// 未监听的高端口：模拟实例端口不可达
	result, err := manager.Open(OpenCommand{SessionID: "s", Ticket: "t", TargetPort: 1, ExpiresAt: time.Now().Add(time.Minute).UnixMilli()})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	entryPort := int(result["listenPort"].(int))
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(entryPort)), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(conn, "%s s t\n", Magic)
	line, _ := bufio.NewReader(conn).ReadString('\n')
	if line != "ERR upstream_unreachable\n" {
		t.Fatalf("response = %q", line)
	}
}

func TestRateBucketDelaysLargeBursts(t *testing.T) {
	// 100 KB/s：一次 100KB 突发应被显著节流（确定性：直接看 take 的返回值）
	limiter := newBucket(100)
	if wait := limiter.take(1); wait != 0 {
		t.Fatalf("small read must pass: %v", wait)
	}
	wait := limiter.take(1024 * 1024)
	if wait <= 0 {
		t.Fatal("1MB read must be throttled by ~10s at 100KB/s")
	}
	if wait > 30*time.Second {
		t.Fatalf("throttle too aggressive: %v", wait)
	}
	if newBucket(0) != nil {
		t.Fatal("rateKbps=0 means unlimited (nil bucket)")
	}
}

func TestOpenRejectsBadPayloadAndDuplicate(t *testing.T) {
	instancePort, stopInstance := fakeInstance(t)
	defer stopInstance()
	manager := New("", nil)
	defer manager.CloseAll("test done")

	if _, err := manager.Open(OpenCommand{Ticket: "t", TargetPort: instancePort}); err == nil {
		t.Fatal("missing sessionId must be rejected")
	}
	if _, err := manager.Open(OpenCommand{SessionID: "s", Ticket: "t", TargetPort: 0}); err == nil {
		t.Fatal("bad port must be rejected")
	}
	if _, err := manager.Open(OpenCommand{SessionID: "s", Ticket: "t", TargetPort: instancePort,
		ExpiresAt: time.Now().Add(-time.Minute).UnixMilli()}); err == nil {
		t.Fatal("expired ticket must be rejected")
	}
	openSession(t, manager, instancePort, time.Minute)
	if _, err := manager.Open(OpenCommand{SessionID: "sess-1", Ticket: "t2", TargetPort: instancePort,
		ExpiresAt: time.Now().Add(time.Minute).UnixMilli()}); err == nil {
		t.Fatal("duplicate sessionId must be rejected")
	}
}

func TestConcurrentConnectionLimit(t *testing.T) {
	instancePort, stopInstance := fakeInstance(t)
	defer stopInstance()
	manager := New("", nil)
	defer manager.CloseAll("test done")
	result := openSession(t, manager, instancePort, time.Minute)
	entryPort := int(result["listenPort"].(int))

	conns := make([]net.Conn, 0, maxConnsPerSession+1)
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	for index := 0; index <= maxConnsPerSession; index++ {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(entryPort)), 3*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", index, err)
		}
		conns = append(conns, conn)
		_, _ = fmt.Fprintf(conn, "%s sess-1 ticket-abc\n", Magic)
		ack, _ := bufio.NewReader(conn).ReadString('\n')
		if index < maxConnsPerSession && ack != "OK\n" {
			t.Fatalf("conn %d ack = %q", index, ack)
		}
		if index == maxConnsPerSession && ack != "ERR busy\n" {
			t.Fatalf("beyond limit must be rejected, got %q", ack)
		}
	}
}
