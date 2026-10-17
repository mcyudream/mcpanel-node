package wsserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/yudream/mcpanel-node/internal/certutil"
	"github.com/yudream/mcpanel-node/internal/proto"
	"github.com/yudream/mcpanel-node/internal/shellterm"
	"github.com/yudream/mcpanel-node/internal/stats"
)

// 节点终端 e2e：面板视角走完整控制信道——open → input → 输出 evt → close。
// 回归背景：终端链路（caps 宣告 / 会话输出泵 / 关闭事件）任一环断掉都会造成
// 「节点终端无法使用」；此处按协议逐帧校验。

func newTerminalHarness(t *testing.T) *harness {
	t.Helper()

	dir := t.TempDir()
	mgr := &certutil.Manager{DataDir: dir, Hostname: "node-term.test.internal"}
	cert, leaf, err := mgr.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	pin := certutil.FingerprintHex(leaf.Raw)

	srv := New(Options{
		Credential:      testCredential(),
		Stats:           &fixedStats{snapshot: stats.Snapshot{CPUPercent: 1, MemTotalMb: 1, AgentVersion: "0.1.0"}},
		Hostname:        "node-term.test.internal",
		Log:             slog.Default(),
		ShellTerm:       shellterm.NewManager(),
		TerminalEnabled: true,
	})

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	return &harness{
		t:       t,
		baseURL: "wss://" + ln.Addr().String() + ControlPath,
		pin:     pin,
		stats:   &fixedStats{},
	}
}

func sendReq(t *testing.T, conn *websocket.Conn, method string, p map[string]any) string {
	t.Helper()
	req, err := proto.NewReq(method, p)
	if err != nil {
		t.Fatal(err)
	}
	data, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
	return req.ID
}

// readTerminalEvt 逐帧读取（跳过 res/stats），返回含 needle 文本的终端输出事件载荷。
func readTerminalEvt(t *testing.T, conn *websocket.Conn, needle string) map[string]any {
	t.Helper()
	deadline := time.After(15 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("15s 内未收到含 %q 的终端输出事件", needle)
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_, data, err := conn.Read(ctx)
		cancel()
		if err != nil {
			t.Fatalf("read terminal output: %v", err)
		}
		env, err := proto.Decode(data)
		if err != nil || env.T != proto.TypeEvt || env.M != "node.terminal.output" {
			continue
		}
		var payload map[string]any
		_ = json.Unmarshal(env.P, &payload)
		if text, _ := payload["text"].(string); strings.Contains(text, needle) {
			return payload
		}
	}
}

func TestNodeTerminalEndToEnd(t *testing.T) {
	h := newTerminalHarness(t)
	conn := h.dialOK(testNodeID, testSecret)
	t.Cleanup(func() { _ = conn.Close(websocket.StatusInternalError, "") })

	hello, _ := helloAndFirstStats(t, conn)
	// caps 必须宣告终端能力（面板 caps 门禁依赖 hello 载荷）
	hasTerm := false
	for _, c := range hello.Caps {
		if c == "node.terminal.open" {
			hasTerm = true
		}
	}
	if !hasTerm {
		t.Fatalf("hello caps 缺少 node.terminal.open: %v", hello.Caps)
	}

	// open：返回归一化 terminalId
	openID := sendReq(t, conn, "node.terminal.open", map[string]any{"terminalId": "e2e-1"})
	res := readFrame(t, conn)
	if res.T != proto.TypeRes || res.ID != openID || res.M != "node.terminal.open" {
		t.Fatalf("open res 异常: %+v", res)
	}
	var opened map[string]any
	if err := json.Unmarshal(res.P, &opened); err != nil {
		t.Fatal(err)
	}
	if opened["terminalId"] != "term-e2e-1" {
		t.Fatalf("terminalId 归一化异常: %v", opened["terminalId"])
	}

	// input：回显命令，输出事件必须携带 terminalId 与命令输出
	inputID := sendReq(t, conn, "node.terminal.input", map[string]any{
		"terminalId": "term-e2e-1", "data": "echo TERM_E2E_OK\n",
	})
	inputRes := readFrame(t, conn)
	if inputRes.T != proto.TypeRes || inputRes.ID != inputID || inputRes.M != "node.terminal.input" {
		t.Fatalf("input res 异常: %+v", inputRes)
	}
	payload := readTerminalEvt(t, conn, "TERM_E2E_OK")
	if payload["terminalId"] != "term-e2e-1" {
		t.Fatalf("输出事件 terminalId 异常: %v", payload["terminalId"])
	}

	// close：res closed=true；终态 closed evt 可能先于 res 入队（输出泵与
	// 响应写队列并发），因此两个信号都见到才算通过，顺序不作假设。
	closeID := sendReq(t, conn, "node.terminal.close", map[string]any{"terminalId": "term-e2e-1"})
	resSeen, closedSeen := false, false
	deadline := time.After(10 * time.Second)
	for !resSeen || !closedSeen {
		select {
		case <-deadline:
			t.Fatalf("close 后信号不全: res=%v closedEvt=%v", resSeen, closedSeen)
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, data, err := conn.Read(ctx)
		cancel()
		if err != nil {
			t.Fatalf("read after close: %v", err)
		}
		env, err := proto.Decode(data)
		if err != nil {
			continue
		}
		if env.T == proto.TypeRes && env.ID == closeID && env.M == "node.terminal.close" {
			resSeen = true
			continue
		}
		if env.T == proto.TypeEvt && env.M == "node.terminal.output" {
			var evt map[string]any
			_ = json.Unmarshal(env.P, &evt)
			if closed, _ := evt["closed"].(bool); closed {
				closedSeen = true
			}
		}
	}
}

// TestNodeTerminalDisabledRejectsOpen：未启用终端时 open 必须干净报错（而非挂起）。
func TestNodeTerminalDisabledRejectsOpen(t *testing.T) {
	h := newHarness(t)
	conn := h.dialOK(testNodeID, testSecret)
	t.Cleanup(func() { _ = conn.Close(websocket.StatusInternalError, "") })
	helloAndFirstStats(t, conn)

	reqID := sendReq(t, conn, "node.terminal.open", map[string]any{"terminalId": "e2e-x"})
	res := readFrame(t, conn)
	if res.T != proto.TypeErr || res.ID != reqID {
		t.Fatalf("未启用终端必须返回 err 帧: %+v", res)
	}
}
