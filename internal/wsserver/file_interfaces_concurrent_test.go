package wsserver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/yudream/mcpanel-node/internal/certutil"
	"github.com/yudream/mcpanel-node/internal/fileutil"
	"github.com/yudream/mcpanel-node/internal/instances"
	"github.com/yudream/mcpanel-node/internal/proto"
	"github.com/yudream/mcpanel-node/internal/stats"
)

// 接口一对一并发回归：file.* 各接口在同一控制会话上并发互射。
// 断言：分页正确、应答 id 一一对应、慢的全量列表（万级目录）不队头阻塞
// 小请求（并发分发的行为回归）、混合读写删在时限内全部应答。

// frameClient 是一个按应答 id 分发的极简面板客户端：
// 并发在途请求各自等待自己的应答通道，读帧由单一 goroutine 完成。
type frameClient struct {
	t        *testing.T
	conn     *websocket.Conn
	writeMu  sync.Mutex
	mu       sync.Mutex
	pending  map[string]chan *proto.Envelope
	closed   chan struct{}
	closedMu sync.Mutex
}

func newFrameClient(t *testing.T, conn *websocket.Conn) *frameClient {
	// 响应帧可达 256KiB（proto.MaxFrameBytes），客户端读上限必须放大。
	conn.SetReadLimit(5 << 20) // 响应帧可达 proto.MaxFrameBytes（4MiB），客户端读上限须放大
	c := &frameClient{t: t, conn: conn, pending: map[string]chan *proto.Envelope{}, closed: make(chan struct{})}
	go func() {
		defer close(c.closed)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			_, data, err := conn.Read(ctx)
			cancel()
			if err != nil {
				return
			}
			env, err := proto.Decode(data)
			if err != nil {
				continue
			}
			c.mu.Lock()
			ch, ok := c.pending[env.ID]
			c.mu.Unlock()
			if ok {
				ch <- env
			}
		}
	}()
	return c
}

// do 发送请求并等待应答；超时/写失败返回 error（可在后台 goroutine 安全使用，
// 禁止在其中调用 t.Fatalf——Fatalf 只允许测试主 goroutine）。
func (c *frameClient) do(method string, payload any) (*proto.Envelope, error) {
	req, err := proto.NewReq(method, payload)
	if err != nil {
		return nil, err
	}
	data, err := req.Encode()
	if err != nil {
		return nil, err
	}

	ch := make(chan *proto.Envelope, 1)
	c.mu.Lock()
	c.pending[req.ID] = ch
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	c.writeMu.Lock()
	writeErr := c.conn.Write(ctx, websocket.MessageText, data)
	c.writeMu.Unlock()
	if writeErr != nil {
		c.mu.Lock()
		delete(c.pending, req.ID)
		c.mu.Unlock()
		return nil, writeErr
	}
	select {
	case res := <-ch:
		if res.T != proto.TypeRes {
			return nil, fmt.Errorf("%s: 应答类型 %v payload=%s", method, res.T, string(res.P))
		}
		return res, nil
	case <-time.After(25 * time.Second):
		c.mu.Lock()
		delete(c.pending, req.ID)
		c.mu.Unlock()
		return nil, fmt.Errorf("%s 90s 内未应答（队头阻塞或丢应答）", method)
	}
}

// fileInterfacesHarness 在 newHarness 基础上接入 instances/files，
// 并预置一个含 30000 个小文件的实例目录（inst-concurrent）。
func fileInterfacesHarness(t *testing.T) (*frameClient, string) {
	t.Helper()

	dir := t.TempDir()
	instSvc, err := instances.New(dir, "", testNodeID, nil)
	require.NoError(t, err)
	instID := "inst-concurrent"
	root := filepath.Join(dir, "instances", instID)
	require.NoError(t, os.MkdirAll(root, 0o755))
	for i := 0; i < 30000; i++ {
		require.NoError(t, os.WriteFile(filepath.Join(root, fmt.Sprintf("f-%05d.txt", i)), []byte("x"), 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "small.txt"), []byte("hello"), 0o644))

	mgr := &certutil.Manager{DataDir: dir, Hostname: "node-a.test.internal"}
	cert, leaf, err := mgr.Ensure()
	require.NoError(t, err)
	pin := certutil.FingerprintHex(leaf.Raw)

	srv := New(Options{
		Credential: testCredential(),
		Stats:      &fixedStats{snapshot: stats.Snapshot{AgentVersion: "0.1.0"}},
		Hostname:   "node-a.test.internal",
		Log:        slog.Default(),
		Instances:  instSvc,
		Files:      fileutil.NewManager(instSvc.Root),
	})

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	})
	require.NoError(t, err)
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	h := &harness{t: t, baseURL: "wss://" + ln.Addr().String() + ControlPath, pin: pin}
	_ = h
	conn := dialPinned(t, ln.Addr().String(), pin, testNodeID, testSecret)
	client := newFrameClient(t, conn)
	// hello 握手（do 负责登记 pending 与等应答；紧随的首帧 stats evt 由读取器丢弃）。
	hello, helloErr := client.do(proto.MethodNodeHello, map[string]string{"panelVersion": "0.1.0"})
	require.NoError(t, helloErr)
	require.Equal(t, proto.TypeRes, hello.T)
	return client, instID
}

func resPayload(res *proto.Envelope) string {
	if res == nil {
		return "<nil>"
	}
	return string(res.P)
}

func clientWait(t *testing.T, c *frameClient, id string) *proto.Envelope {
	c.mu.Lock()
	ch, ok := c.pending[id]
	c.mu.Unlock()
	require.True(t, ok)
	select {
	case res := <-ch:
		return res
	case <-time.After(20 * time.Second):
		c.t.Fatalf("等待应答超时：%s", id)
		return nil
	}
}

// dialPinned 以 pin 校验自签证书 + Bearer/nodeId 头直拨控制端点。
func dialPinned(t *testing.T, baseWSURL, pin, nodeID, secret string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
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
	header := http.Header{}
	header.Set("X-Mcpanel-Node-Id", nodeID)
	header.Set("Authorization", "Bearer "+secret)
	conn, _, err := websocket.Dial(ctx, "wss://"+baseWSURL+ControlPath, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}},
		HTTPHeader: header,
	})
	require.NoError(t, err)
	return conn
}

func TestFileListPaginationOnLargeDirectory(t *testing.T) {
	client, instID := fileInterfacesHarness(t)

	start := time.Now()
	res, doErr := client.do("file.list", map[string]any{
		"instanceId": instID, "path": "", "page": 1, "size": 50,
	})
	elapsed := time.Since(start)
	require.NoError(t, doErr)

	var payload struct {
		Entries []struct {
			Name  string `json:"name"`
			IsDir bool   `json:"isDir"`
		} `json:"entries"`
		Total int   `json:"total"`
		Page  int64 `json:"page"`
		Size  int64 `json:"size"`
	}
	require.NoError(t, json.Unmarshal(res.P, &payload))
	require.Len(t, payload.Entries, 50)
	require.Equal(t, 30001, payload.Total) // 30000 个编号文件 + small.txt
	require.Equal(t, int64(1), payload.Page)
	require.Equal(t, int64(50), payload.Size)
	require.Less(t, elapsed, 10*time.Second, "分页列表（仅 50 次 stat）应在 10s 内返回")
}

func TestFileListPageBeyondTotalIsEmpty(t *testing.T) {
	client, instID := fileInterfacesHarness(t)
	// 601 页恰含最后 1 条（30001 = 600*50 + 1）；602 页起为空。
	res, doErr := client.do("file.list", map[string]any{
		"instanceId": instID, "path": "", "page": 602, "size": 50,
	})
	require.NoError(t, doErr)
	var payload struct {
		Entries []map[string]any `json:"entries"`
		Total   int              `json:"total"`
	}
	require.NoError(t, json.Unmarshal(res.P, &payload))
	require.Empty(t, payload.Entries)
	require.Equal(t, 30001, payload.Total)
}

func TestFileReadAndKeywordFilter(t *testing.T) {
	client, instID := fileInterfacesHarness(t)

	res, doErr := client.do("file.read", map[string]any{"instanceId": instID, "path": "small.txt"})
	require.NoError(t, doErr)
	var read struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
		Size     int    `json:"size"`
	}
	require.NoError(t, json.Unmarshal(res.P, &read))
	require.Equal(t, "base64", read.Encoding)
	require.Equal(t, 5, read.Size)

	res, doErr = client.do("file.list", map[string]any{
		"instanceId": instID, "path": "", "page": 1, "size": 10, "keyword": "f-2999",
	})
	require.NoError(t, doErr)
	var payload struct {
		Entries []struct {
			Name string `json:"name"`
		} `json:"entries"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(res.P, &payload))
	require.Len(t, payload.Entries, 10)
	require.Equal(t, 10, payload.Total) // f-29990..f-29999（f-%05d 零填充，无 f-2999.txt）
}

// 慢操作（万级目录全量列表）不得队头阻塞小请求：并发分发行为回归。
func TestFullListDoesNotBlockSmallRead(t *testing.T) {
	client, instID := fileInterfacesHarness(t)

	bigDone := make(chan struct{})
	go func() {
		defer close(bigDone)
		client.do("file.list", map[string]any{"instanceId": instID, "path": ""})
	}()

	time.Sleep(100 * time.Millisecond) // 让全量列表先进入处理
	select {
	case <-bigDone:
		t.Skip("环境过快，全量列表已先行完成；并发断言在本机不具区分度")
	default:
	}

	start := time.Now()
	res, doErr := client.do("file.read", map[string]any{"instanceId": instID, "path": "small.txt"})
	elapsed := time.Since(start)
	require.NoError(t, doErr)

	var read struct {
		Size int `json:"size"`
	}
	require.NoError(t, json.Unmarshal(res.P, &read))
	require.Equal(t, 5, read.Size)
	require.Less(t, elapsed, 5*time.Second, "小请求应立即得到应答而非排队等待全量列表")
}

// 24 路并发 file.list（不同 page/keyword）+ 交错读写删：全部在 20s 内应答。
func TestMixedInterfacesConcurrent(t *testing.T) {
	client, instID := fileInterfacesHarness(t)

	const workers = 24
	var wg sync.WaitGroup
	fail := make(chan string, workers*2)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					fail <- fmt.Sprintf("worker-%d panic: %v", worker, r)
				}
			}()
			page := int64(worker%600) + 1
			res, doErr := client.do("file.list", map[string]any{
				"instanceId": instID, "path": "", "page": page, "size": 50,
			})
			if doErr != nil {
				// 超过分发闸门的请求按设计收到 node.busy（可重试）；
				// 超时或其他错误码才是回归。
				if strings.Contains(doErr.Error(), "node.busy") {
					return
				}
				fail <- fmt.Sprintf("worker-%d: %v | res=%s", worker, doErr, string(resPayload(res)))
				return
			}
			if res.T != proto.TypeRes {
				fail <- fmt.Sprintf("worker-%d 应答类型错误 res=%s", worker, string(res.P))
			}
		}(i)
	}
	// 交错一轮写类操作（带 ik 幂等键，Mutate 实例级串行）。
	ops := []struct {
		method  string
		payload map[string]any
	}{
		{"file.mkdir", map[string]any{"instanceId": instID, "path": "conc-dir", "ik": "mk-1"}},
		{"file.write", map[string]any{"instanceId": instID, "path": "conc-dir/a.txt", "content": "YWJj", "encoding": "base64", "ik": "wr-1"}},
		{"file.rename", map[string]any{"instanceId": instID, "from": "conc-dir/a.txt", "to": "conc-dir/b.txt", "ik": "rn-1"}},
		{"file.read", map[string]any{"instanceId": instID, "path": "conc-dir/b.txt"}},
	}
	opsDone := make(chan struct{})
	go func() {
		defer close(opsDone)
		for _, op := range ops {
			client.do(op.method, op.payload)
		}
	}()

	opsWait := make(chan struct{})
	go func() {
		select {
		case <-opsDone:
			close(opsWait)
		case <-time.After(20 * time.Second):
			fail <- "写类操作 20s 未完成"
		}
	}()
	wgDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(wgDone)
	}()
	select {
	case <-wgDone:
	case <-time.After(20 * time.Second):
		t.Fatal("并发 file.list 20s 内未全部应答（队头阻塞或丢应答）")
	}
	<-opsWait
	close(fail)
	for msg := range fail {
		t.Error(msg)
	}
}

// 200 路洪水并发（分页列表 + 读文件混射）：排队等待机制下应零 busy、零超时，
// 全部在 25s 内得到正确应答——日常使用突发不允许出现任何丢弃。
func TestFloodRequestsZeroBusy(t *testing.T) {
	client, instID := fileInterfacesHarness(t)

	const total = 200
	var wg sync.WaitGroup
	fail := make(chan string, total)
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					fail <- fmt.Sprintf("req-%d panic: %v", i, r)
				}
			}()
			if i%4 == 0 {
				res, doErr := client.do("file.read", map[string]any{
					"instanceId": instID, "path": "small.txt",
				})
				if doErr != nil {
					fail <- fmt.Sprintf("read-%d: %v", i, doErr)
					return
				}
				var body struct {
					Size int `json:"size"`
				}
				if err := json.Unmarshal(res.P, &body); err != nil || body.Size != 5 {
					fail <- fmt.Sprintf("read-%d 内容异常", i)
				}
				return
			}
			res, doErr := client.do("file.list", map[string]any{
				"instanceId": instID, "path": "", "page": int64(i%601) + 1, "size": 100,
			})
			if doErr != nil {
				fail <- fmt.Sprintf("list-%d: %v", i, doErr)
				return
			}
			var body struct {
				Entries []map[string]any `json:"entries"`
			}
			if err := json.Unmarshal(res.P, &body); err != nil {
				fail <- fmt.Sprintf("list-%d 解析失败: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(fail)
	for msg := range fail {
		t.Error(msg)
	}
}

// 全分页扫过：所有页拼接后 = 过滤后总数（30001），无重复、无丢失——零丢弃语义。
func TestFullPaginationSweepCoversAllEntries(t *testing.T) {
	client, instID := fileInterfacesHarness(t)

	seen := map[string]bool{}
	const size = 500
	fileSeen := false
	dirsAfterFile := false
	for page := int64(1); ; page++ {
		res, doErr := client.do("file.list", map[string]any{
			"instanceId": instID, "path": "", "page": page, "size": size,
		})
		require.NoError(t, doErr)
		var payload struct {
			Entries []struct {
				Name  string `json:"name"`
				IsDir bool   `json:"isDir"`
			} `json:"entries"`
			Total int   `json:"total"`
			Page  int64 `json:"page"`
		}
		require.NoError(t, json.Unmarshal(res.P, &payload))
		require.Equal(t, page, payload.Page)
		for _, entry := range payload.Entries {
			require.False(t, seen[entry.Name], "条目重复：%s", entry.Name)
			seen[entry.Name] = true
			if entry.IsDir && fileSeen {
				dirsAfterFile = true
			}
			if !entry.IsDir {
				fileSeen = true
			}
		}
		if int64(len(seen)) >= int64(payload.Total) || len(payload.Entries) == 0 {
			break
		}
		if page > 100 {
			t.Fatal("分页未收敛（超过 100 页）")
		}
	}
	require.Equal(t, 30001, len(seen))
	require.False(t, dirsAfterFile, "目录优先排序在分页边界被破坏")
}
