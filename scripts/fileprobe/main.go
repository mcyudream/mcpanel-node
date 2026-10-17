// Command fileprobe dials a node's control channel and exercises file.*
// interfaces one by one with per-call latency, for diagnosing panel-side
// "file.list timeout" reports.
//
// Usage:
//
//	go run ./scripts/fileprobe -url wss://127.0.0.1:7443 -node-id <id> \
//	    -secret <secret> -pin <sha256hex> -instance <instanceId>
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/yudream/mcpanel-node/internal/proto"
)

type probeClient struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[string]chan *proto.Envelope
	readErr chan error
}

func (c *probeClient) reader(ctx context.Context) {
	for {
		_, data, err := c.conn.Read(ctx)
		if err != nil {
			close(c.readErr)
			return
		}
		env, err := proto.Decode(data)
		if err != nil {
			continue
		}
		if env.T == proto.TypeEvt {
			continue // 统计/推送事件不参与请求应答配对
		}
		c.mu.Lock()
		ch, ok := c.pending[env.ID]
		c.mu.Unlock()
		if ok {
			ch <- env
		}
	}
}

func (c *probeClient) call(ctx context.Context, name, method string, payload map[string]any, summarize func(map[string]any) string) {
	req, err := proto.NewReq(method, payload)
	if err != nil {
		fmt.Printf("%-28s %12s  构造失败: %v\n", name, "", err)
		return
	}
	data, err := req.Encode()
	if err != nil {
		fmt.Printf("%-28s %12s  构造失败: %v\n", name, "", err)
		return
	}
	ch := make(chan *proto.Envelope, 1)
	c.mu.Lock()
	c.pending[req.ID] = ch
	c.mu.Unlock()

	start := time.Now()
	wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
	defer wcancel()
	c.writeMu.Lock()
	writeErr := c.conn.Write(wctx, websocket.MessageText, data)
	c.writeMu.Unlock()
	if writeErr != nil {
		fmt.Printf("%-28s %12s  写失败: %v\n", name, time.Since(start).Round(time.Millisecond), writeErr)
		return
	}

	cctx, ccancel := context.WithTimeout(ctx, 50*time.Second)
	defer ccancel()
	var env *proto.Envelope
	select {
	case env = <-ch:
	case err := <-c.readErr:
		fmt.Printf("%-28s %12s  连接关闭: %v\n", name, time.Since(start).Round(time.Millisecond), err)
		return
	case <-cctx.Done():
		fmt.Printf("%-28s %12s  超时(>50s) 请求id=%s —— 队头阻塞或节点卡死\n", name, time.Since(start).Round(time.Millisecond), req.ID)
		c.mu.Lock()
		delete(c.pending, req.ID)
		c.mu.Unlock()
		return
	}
	elapsed := time.Since(start)
	c.mu.Lock()
	delete(c.pending, req.ID)
	c.mu.Unlock()

	if env.T != proto.TypeRes {
		fmt.Printf("%-28s %12s  err: %s\n", name, elapsed.Round(time.Millisecond), string(env.P))
		return
	}
	summary := ""
	if summarize != nil {
		var out map[string]any
		if err := json.Unmarshal(env.P, &out); err == nil {
			summary = summarize(out)
		}
	}
	fmt.Printf("%-28s %12s  %s\n", name, elapsed.Round(time.Millisecond), summary)
}

func main() {
	url := flag.String("url", "wss://127.0.0.1:7443", "control URL")
	nodeID := flag.String("node-id", "", "nodeId")
	secret := flag.String("secret", "", "nodeSecret")
	pin := flag.String("pin", "", "leaf cert sha256 hex")
	instance := flag.String("instance", "", "instanceId to test")
	readPath := flag.String("path", "spigot.yml", "file path to read")
	flag.Parse()
	if *nodeID == "" || *secret == "" || *instance == "" {
		fmt.Fprintln(os.Stderr, "-node-id -secret -instance required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec // pinned probe
	if *pin != "" {
		if want, _ := hex.DecodeString(*pin); len(want) != 32 {
			fmt.Fprintln(os.Stderr, "-pin must be 64 hex chars")
			os.Exit(2)
		}
		tlsCfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return context.Canceled
			}
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != *pin {
				return context.Canceled
			}
			return nil
		}
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	header := http.Header{}
	header.Set("X-Mcpanel-Node-Id", *nodeID)
	header.Set("Authorization", "Bearer "+*secret)
	conn, _, err := websocket.Dial(dialCtx, *url+"/control", &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}},
		HTTPHeader: header,
	})
	dialCancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	client := &probeClient{conn: conn, pending: map[string]chan *proto.Envelope{}, readErr: make(chan error, 1)}
	go client.reader(ctx)

	// hello
	helloReq, _ := proto.NewReq("node.hello", map[string]string{"panelVersion": "0.1.0"})
	helloData, _ := helloReq.Encode()
	helloCh := make(chan *proto.Envelope, 1)
	client.mu.Lock()
	client.pending[helloReq.ID] = helloCh
	client.mu.Unlock()
	helloStart := time.Now()
	wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
	defer wcancel()
	if err := conn.Write(wctx, websocket.MessageText, helloData); err != nil {
		fmt.Fprintln(os.Stderr, "hello write:", err)
		os.Exit(1)
	}
	select {
	case env := <-helloCh:
		fmt.Printf("%-28s %12s\n", "node.hello", time.Since(helloStart).Round(time.Millisecond))
		_ = env
	case err := <-client.readErr:
		fmt.Fprintln(os.Stderr, "连接在 hello 期间关闭:", err)
		os.Exit(1)
	case <-time.After(20 * time.Second):
		fmt.Fprintln(os.Stderr, "hello 超时")
		os.Exit(1)
	}

	list := func(name string, page int64) {
		client.call(ctx, name, "file.list", map[string]any{
			"instanceId": *instance, "path": "", "page": page, "size": 50,
		}, func(out map[string]any) string {
			summary := ""
			if entries, ok := out["entries"].([]any); ok {
				summary = fmt.Sprintf("%d 条", len(entries))
			}
			if total, ok := out["total"].(float64); ok {
				summary += fmt.Sprintf(" / total %d", int(total))
			}
			return summary
		})
	}
	read := func(name, path string) {
		client.call(ctx, name, "file.read", map[string]any{
			"instanceId": *instance, "path": path,
		}, func(out map[string]any) string {
			if size, ok := out["size"].(float64); ok {
				return fmt.Sprintf("%d 字节", int(size))
			}
			return ""
		})
	}
	outputRead := func() {
		client.call(ctx, "instance.output.read", "instance.output.read", map[string]any{
			"instanceId": *instance, "tail": 100,
		}, func(out map[string]any) string {
			if text, ok := out["text"].(string); ok {
				return fmt.Sprintf("%d 字节", len(text))
			}
			return ""
		})
	}

	list("file.list p1", 1)
	read("file.read "+*readPath, *readPath)
	list("file.list p2", 2)
	outputRead()
	list("file.list p1 重复", 1)
	read("file.read 重复 "+*readPath, *readPath)

	fmt.Println("== 完成 ==")
}
