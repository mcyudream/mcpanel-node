// Command mcpanel-p2p 是启动器 P2P 直连的 sidecar：
//
//	mcpanel-p2p --panel https://panel.example.com --token <启动器域令牌> --instance <实例ID>
//
// 面板地址默认按启动器适配器契约补全（…/api/plugins/ymcl-adapter/v1/p2p）。
// 就绪后向 stdout 打印一行机器可读信息（启动器据此启动 MC 客户端）：
//
//	MCP2P-READY {"local":"127.0.0.1:52341","session_id":"…","instance_id":"…","target_port":25600}
//
// 只监听 127.0.0.1；stdin 关闭 / SIGINT / SIGTERM 时回收会话退出。
// 协议见宿主仓 docs/mc-panel-p2p-protocol.md。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yudream/mcpanel-node/internal/p2pclient"
)

// version 由构建脚本注入（-X main.version=…）。
var version = "dev"

func main() {
	flag.Usage = usage
	panel := flag.String("panel", os.Getenv("MCPANEL_PANEL"), "面板地址（默认按启动器适配器契约补全 /api/plugins/ymcl-adapter/v1/p2p）")
	token := flag.String("token", os.Getenv("MCPANEL_TOKEN"), "启动器域访问令牌，建议用环境变量 MCPANEL_TOKEN")
	scheme := flag.String("auth-scheme", os.Getenv("MCPANEL_AUTH_SCHEME"), "Authorization scheme 前缀；留空＝裸 token（宿主与启动器约定）")
	instance := flag.String("instance", os.Getenv("MCPANEL_INSTANCE"), "要连接的实例 ID")
	local := flag.String("local", "127.0.0.1:0", "本地监听地址（只允许 loopback；默认随机端口）")
	statusEvery := flag.Duration("status-interval", 2*time.Second, "会话状态轮询间隔")
	readyFile := flag.String("ready-file", "", "可选：把就绪信息同时写入该文件（启动器读取用）")
	verbose := flag.Bool("verbose", false, "输出详细日志到 stderr")
	flag.Parse()

	if strings.TrimSpace(*panel) == "" || strings.TrimSpace(*instance) == "" {
		usage()
		os.Exit(2)
	}
	if !isLoopback(*local) {
		fmt.Fprintln(os.Stderr, "拒绝启动：本地入口只允许监听 loopback（127.0.0.1/localhost/[::1]）")
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	// 启动器关闭 stdin（或管道断开）时优雅退出
	go func() {
		buffer := make([]byte, 1)
		for {
			if _, err := os.Stdin.Read(buffer); err != nil {
				cancel()
				return
			}
		}
	}()

	logf := func(format string, args ...any) {
		if *verbose {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}
	err := p2pclient.Run(ctx, p2pclient.Config{
		PanelBase:   *panel,
		Token:       *token,
		AuthScheme:  *scheme,
		InstanceID:  *instance,
		LocalAddr:   *local,
		StatusEvery: *statusEvery,
		Logf:        logf,
		OnReady: func(localAddr string, session *p2pclient.Session) {
			payload, _ := json.Marshal(map[string]any{
				"local":       localAddr,
				"session_id":  session.SessionID,
				"instance_id": session.InstanceID,
				"target_port": session.TargetPort,
			})
			line := "MCP2P-READY " + string(payload)
			fmt.Println(line) // 机器可读：启动器读 stdout
			if *readyFile != "" {
				if writeErr := os.WriteFile(*readyFile, []byte(line+"\n"), 0o600); writeErr != nil {
					logf("就绪文件写入失败：%v", writeErr)
				}
			}
		},
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "P2P 直连失败：%v\n", err)
		os.Exit(1)
	}
}

func isLoopback(addr string) bool {
	host := addr
	if index := strings.LastIndex(addr, ":"); index >= 0 {
		host = addr[:index]
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "", "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

func usage() {
	fmt.Fprint(os.Stderr, `mcpanel-p2p —— 启动器 P2P 直连 sidecar（只监听 loopback）

用法：
  mcpanel-p2p --panel <面板地址> --instance <实例ID> [--token <玩家令牌>] [-verbose]

参数（也可用同名环境变量）：
  --panel        MCPANEL_PANEL       面板地址，如 https://panel.example.com
  --token        MCPANEL_TOKEN       启动器域访问令牌
  --auth-scheme  MCPANEL_AUTH_SCHEME Authorization scheme；留空＝裸 token
  --instance     MCPANEL_INSTANCE    实例 ID
  --local                            本地监听地址（默认 127.0.0.1:随机端口）
  --ready-file                       就绪信息写入文件（启动器读取）
  -verbose                           打印详细日志到 stderr

就绪后 stdout 输出一行：MCP2P-READY {"local":"127.0.0.1:52341",...}
关闭 stdin / Ctrl+C 即回收会话退出。
`)
}
