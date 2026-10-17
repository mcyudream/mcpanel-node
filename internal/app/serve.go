// Package app wires configuration, credentials, TLS, stats, the control
// channel server and the optional embedded frpc into the node runtime.
package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
 "log/slog"
 "net"
 "net/http"
 "os"
 "os/signal"
 "path/filepath"
 "strconv"
	"syscall"
	"time"

 "github.com/yudream/mcpanel-node/internal/certutil"
 "github.com/yudream/mcpanel-node/internal/config"
 "github.com/yudream/mcpanel-node/internal/credential"
 "github.com/yudream/mcpanel-node/internal/dockerx"
 "github.com/yudream/mcpanel-node/internal/enroll"
 "github.com/yudream/mcpanel-node/internal/fileutil"
 "github.com/yudream/mcpanel-node/internal/frpc"
 "github.com/yudream/mcpanel-node/internal/instances"
 "github.com/yudream/mcpanel-node/internal/ftpserv"
 "github.com/yudream/mcpanel-node/internal/logutil"
 "github.com/yudream/mcpanel-node/internal/shellterm"
 "github.com/yudream/mcpanel-node/internal/stats"
 "github.com/yudream/mcpanel-node/internal/tasks"
 "github.com/yudream/mcpanel-node/internal/version"
 "github.com/yudream/mcpanel-node/internal/wsserver"
)

// enrollClient builds the bootstrap client honoring the admin-provided pin.
func enrollClient(cfg *config.Config, log *slog.Logger) (*enroll.Client, error) {
	return enroll.NewClient(cfg.Panel.URL, cfg.Panel.TLSPinSha256, log)
}

// enrollRequest assembles the bootstrap body (protocol §2).
func enrollRequest(cfg *config.Config, hostname, tlsCertSha256 string) enroll.Request {
	return enroll.Request{
		EnrollToken:   cfg.Enroll.Token,
		Hostname:      hostname,
		AgentVersion:  version.Version,
		Caps:          enroll.Caps,
		TLSCertSha256: tlsCertSha256,
	}
}

// Options carries the resolved runtime inputs for Serve.
type Options struct {
	Config *config.Config
	Log    *slog.Logger
}

// Serve runs the node until the context is cancelled or a SIGINT/SIGTERM
// arrives. TLS terminates here; any frp tunnel only relays TCP.
func Serve(ctx context.Context, opts Options) error {
 cfg := opts.Config
 log := opts.Log

 // 节点生命周期 ctx：业务长任务（镜像拉取/安装）随节点关闭一并取消。
 lifecycle, stopLifecycle := context.WithCancel(ctx)
 defer stopLifecycle()

 credStore := credential.NewStore(cfg.DataDir, cfg.Credential.Path)
 if !credStore.Exists() {
  return errors.New("no credential found; run `mcpanel-node enroll` first (M1 does not support re-enrollment of a registered node without deleting its panel record)")
 }
 cred, err := credStore.Load()
 if err != nil {
  return fmt.Errorf("load credential: %w", err)
 }
 log.Info("credential loaded", "nodeId", cred.NodeID, "nodeSecret", logutil.Redact(cred.NodeSecret),
  "controlPlan", cred.ControlPlan.Mode)

 hostname := cfg.TLS.Hostname
 if hostname == "" {
  hostname, _ = os.Hostname()
 }
 certMgr := &certutil.Manager{
  DataDir:  cfg.DataDir,
  CertFile: cfg.TLS.CertFile,
  KeyFile:  cfg.TLS.KeyFile,
  Hostname: hostname,
 }
 tlsCert, leaf, err := certMgr.Ensure()
 if err != nil {
  return fmt.Errorf("resolve tls certificate: %w", err)
 }
 log.Info("tls certificate ready",
  "pin", certutil.FingerprintHex(leaf.Raw),
  "subject", leaf.Subject.CommonName, "notAfter", leaf.NotAfter.Format(time.RFC3339))

 // Docker is best-effort: without a daemon the control channel still serves
 // hello/stats, and every business method answers a clean error.
 dockerCli, err := dockerx.New()
 if err == nil {
  pingCtx, cancel := context.WithTimeout(lifecycle, 3*time.Second)
  err = dockerCli.Ping(pingCtx)
  cancel()
 }
 if err != nil {
  log.Warn("docker unavailable; business operations disabled", "err", err)
  _ = dockerCli.Close()
  dockerCli = nil
 }
 if dockerCli != nil {
  defer func() { _ = dockerCli.Close() }()
 }

 collector := stats.New(cfg.DataDir, dockerCli, log)

 // 业务装配：实例数据根 = dataDir；容器内部署时 Docker 引擎看到的宿主路径
 // 由 cfg.Data.HostRoot 提供（默认与 dataDir 相同）。
 hostRoot := cfg.Data.HostRoot
 if hostRoot == "" {
  hostRoot = cfg.DataDir
  // 容器化节点（挂了 docker.sock）未设 hostRoot 时，实例容器的绑定源
  // 是节点容器内的 /data——宿主引擎必然不存在该路径，创建实例必失败。
  if _, err := os.Stat("/var/run/docker.sock"); err == nil {
   log.Warn("data.hostRoot 未设置：创建实例的绑定源将使用 " + hostRoot +
    "；容器化节点必须把宿主目录 bind-mount 到 dataDir，并设置 MCNODE_DATA_HOST_ROOT=宿主目录，否则实例容器会因绑定路径不存在而创建失败")
  }
 }
 engine := asEngine(dockerCli)
 instanceSvc, fileMgr, taskReg, backupDir, ftpMgr, termMgr, err := assembleServices(cfg, hostRoot, cred.NodeID, engine, log)
 if err != nil {
  return err
 }
 // 启动成功检测窗口 → stats 快照把 running 覆写为 starting（面板三口径一致）。
 if instanceSvc != nil {
  collector.SetStartingLookup(instanceSvc.IsStarting)
 }
 // 存量实例容器策略对齐：旧版节点创建的容器 HostConfig 已固化（如缺
 // DAC_OVERRIDE 导致实例内进程 EACCES），节点启动即重建修复，运行中的恢复
 // 运行。异步执行不阻塞控制通道上线。
 if instanceSvc != nil && engine != nil {
  go instanceSvc.ReconcileContainers(lifecycle, log)
 }

 srv := wsserver.New(wsserver.Options{
  Credential: cred,
  Stats:      collector,
  Hostname:   hostname,
  Log:        log,
  Engine:     engine,
  Instances:  instanceSvc,
  Files:      fileMgr,
  FileRoots:  cfg.FileRoots,
  Tasks:      taskReg,
  ShellTerm:  termMgr,
  TerminalEnabled: cfg.Security.TerminalEnabled,
  FTP:        ftpMgr,
  FTPBasePort: ftpBasePort(cfg),
  BackupDir:  backupDir,
  Lifecycle:  lifecycle,
 })
 srv.StartEvents()

 // 回收站保留期清扫：每小时一次，清除超过 trash.retentionDays 的回收目录
 // （0=永久保留）。随 lifecycle 退出，进程重启不补扫错删——下个整点即扫。
 go trashSweeper(lifecycle, instanceSvc, log)

 // Optional outbound tunnel (controlPlan frp mode or explicit local dev
 // config). The tunnel is raw TCP relay; TLS still terminates at the node.
 var tunnel *frpc.Runner
 if cred.ControlPlan.Mode == "frp" && cred.ControlPlan.FRP != nil {
  plan := cred.ControlPlan.FRP
  tunnel, err = frpc.Start(ctx, frpc.Config{
   ServerAddr: plan.ServerAddr,
   ServerPort: plan.ServerPort,
   User:       plan.ProxyUser,
   ProxyName:  fmt.Sprintf("control-%s", cred.NodeID),
   Token:      plan.ProxyToken,
   RemotePort: plan.RemotePort,
   LocalIP:    "127.0.0.1",
   LocalPort:  listenPort(cfg.Listen),
  }, log)
  if err != nil {
   return fmt.Errorf("start embedded frpc: %w", err)
  }
  log.Info("embedded frpc started (experimental M1b tunnel)", "remotePort", plan.RemotePort)
 } else if cfg.FRPC.Enabled {
  tunnel, err = frpc.Start(ctx, frpc.Config{
   ServerAddr: cfg.FRPC.ServerAddr,
   ServerPort: cfg.FRPC.ServerPort,
   User:       cfg.FRPC.User,
   ProxyName:  orDefault(cfg.FRPC.ProxyName, "control"),
   Token:      cfg.FRPC.Token,
   RemotePort: cfg.FRPC.RemotePort,
   LocalIP:    orDefault(cfg.FRPC.LocalIP, "127.0.0.1"),
   LocalPort:  orDefaultInt(cfg.FRPC.LocalPort, listenPort(cfg.Listen)),
  }, log)
  if err != nil {
   return fmt.Errorf("start embedded frpc (local dev config): %w", err)
  }
  log.Warn("embedded frpc started from local config (experimental; do not share frps admin tokens)")
 }

 ln, err := tls.Listen("tcp", cfg.Listen, &tls.Config{
  MinVersion:   tls.VersionTLS12,
  Certificates: []tls.Certificate{tlsCert},
 })
 if err != nil {
  if tunnel != nil {
   tunnel.Stop()
  }
  return fmt.Errorf("listen %s: %w", cfg.Listen, err)
 }
 defer func() {
  _ = ln.Close()
 }()

 httpSrv := &http.Server{
  Handler:           srv.Handler(),
  ReadHeaderTimeout: 10 * time.Second,
 }

 log.Info("node control channel listening", "addr", cfg.Listen, "path", wsserver.ControlPath,
  "businessOps", engine != nil)

 errCh := make(chan error, 1)
 go func() { errCh <- httpSrv.Serve(ln) }()

 stop := make(chan os.Signal, 1)
 signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
 defer signal.Stop(stop)

 var runErr error
 select {
 case <-ctx.Done():
 case sig := <-stop:
  log.Info("shutdown signal received", "signal", sig.String())
 case runErr = <-errCh:
 }

 // Teardown order:
 //  1. stop accepting new control connections;
 //  2. actively cancel + force-close hijacked websocket sessions
 //     (http.Server.Shutdown does NOT close hijacked connections)
 //     and cancel long-running business tasks via lifecycle;
 //  3. stop the outbound tunnel and release the docker client.
 shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
 defer cancel()
 _ = httpSrv.Shutdown(shutdownCtx)
 srv.Shutdown()
 stopLifecycle()
 if tunnel != nil {
  tunnel.Stop()
 }
 if errors.Is(runErr, http.ErrServerClosed) {
  runErr = nil
 }
 return runErr
}

func ftpBasePort(cfg *config.Config) int {
 if cfg.FTP.BasePort > 0 {
  return cfg.FTP.BasePort
 }
 return 2121
}

// trashSweeper 每小时清扫一次过期回收目录；实例服务不可用时静默退出。
func trashSweeper(ctx context.Context, svc *instances.Service, log *slog.Logger) {
 if svc == nil {
  return
 }
 ticker := time.NewTicker(time.Hour)
 defer ticker.Stop()
 for {
  select {
  case <-ctx.Done():
   return
  case <-ticker.C:
   if n := svc.SweepExpiredTrash(time.Now()); n > 0 {
    log.Info("expired trash swept", "count", n)
   }
  }
 }
}

func asEngine(cli *dockerx.Client) wsserver.DockerEngine {
 if cli == nil {
  return nil
 }
 return cli
}

func assembleServices(cfg *config.Config, hostRoot, nodeID string, engine wsserver.DockerEngine, log *slog.Logger) (*instances.Service, *fileutil.Manager, *tasks.Registry, string, *ftpserv.Manager, *shellterm.Manager, error) {
 instanceSvc, err := instances.New(cfg.DataDir, hostRoot, nodeID, engine)
 if err != nil {
  log.Warn("instance service unavailable", "err", err)
  instanceSvc = nil
 } else {
  instanceSvc.SetTrashRetention(cfg.Trash.RetentionDays)
 }
 ftpMgr, err := ftpserv.NewManager()
 if err != nil {
  return nil, nil, nil, "", nil, nil, err
 }
 var fileMgr *fileutil.Manager
 if instanceSvc != nil {
  fileMgr = fileutil.NewManager(instanceSvc.Root)
 } else {
  fileMgr = fileutil.NewManager(func(string) (string, error) { return "", errors.New("实例服务不可用") })
 }
 taskReg := tasks.New()
 backupDir := filepath.Join(cfg.DataDir, "backups")
 return instanceSvc, fileMgr, taskReg, backupDir, ftpMgr, shellterm.NewManager(), nil
}

// Enroll executes the bootstrap flow and persists the issued credential.
// Refuses to run when a credential already exists: M1 has no rekey and a
// registered node must not re-bootstrap (protocol §1).
func Enroll(ctx context.Context, cfg *config.Config, log *slog.Logger) (credential.Credential, error) {
	if err := cfg.ValidateEnroll(); err != nil {
		return credential.Credential{}, err
	}
	credStore := credential.NewStore(cfg.DataDir, cfg.Credential.Path)
	if credStore.Exists() {
		return credential.Credential{}, errors.New("credential already exists; this node is already enrolled (M1: delete the panel node record and remove " + credStore.Path + " to re-enroll)")
	}

	hostname := cfg.TLS.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	certMgr := &certutil.Manager{
		DataDir:  cfg.DataDir,
		CertFile: cfg.TLS.CertFile,
		KeyFile:  cfg.TLS.KeyFile,
		Hostname: hostname,
	}
	// The TLS certificate must exist before bootstrap: its fingerprint is
	// reported in the request body and pinned on the panel side.
	_, leaf, err := certMgr.Ensure()
	if err != nil {
		return credential.Credential{}, fmt.Errorf("resolve tls certificate: %w", err)
	}
	fp := certutil.FingerprintHex(leaf.Raw)
	log.Info("node tls fingerprint (pin this on the panel)", "pin", fp)

	client, err := enrollClient(cfg, log)
	if err != nil {
		return credential.Credential{}, err
	}
	cred, err := client.Bootstrap(ctx, enrollRequest(cfg, hostname, fp))
	if err != nil {
		return credential.Credential{}, err
	}
	if err := credStore.Save(cred); err != nil {
		return credential.Credential{}, fmt.Errorf("save credential: %w", err)
	}
	log.Info("enrolled", "nodeId", cred.NodeID, "controlPlan", cred.ControlPlan.Mode,
		"nodeSecret", logutil.Redact(cred.NodeSecret))
	return cred, nil
}

func listenPort(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func orDefaultInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}
