package instances

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "log/slog"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "time"
 "testing"

 "github.com/yudream/mcpanel-node/internal/dockerx"
)

func validSpec() Spec {
 return Spec{
  InstanceID: "inst-001", Name: "主服", Image: "eclipse-temurin:21-jre",
  Command: []string{"java", "-jar", "paper.jar"}, Env: map[string]string{"XMS": "512M"},
  MemoryMb: 1024, CPUMillis: 1000, DiskMb: 2048,
  Ports: []dockerx.PortBinding{{Port: 25565, ContainerPort: 25565, Proto: "tcp"}},
  Kind: "paper", Config: map[string]string{"motd": "hello"},
 }
}

func TestSpecValidate(t *testing.T) {
 if err := validSpec().Validate(); err != nil {
  t.Fatalf("合法规格被拒: %v", err)
 }
 bad := []func(s *Spec){
  func(s *Spec) { s.InstanceID = "../x" },
  func(s *Spec) { s.Image = "a b" },
  func(s *Spec) { s.Command = nil },
  func(s *Spec) { s.MemoryMb = 10 },
  func(s *Spec) { s.CPUMillis = 1 },
  func(s *Spec) { s.Env = map[string]string{"1BAD": "x"} },
  func(s *Spec) { s.Ports = []dockerx.PortBinding{{Port: 80, ContainerPort: 80, Proto: "tcp"}} },
  func(s *Spec) { s.Ports = []dockerx.PortBinding{{Port: 25565, ContainerPort: 25565, Proto: "sctp"}} },
  func(s *Spec) { s.Kind = "unknown" },
 }
 for i, mutate := range bad {
  s := validSpec()
  mutate(&s)
  if err := s.Validate(); err == nil {
   t.Fatalf("case %d 必须被拒绝", i)
  }
 }
}

type fakeEngine struct {
 mu          sync.Mutex
 created     []dockerx.ContainerSpec
 actions     []string
 byContainer map[string]dockerx.ContainerState
 containerOf map[string]string
 nextID      int
}

func (f *fakeEngine) Create(_ context.Context, _ string, spec dockerx.ContainerSpec) (string, error) {
 f.mu.Lock(); defer f.mu.Unlock()
 f.nextID++
 id := "cid-" + string(rune('0'+f.nextID/10)) + string(rune('0'+f.nextID%10))
 if f.byContainer == nil {
  f.byContainer = map[string]dockerx.ContainerState{}
  f.containerOf = map[string]string{}
 }
 f.created = append(f.created, spec)
 // 与真实 Docker 行为一致：容器回填 create 时请求的 capability 策略。
 f.byContainer[id] = dockerx.ContainerState{ID: id, State: "created", Labels: labelOf(spec),
  CapAdd: dockerx.InstanceCapAdd, CapDrop: dockerx.InstanceCapDrop}
 f.containerOf[spec.InstanceID] = id
 return id, nil
}

func labelOf(spec dockerx.ContainerSpec) map[string]string {
 return map[string]string{"mcpanel.managed": "true", "mcpanel.instanceId": spec.InstanceID, "mcpanel.nodeId": spec.NodeID}
}

func (f *fakeEngine) Inspect(_ context.Context, id string) (dockerx.ContainerState, error) {
 f.mu.Lock(); defer f.mu.Unlock()
 if st, ok := f.byContainer[id]; ok {
  return st, nil
 }
 return dockerx.ContainerState{}, &dockerx.APIError{Status: 404, Message: "no such container"}
}

func (f *fakeEngine) Action(_ context.Context, id, action string, _ int) error {
 f.mu.Lock(); defer f.mu.Unlock()
 f.actions = append(f.actions, action)
 st, ok := f.byContainer[id]
 if !ok {
  return &dockerx.APIError{Status: 404, Message: "no such container"}
 }
 switch action {
 case "start":
  st.State = "running"; st.Running = true
 case "stop", "kill":
  st.State = "exited"; st.Running = false; st.ExitCode = 0
 }
 f.byContainer[id] = st
 return nil
}

func (f *fakeEngine) Remove(_ context.Context, _ string) error { return nil }
func (f *fakeEngine) Logs(_ context.Context, _ string, _ string, _ int) (string, bool, error) {
 // 与 docker logs --timestamps 的真实行格式一致：RFC3339Nano + 空格 + 内容。
 return "2026-01-01T00:00:00.000000000Z Done (3.2s)! \n", false, nil
}
func (f *fakeEngine) AttachWriter(_ context.Context, _ string) (io.WriteCloser, error) {
 r, w := io.Pipe()
 go func() { _ = r.Close() }()
 return w, nil
}
func (f *fakeEngine) Pull(_ context.Context, _ string) error { return nil }
func (f *fakeEngine) ImageExists(context.Context, string) bool { return true }
func (f *fakeEngine) UpdateRestartPolicy(_ context.Context, _ string, _ string) error {
 return nil
}

func newTestService(t *testing.T) (*Service, *fakeEngine) {
 t.Helper()
 root := t.TempDir()
 engine := &fakeEngine{}
 svc, err := New(root, root, "node-1", engine)
 if err != nil {
  t.Fatal(err)
 }
 return svc, engine
}

func TestCreateStartAndConfigRewrite(t *testing.T) {
 svc, _ := newTestService(t)
 var states []string
 var mu sync.Mutex
 svc.SetOnStateChange(func(instanceID, state string) {
  mu.Lock(); states = append(states, state); mu.Unlock()
 })
 ctx := context.Background()
 spec := validSpec()
 rec, err := svc.Create(ctx, spec)
 if err != nil {
  t.Fatal(err)
 }
 if rec.ContainerID == "" || rec.State != "created" {
  t.Fatalf("创建结果异常: %+v", rec)
 }
 if _, err := svc.Create(ctx, spec); err == nil || !strings.Contains(err.Error(), "已存在") {
  t.Fatalf("重复创建必须被拒: %v", err)
 }
 out, err := svc.Action(ctx, spec.InstanceID, "start", 30)
 if err != nil {
  t.Fatal(err)
 }
 // paper 默认启动标记（"Done ("）在桩 Logs 里必命中：动作返回即报 starting，
 // 真实 running 由检测窗口命中后经 onState 回调回推。
 if m, ok := out.(Record); !ok || m.State != "starting" {
  t.Fatalf("启动后应处于 starting（检测窗口内）: %+v", out)
 }
 // 检测 goroutine 轮询间隔 2s，等命中回推。
 deadline := time.Now().Add(5 * time.Second)
 for svc.IsStarting(spec.InstanceID) && time.Now().Before(deadline) {
  time.Sleep(50 * time.Millisecond)
 }
 if svc.IsStarting(spec.InstanceID) {
  t.Fatalf("启动检测未在预期时间内命中标记")
 }
 mu.Lock(); pushed := append([]string(nil), states...); mu.Unlock()
 if len(pushed) == 0 || pushed[len(pushed)-1] != "running" {
  t.Fatalf("检测命中应回推 running: %v", pushed)
 }
 b, err := os.ReadFile(filepath.Join(svc.root, "instances", spec.InstanceID, "server.properties"))
 if err != nil {
  t.Fatal(err)
 }
 props := string(b)
 if !strings.Contains(props, "server-port=25565") || !strings.Contains(props, "motd=hello") {
  t.Fatalf("启动前配置重写缺失: %s", props)
 }
}

func TestStartWithoutMarkerStaysRunningImmediately(t *testing.T) {
 svc, _ := newTestService(t)
 ctx := context.Background()
 spec := validSpec()
 spec.Kind = "generic" // generic 无默认标记：不进入检测窗口
 if _, err := svc.Create(ctx, spec); err != nil {
  t.Fatal(err)
 }
 out, err := svc.Action(ctx, spec.InstanceID, "start", 30)
 if err != nil {
  t.Fatal(err)
 }
 if m, ok := out.(Record); !ok || m.State != "running" {
  t.Fatalf("无启动标记时应立即 running: %+v", out)
 }
 if svc.IsStarting(spec.InstanceID) {
  t.Fatalf("generic 不应进入启动检测窗口")
 }
}

func TestStartWatchCustomMarkerAndTimeout(t *testing.T) {
 svc, engine := newTestService(t)
 // 桩 Logs 恒返 "Done ("，自定义标记永不命中 → 只能靠超时兜底。
 // 把窗口调短不可行（常量），改为注册 onState 后用 die 事件路径收口。
 var states []string
 var mu sync.Mutex
 svc.SetOnStateChange(func(instanceID, state string) {
  mu.Lock(); states = append(states, state); mu.Unlock()
 })
 ctx := context.Background()
 spec := validSpec()
 spec.StartDetect = "NEVER_MATCH_MARKER"
 if _, err := svc.Create(ctx, spec); err != nil {
  t.Fatal(err)
 }
 if _, err := svc.Action(ctx, spec.InstanceID, "start", 30); err != nil {
  t.Fatal(err)
 }
 if !svc.IsStarting(spec.InstanceID) {
  t.Fatalf("自定义标记未命中前应处于检测窗口")
 }
 insp, err := svc.Inspect(ctx, spec.InstanceID)
 if err != nil {
  t.Fatal(err)
 }
 if insp.State != "starting" {
  t.Fatalf("检测窗口内 Inspect 应回 starting: %+v", insp)
 }
 // 容器 die：窗口收口且不再回推 running（退出状态由事件承载）。
 svc.CancelStartWatch(spec.InstanceID)
 if svc.IsStarting(spec.InstanceID) {
  t.Fatalf("die 后检测窗口应收口")
 }
 _ = engine
}

func TestDefaultStartDetectByKind(t *testing.T) {
 cases := map[string]string{
  "vanilla": "Done (", "paper": "Done (", "fabric": "Done (", "velocity": "Done (",
  "bungee": "Listening on", "bedrock": "Server started", "generic": "",
 }
 for kind, want := range cases {
  spec := validSpec()
  spec.Kind = kind
  if got := spec.DefaultStartDetect(); got != want {
   t.Fatalf("kind=%s 默认标记 = %q, want %q", kind, got, want)
  }
 }
}

func TestMutateIdempotencyAndConflict(t *testing.T) {
 svc, _ := newTestService(t)
 ctx := context.Background()
 p, _ := json.Marshal(map[string]any{"instanceId": "inst-x"})
 first, err := svc.Mutate(ctx, "instance.start", "key-1234567890abcdef", "inst-x", p, func() (any, error) {
  return map[string]int{"n": 1}, nil
 })
 if err != nil {
  t.Fatal(err)
 }
 again, err := svc.Mutate(ctx, "instance.start", "key-1234567890abcdef", "inst-x", p, func() (any, error) {
  t.Fatal("幂等命中不应重复执行")
  return nil, nil
 })
 if err != nil {
  t.Fatal(err)
 }
 if first.(map[string]any)["n"].(float64) != again.(map[string]any)["n"].(float64) {
  t.Fatal("幂等结果不一致")
 }
 p2, _ := json.Marshal(map[string]any{"instanceId": "inst-y"})
 if _, err := svc.Mutate(ctx, "instance.start", "key-1234567890abcdef", "inst-x", p2, nil); err == nil || !strings.Contains(err.Error(), "operation.conflict") {
  t.Fatalf("同键不同载荷必须冲突: %v", err)
 }
 if _, err := svc.Mutate(ctx, "instance.stop", "short", "inst-x", p, nil); err == nil {
  t.Fatal("过短幂等键必须被拒绝")
 }
}

func TestFailedOperationRetryableWithSameKey(t *testing.T) {
	// 业务失败是确定性结果：pending 记录必须被清除，同一幂等键可重试。
	// 否则面板侧固定幂等键（如 panel-delete-<id>-keep）会在一次失败后永久卡死。
	svc, _ := newTestService(t)
	ctx := context.Background()
	p, _ := json.Marshal(map[string]any{"instanceId": "inst-r"})
	called := 0
	_, err := svc.Mutate(ctx, "instance.delete", "key-1234567890abcdef", "inst-r", p, func() (any, error) {
		called++
		return nil, errors.New("请先停止实例")
	})
	if err == nil || called != 1 {
		t.Fatalf("失败必须返回错误且只执行一次: %v", err)
	}
	result, err := svc.Mutate(ctx, "instance.delete", "key-1234567890abcdef", "inst-r", p, func() (any, error) {
		called++
		return map[string]bool{"deleted": true}, nil
	})
	if err != nil {
		t.Fatalf("同键重试必须重新执行而非 uncertain: %v", err)
	}
	if called != 2 {
		t.Fatalf("重试应再次执行 fn, called=%d", called)
	}
	if !result.(map[string]any)["deleted"].(bool) {
		t.Fatalf("重试结果异常: %+v", result)
	}
}

func TestUncertainOperationNotReplayed(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	p, _ := json.Marshal(map[string]any{})

	// 模拟进程在 fn 执行中途崩溃：pending 记录留在磁盘且状态不确定。
	// 文件名为 sha256(幂等键)，内容 digest 为 sha256(载荷)。
	key := "key-1234567890abcdef"
	digest := sha256.Sum256(p)
	entry := fmt.Sprintf(`{"method":"instance.start","digest":%q,"state":"pending","at":1}`,
		hex.EncodeToString(digest[:]))
	keyHash := sha256.Sum256([]byte(key))
	opPath := filepath.Join(svc.root, "operations", hex.EncodeToString(keyHash[:])+".json")
	if err := os.WriteFile(opPath, []byte(entry), 0o600); err != nil {
		t.Fatal(err)
	}
	called := 0
	_, err := svc.Mutate(ctx, "instance.start", key, "inst-u", p, func() (any, error) {
		t.Fatal("pending 记录不得自动重放")
		called++
		return nil, nil
	})
	if err == nil || !strings.Contains(err.Error(), "operation.uncertain") {
		t.Fatalf("中断操作必须返回 uncertain: %v", err)
	}
	if called != 0 {
		t.Fatalf("uncertain 不得执行 fn, called=%d", called)
	}
}

// staleCaps 把已存在容器改成旧版节点创建的形态：CapDrop ALL 但未保留
// DAC_OVERRIDE（0.6.2 之前的产品行为）。
func staleCaps(t *testing.T, engine *fakeEngine, containerID string) {
 t.Helper()
 engine.mu.Lock()
 st := engine.byContainer[containerID]
 st.CapAdd, st.CapDrop = nil, []string{"ALL"}
 engine.byContainer[containerID] = st
 engine.mu.Unlock()
}

func TestStaleCapsRecreatedOnStart(t *testing.T) {
 svc, engine := newTestService(t)
 ctx := context.Background()
 rec, err := svc.Create(ctx, validSpec())
 if err != nil {
  t.Fatal(err)
 }
 staleCaps(t, engine, rec.ContainerID)
 creates := len(engine.created)
 out, err := svc.Action(ctx, rec.InstanceID, "start", 30)
 if err != nil {
  t.Fatal(err)
 }
 if len(engine.created) != creates+1 {
  t.Fatalf("策略过期的容器 start 前必须重建: created=%d", len(engine.created))
 }
 m, ok := out.(Record)
 if !ok {
  t.Fatalf("start 应答类型异常: %+v", out)
 }
 if m.ContainerID == rec.ContainerID {
  t.Fatalf("重建后记录必须指向新容器: %s", m.ContainerID)
 }
 if m.State != "starting" && m.State != "running" {
  t.Fatalf("重建后应正常进入启动流程: %+v", m)
 }
 // 重建后的容器策略已是当前版本：再次 start 不得再重建。
 if _, err := svc.Action(ctx, rec.InstanceID, "start", 30); err != nil {
  t.Fatal(err)
 }
 if len(engine.created) != creates+1 {
  t.Fatalf("策略一致时不得重复重建: created=%d", len(engine.created))
 }
}

func TestReconcileContainersRebuildsStaleAndKeepsFresh(t *testing.T) {
	svc, engine := newTestService(t)
	ctx := context.Background()
	stale, err := svc.Create(ctx, validSpec())
	if err != nil {
		t.Fatal(err)
	}
	staleCaps(t, engine, stale.ContainerID)
	freshSpec := validSpec()
	freshSpec.InstanceID = "inst-fresh"
	if _, err := svc.Create(ctx, freshSpec); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.ReconcileContainers(ctx, log)
	if got := len(engine.created); got != 3 {
		t.Fatalf("只有策略过期的容器应被重建: created=%d", got)
	}
	insp, err := svc.Inspect(ctx, stale.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	st := engine.byContainer[insp.ContainerID]
	engine.mu.Unlock()
	if insp.State != "created" || !dockerx.CapsUpToDate(st.CapAdd, st.CapDrop) {
		t.Fatalf("重建后停止中的实例应保持 created 且策略对齐: %+v caps=%v/%v", insp, st.CapAdd, st.CapDrop)
	}
	// 已对齐后重跑对齐必须零重建（节点每次重启都会调用）。
	svc.ReconcileContainers(ctx, log)
	if got := len(engine.created); got != 3 {
		t.Fatalf("对齐后的重跑不得再重建: created=%d", got)
	}
}

func TestReconcileRestartsRunningStaleContainer(t *testing.T) {
	svc, engine := newTestService(t)
	ctx := context.Background()
	rec, err := svc.Create(ctx, validSpec())
	if err != nil {
		t.Fatal(err)
	}
	staleCaps(t, engine, rec.ContainerID)
	engine.mu.Lock()
	st := engine.byContainer[rec.ContainerID]
	st.State = "running"; st.Running = true
	engine.byContainer[rec.ContainerID] = st
	engine.mu.Unlock()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.ReconcileContainers(ctx, log)
	insp, err := svc.Inspect(ctx, rec.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	st = engine.byContainer[insp.ContainerID]
	engine.mu.Unlock()
	if !st.Running {
		t.Fatalf("运行中的实例重建后必须恢复运行: %+v", st)
	}
	if insp.ContainerID == rec.ContainerID {
		t.Fatal("恢复运行的必须是重建后的新容器")
	}
}

func TestCapsUpToDate(t *testing.T) {
	if !dockerx.CapsUpToDate([]string{"DAC_OVERRIDE"}, []string{"ALL"}) {
		t.Fatal("当前策略必须判定为最新")
	}
	if dockerx.CapsUpToDate(nil, []string{"ALL"}) {
		t.Fatal("缺 DAC_OVERRIDE 的旧容器必须判定为过期")
	}
	if dockerx.CapsUpToDate([]string{"DAC_OVERRIDE"}, nil) {
		t.Fatal("缺 CapDrop 的容器必须判定为过期")
	}
}

func TestDeleteRunningRequiresStop(t *testing.T) {
 svc, engine := newTestService(t)
 ctx := context.Background()
 rec, err := svc.Create(ctx, validSpec())
 if err != nil {
  t.Fatal(err)
 }
 // 直接把状态改成 running 模拟已启动
 engine.mu.Lock()
 st := engine.byContainer[rec.ContainerID]
 st.State = "running"; st.Running = true
 engine.byContainer[rec.ContainerID] = st
 engine.mu.Unlock()
 if _, err := svc.Action(ctx, rec.InstanceID, "delete", 30); err == nil || !strings.Contains(err.Error(), "先停止") {
  t.Fatalf("运行中删除必须被拒: %v", err)
 }
}

func TestOutputCursor(t *testing.T) {
 svc, _ := newTestService(t)
 ctx := context.Background()
 _, err := svc.Create(ctx, validSpec())
 if err != nil {
  t.Fatal(err)
 }
 out, err := svc.Output(ctx, validSpec().InstanceID, "", 10)
 if err != nil {
  t.Fatal(err)
 }
 m := out.(map[string]any)
 if !strings.Contains(m["text"].(string), "Done") {
  t.Fatalf("输出解码异常: %v", m["text"])
 }
 if m["nextCursor"] == "" {
  t.Fatal("必须返回下一次游标")
 }
}

// seedInstanceData 在实例目录写入可识别的数据文件，用于验证迁移不丢数据。
func seedInstanceData(t *testing.T, svc *Service, id string) {
 t.Helper()
 dir := filepath.Join(svc.root, "instances", id, "world")
 if err := os.MkdirAll(dir, 0o755); err != nil {
  t.Fatal(err)
 }
 if err := os.WriteFile(filepath.Join(dir, "level.dat"), []byte("world-data"), 0o644); err != nil {
  t.Fatal(err)
 }
}

func TestDeleteMovesDataToTrash(t *testing.T) {
 svc, _ := newTestService(t)
 ctx := context.Background()
 spec := validSpec()
 if _, err := svc.Create(ctx, spec); err != nil {
  t.Fatal(err)
 }
 seedInstanceData(t, svc, spec.InstanceID)
 out, err := svc.Action(ctx, spec.InstanceID, "delete", 30)
 if err != nil {
  t.Fatal(err)
 }
 m, ok := out.(map[string]any)
 if !ok || m["deleted"] != true || m["trashed"] != true {
  t.Fatalf("删除应答必须含 trashed:true: %+v", out)
 }
 if _, err := os.Stat(filepath.Join(svc.root, "instances", spec.InstanceID)); !os.IsNotExist(err) {
  t.Fatalf("删除后 instances/ 下不得残留数据目录: %v", err)
 }
 entries, err := os.ReadDir(filepath.Join(svc.root, "trash"))
 if err != nil || len(entries) != 1 {
  t.Fatalf("回收站必须恰有一个目录: %v %v", entries, err)
 }
 if entries[0].Name() != spec.InstanceID {
  t.Fatalf("回收目录主名必须为实例 id: %s", entries[0].Name())
 }
 if _, err := os.Stat(filepath.Join(svc.root, "trash", entries[0].Name(), "world", "level.dat")); err != nil {
  t.Fatalf("回收目录必须完整保留实例数据: %v", err)
 }
	// 记录已被删除：同 id 重试 delete 必须得到「不存在」类错误（面板映射 instance.notFound）。
	if _, err := svc.Action(ctx, spec.InstanceID, "delete", 30); err == nil || !os.IsNotExist(err) {
		t.Fatalf("记录删除后的重试必须返回不存在类错误: %v", err)
	}
}

func TestTrashListAndTrashDelete(t *testing.T) {
 svc, _ := newTestService(t)
 ctx := context.Background()
 spec := validSpec()
 if _, err := svc.Create(ctx, spec); err != nil {
  t.Fatal(err)
 }
 seedInstanceData(t, svc, spec.InstanceID)
 if _, err := svc.Action(ctx, spec.InstanceID, "delete", 30); err != nil {
  t.Fatal(err)
 }
 res, err := svc.TrashList()
 if err != nil {
  t.Fatal(err)
 }
 items := res["items"].([]TrashItem)
 if len(items) != 1 {
  t.Fatalf("回收站列表必须有一条: %+v", items)
 }
 if items[0].InstanceID != spec.InstanceID || items[0].Name != spec.Name || items[0].DeletedAt <= 0 {
  t.Fatalf("回收条目元数据不完整: %+v", items[0])
 }
 if res["retentionDays"].(int) != 14 {
  t.Fatalf("默认保留期必须为 14 天: %v", res["retentionDays"])
 }
 if err := svc.TrashDelete(items[0].TrashID); err != nil {
  t.Fatal(err)
 }
 if again, _ := svc.TrashList(); len(again["items"].([]TrashItem)) != 0 {
  t.Fatal("TrashDelete 后列表必须为空")
 }
 if err := svc.TrashDelete("../../instances"); err == nil {
  t.Fatal("非法 trashId 必须被拒绝")
 }
}

func TestRestoreFromTrashRecreatesInstance(t *testing.T) {
 svc, _ := newTestService(t)
 ctx := context.Background()
 spec := validSpec()
 if _, err := svc.Create(ctx, spec); err != nil {
  t.Fatal(err)
 }
 seedInstanceData(t, svc, spec.InstanceID)
 if _, err := svc.Action(ctx, spec.InstanceID, "delete", 30); err != nil {
  t.Fatal(err)
 }
 res, _ := svc.TrashList()
 trashID := res["items"].([]TrashItem)[0].TrashID
 if err := svc.RestoreFromTrash(trashID, spec.InstanceID); err != nil {
  t.Fatal(err)
 }
 if _, err := os.Stat(filepath.Join(svc.root, "instances", spec.InstanceID, "world", "level.dat")); err != nil {
  t.Fatalf("找回后数据必须回到实例目录: %v", err)
 }
 if _, err := os.Stat(filepath.Join(svc.root, "instances", spec.InstanceID, trashMetaFile)); err == nil {
  t.Fatal("找回后不得残留回收站元数据文件")
 }
 // 找回后可以按原规格重建容器（目录已存在时 Create 不得清空数据）。
 if _, err := svc.Create(ctx, spec); err != nil {
  t.Fatalf("找回后重建实例失败: %v", err)
 }
 b, err := os.ReadFile(filepath.Join(svc.root, "instances", spec.InstanceID, "world", "level.dat"))
 if err != nil || string(b) != "world-data" {
  t.Fatalf("重建后原有数据丢失: %v %q", err, string(b))
 }
}

func TestRestoreFromTrashRejectsConflict(t *testing.T) {
 svc, _ := newTestService(t)
 spec := validSpec()
 if err := svc.RestoreFromTrash("inst-001-123", spec.InstanceID); err == nil {
  t.Fatal("回收条目不存在必须报错")
 }
 if err := svc.RestoreFromTrash("../evil", spec.InstanceID); err == nil {
  t.Fatal("非法 trashId 必须被拒绝")
 }
}

func TestPurgeRemovesDataAndTrashEvenWithoutRecord(t *testing.T) {
 svc, _ := newTestService(t)
 ctx := context.Background()
 spec := validSpec()
 if _, err := svc.Create(ctx, spec); err != nil {
  t.Fatal(err)
 }
 seedInstanceData(t, svc, spec.InstanceID)
 // 先正常删除（数据进回收站，记录删除），再对同 id Purge：
 // 记录已不存在（os.IsNotExist）+ instances/ 目录已迁移，两个环节都必须容忍。
 if _, err := svc.Action(ctx, spec.InstanceID, "delete", 30); err != nil {
  t.Fatal(err)
 }
 if err := svc.Purge(spec.InstanceID); err != nil {
  t.Fatalf("删除后的重试式 Purge 必须成功: %v", err)
 }
 entries, _ := os.ReadDir(filepath.Join(svc.root, "trash"))
 for _, e := range entries {
  if strings.HasPrefix(e.Name(), spec.InstanceID+"-") {
   t.Fatalf("Purge 后回收站不得残留该实例目录: %s", e.Name())
  }
 }
 // 记录存在但数据目录已被外部清空的 Purge 同样幂等成功。
 if _, err := svc.Create(ctx, spec); err != nil {
  t.Fatal(err)
 }
 if err := os.RemoveAll(filepath.Join(svc.root, "instances", spec.InstanceID)); err != nil {
  t.Fatal(err)
 }
 if err := svc.Purge(spec.InstanceID); err != nil {
  t.Fatalf("数据目录缺失时 Purge 必须幂等成功: %v", err)
 }
}

func TestSweepExpiredTrashRespectsRetention(t *testing.T) {
 svc, _ := newTestService(t)
 ctx := context.Background()
 spec := validSpec()
 if _, err := svc.Create(ctx, spec); err != nil {
  t.Fatal(err)
 }
 if _, err := svc.Action(ctx, spec.InstanceID, "delete", 30); err != nil {
  t.Fatal(err)
 }
 res, _ := svc.TrashList()
 trashID := res["items"].([]TrashItem)[0].TrashID
 stale := time.Now().Add(-48 * time.Hour).UnixMilli()

 // retention=0：永久保留，不清扫。
 svc.SetTrashRetention(0)
 if n := svc.SweepExpiredTrash(time.Now()); n != 0 {
  t.Fatalf("retention=0 不得清扫: %d", n)
 }
 // 把 meta 的 deletedAt 改成 48 小时前；retention=1 天：必须清除。
 svc.SetTrashRetention(1)
 metaPath := filepath.Join(svc.root, "trash", trashID, trashMetaFile)
 b, err := json.Marshal(trashMeta{InstanceID: spec.InstanceID, Name: spec.Name, DeletedAt: stale})
 if err != nil {
  t.Fatal(err)
 }
 if err := os.WriteFile(metaPath, b, 0o600); err != nil {
  t.Fatal(err)
 }
 if n := svc.SweepExpiredTrash(time.Now()); n != 1 {
  t.Fatalf("过期回收目录必须被清扫: %d", n)
 }
 if _, err := os.Stat(filepath.Join(svc.root, "trash", trashID)); !os.IsNotExist(err) {
  t.Fatal("清扫后目录必须消失")
 }
}
