package instances

import (
 "context"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "log/slog"
 "os"
 "path/filepath"
 "regexp"
 "sort"
 "strconv"
 "strings"
 "sync"
 "time"

 "github.com/yudream/mcpanel-node/internal/dockerx"
 "github.com/yudream/mcpanel-node/internal/fileutil"
)

type Engine interface{
 Create(context.Context,string,dockerx.ContainerSpec)(string,error)
 Inspect(context.Context,string)(dockerx.ContainerState,error)
 Action(context.Context,string,string,int)error
 UpdateRestartPolicy(context.Context,string,string)error
 Remove(context.Context,string)error
 Logs(context.Context,string,string,int)(string,bool,error)
 AttachWriter(context.Context,string)(io.WriteCloser,error)
 Pull(context.Context,string)error
 ImageExists(context.Context,string)bool
}

type Service struct{
 root string
 hostRoot string
 nodeID string
 engine Engine
 retentionDays int
 locks [64]sync.Mutex
 storeMu sync.Mutex
 stdinMu sync.Mutex
 stdin map[string]io.WriteCloser
 startMu sync.Mutex
 starting map[string]*startWatch
 onState func(instanceID, state string)
 onStateGen int64
}

// startWatch 标识一次启动检测窗口：goroutine 结束时按代数摘除，防止误删
// 后来重进的新窗口（Go 函数不可比较，用代数代替指针同一性）。
type startWatch struct{ cancel context.CancelFunc; gen int64 }

// startDetectTimeout 启动成功检测窗口：超时未命中标记则视为已启动（容器仍在
// 运行，不能永远停在 starting）。大整合包冷启动可达数分钟，默认 5 分钟。
const startDetectTimeout = 5 * time.Minute

// startDetectInterval 启动日志轮询间隔：docker logs 尾部扫描足够轻。
const startDetectInterval = 2 * time.Second

// SetOnStateChange 注册状态回调（wsserver 用于把 starting→running 迁移推给面板）。
func(s *Service) SetOnStateChange(fn func(instanceID, state string)){ s.onState=fn }

// IsStarting 实例是否处于启动检测窗口（stats 快照与 Inspect 口径覆写用）。
func(s *Service) IsStarting(id string) bool {
 if id==""{return false}
 s.startMu.Lock();defer s.startMu.Unlock()
 _,ok:=s.starting[id]
 return ok
}

// BeginStartWatch 进入启动检测窗口：返回是否真的进入（未配置标记 = false，
// 调用方按 running 处理）。窗口内轮询容器日志尾，命中标记或超时即退出并
// 回推 running；容器退出（die 事件）由 CancelStartWatch 收口，事件只报 exited。
func(s *Service) BeginStartWatch(id string) bool {
 r,err:=s.load(id);if err!=nil{return false}
 marker:=r.StartDetect
 if marker==""{marker=r.DefaultStartDetect()}
 if marker==""{return false}
 if r.ContainerID==""{return false}
 s.startMu.Lock()
 if old,ok:=s.starting[id];ok{old.cancel()}
 s.onStateGen++
 watch:=&startWatch{cancel:nil,gen:s.onStateGen}
 ctx,cancel:=context.WithCancel(context.Background())
 watch.cancel=cancel
 if s.starting==nil{s.starting=map[string]*startWatch{}}
 s.starting[id]=watch
 gen:=watch.gen
 onState:=s.onState
 s.startMu.Unlock()
 go func(){
  defer func(){
   s.startMu.Lock();if cur,ok:=s.starting[id];ok&&cur.gen==gen{delete(s.starting,id)};s.startMu.Unlock()
   cancel()
  }()
  deadline:=time.Now().Add(startDetectTimeout)
  for time.Now().Before(deadline){
   select{
   case <-ctx.Done():return
   case <-time.After(startDetectInterval):
   }
   text,_,err:=s.engine.Logs(ctx,r.ContainerID,"",400)
   if err!=nil{
    if dockerx.IsNotFound(err){return} // 容器已消失：die 事件负责报 exited
    continue
   }
   if strings.Contains(text,marker){
    if onState!=nil{onState(id,"running")}
    return
   }
  }
  // 超时：容器仍在运行，回推 running 兜底（面板不会永远显示启动中）。
  if onState!=nil{onState(id,"running")}
 }()
 return true
}

// CancelStartWatch 结束启动检测窗口（容器 die/stop/destroy 时调用）：
// 只收口窗口，不回推状态——退出状态由 docker 事件承载。
func(s *Service) CancelStartWatch(id string) {
 s.startMu.Lock();watch,ok:=s.starting[id];if ok{delete(s.starting,id)};s.startMu.Unlock()
 if ok{watch.cancel()}
}

type outcome struct{ Method string `json:"method"`; Digest string `json:"digest"`; Result json.RawMessage `json:"result,omitempty"`; State string `json:"state"`; At int64 `json:"at"` }

// trashMeta 是回收目录内的元数据文件：回收站列表靠它还原名/删除时间，
// 写入失败时列表按目录名回退解析（trashId = instanceId-删除时刻毫秒）。
type trashMeta struct{ InstanceID string `json:"instanceId"`; Name string `json:"name"`; DeletedAt int64 `json:"deletedAt"` }
type TrashItem struct{ TrashID string `json:"trashId"`; InstanceID string `json:"instanceId"`; Name string `json:"name"`; DeletedAt int64 `json:"deletedAt"` }

const trashMetaFile = ".mcpanel-trash.json"

var validTrashID=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,79}$`)

func New(root,hostRoot,nodeID string,engine Engine)(*Service,error){
 abs,err:=filepath.Abs(root);if err!=nil{return nil,err}
 if hostRoot==""{hostRoot=abs}
 s:=&Service{root:abs,hostRoot:hostRoot,nodeID:nodeID,engine:engine,retentionDays:14,stdin:map[string]io.WriteCloser{}}
 for _,d:=range []string{"records","operations","backups","uploads","trash"}{if err=os.MkdirAll(filepath.Join(abs,d),0700);err!=nil{return nil,err}}
 // instances 必须放开写权限：实例容器内进程的 uid 由镜像决定（如 openjdk25
 // 的 10001），Windows/macOS Docker Desktop 的 bind mount 会把这里的 mode
 // 映射进实例容器，0700/0755 会让非属主 uid 的服务端进程 EACCES。
 if err=os.MkdirAll(filepath.Join(abs,"instances"),0777);err!=nil{return nil,err}
 return s,nil
}
func(s *Service) lock(id string)*sync.Mutex{h:=sha256.Sum256([]byte(id));return &s.locks[int(h[0])%len(s.locks)]}
func(s *Service) Root(id string)(string,error){if !validID.MatchString(id){return "",errors.New("实例ID无效")};return filepath.Join(s.root,"instances",id),nil}
func(s *Service) recordPath(id string)string{return filepath.Join(s.root,"records",id+".json")}
func(s *Service) load(id string)(Record,error){
 if !validID.MatchString(id){return Record{},errors.New("实例ID无效")}
 data,err:=os.ReadFile(s.recordPath(id));if err!=nil{return Record{},err};var r Record;err=json.Unmarshal(data,&r);return r,err
}
func atomicJSON(path string,value any)error{b,err:=json.Marshal(value);if err!=nil{return err};return atomicFile(path,b,0600)}
func atomicFile(path string,b []byte,mode os.FileMode)error{
 f,err:=os.CreateTemp(filepath.Dir(path),".panel-write-*");if err!=nil{return err};name:=f.Name();defer os.Remove(name)
 if err=f.Chmod(mode);err==nil{_,err=f.Write(b)};if err==nil{err=f.Sync()};closeErr:=f.Close();if err!=nil{return err};if closeErr!=nil{return closeErr};return os.Rename(name,path)
}
func(s *Service) save(r Record)error{r.UpdatedAt=time.Now().UnixMilli();return atomicJSON(s.recordPath(r.InstanceID),r)}

// An uncertain command is never replayed automatically after a node crash.
func(s *Service) Mutate(ctx context.Context,method,key,id string,payload json.RawMessage,fn func()(any,error))(any,error){
 if len(key)<16||len(key)>128{return nil,errors.New("变更操作需要16至128位幂等键")}
 l:=s.lock(id);l.Lock();defer l.Unlock()
 hash:=sha256.Sum256([]byte(key));path:=filepath.Join(s.root,"operations",hex.EncodeToString(hash[:])+".json")
 digest:=sha256.Sum256(payload);d:=hex.EncodeToString(digest[:])
 s.storeMu.Lock()
 b,readErr:=os.ReadFile(path)
 if readErr==nil{
  var old outcome;err:=json.Unmarshal(b,&old);s.storeMu.Unlock();if err!=nil{return nil,err}
  if old.Method!=method||old.Digest!=d{return nil,errors.New("operation.conflict：同一幂等键的操作内容不同")}
  if old.State!="done"{return nil,errors.New("operation.uncertain：操作处理中或中断，请先核对实例状态")}
  var result any;err=json.Unmarshal(old.Result,&result);return result,err
 }
 if !os.IsNotExist(readErr){s.storeMu.Unlock();return nil,readErr}
 entries,err:=os.ReadDir(filepath.Dir(path));if err!=nil{s.storeMu.Unlock();return nil,err}
 if len(entries)>=10000{
  for _,e:=range entries{info,e2:=e.Info();if e2==nil&&time.Since(info.ModTime())>24*time.Hour{_ = os.Remove(filepath.Join(filepath.Dir(path),e.Name()))}}
  entries,_=os.ReadDir(filepath.Dir(path));if len(entries)>=10000{s.storeMu.Unlock();return nil,errors.New("操作记录已满，请稍后重试")}
 }
 entry:=outcome{Method:method,Digest:d,State:"pending",At:time.Now().UnixMilli()}
 err=atomicJSON(path,entry);s.storeMu.Unlock();if err!=nil{return nil,err}
 if err=ctx.Err();err!=nil{_ = os.Remove(path);return nil,err}
 result,err:=fn()
 if err!=nil{
  // 业务失败是确定性结果：清除 pending 记录，让同一幂等键可以重试。
  // 仅进程在 fn 执行中途崩溃时才保留 pending（此时状态真不确定，重放须人工核对）。
  _ = os.Remove(path)
  return nil,err
 }
 raw,err:=json.Marshal(result);if err!=nil{return nil,err};entry.State="done";entry.Result=raw
 if err=atomicJSON(path,entry);err!=nil{return nil,err}
 // 与幂等重放路径同构：一律经 JSON 往返，调用方拿到的类型稳定。
 var normalized any
 if err=json.Unmarshal(raw,&normalized);err!=nil{return nil,err}
 return normalized,nil
}

func(s *Service) Create(ctx context.Context,spec Spec)(Record,error){
 if err:=spec.Validate();err!=nil{return Record{},err}
 if s.engine==nil{return Record{},errors.New("Docker 不可用")}
 if r,err:=s.load(spec.InstanceID);err==nil{return r,errors.New("实例已存在") }else if !os.IsNotExist(err){return Record{},err}
 root,_:=s.Root(spec.InstanceID);if err:=os.MkdirAll(root,0777);err!=nil{return Record{},err}
 // 实例数据目录对实例容器内进程（uid 由镜像决定）必须可写：Windows/macOS
 // Docker Desktop bind mount 会把此 mode 映射给挂载方，0775/0700 均会 EACCES。
 _=os.Chmod(root,0777)
 // 镜像预拉取：Docker create 不会自动拉镜像，缺失时先内联拉取（面板对
 // instance.create 使用长超时；超大镜像应走 image.pull 任务 + 重建流程）。
 if !s.engine.ImageExists(ctx,spec.Image){
  if err:=s.engine.Pull(ctx,spec.Image);err!=nil{
   _=os.RemoveAll(root)
   return Record{},fmt.Errorf("image.notFound：镜像 %s 拉取失败（%s）",spec.Image,err)
  }
 }
 r:=Record{Spec:spec,State:"installing",CreatedAt:time.Now().UnixMilli()}
 if err:=s.save(r);err!=nil{return Record{},err}
 id,err:=s.engine.Create(ctx,s.containerName(spec.InstanceID),s.containerSpec(spec))
 var apiErr *dockerx.APIError
 if errors.As(err,&apiErr)&&apiErr.Status==409{
  // 上一次非正常退出可能遗留同名容器（可能仍在运行）：强制清理后重试一次。
  _=s.engine.Action(ctx,s.containerName(spec.InstanceID),"kill",5)
  _=s.engine.Remove(ctx,s.containerName(spec.InstanceID))
  id,err=s.engine.Create(ctx,s.containerName(spec.InstanceID),s.containerSpec(spec))
 }
 if err!=nil{
  // 失败清理：不留孤儿记录/目录（端口由面板回收；幂等键已作废由面板新键重试）。
  _=os.Remove(s.recordPath(spec.InstanceID))
  _=os.RemoveAll(root)
  if errors.As(err,&apiErr)&&apiErr.Status==404{
   return Record{},fmt.Errorf("image.notFound：镜像 %s 不存在且自动拉取失败（%s）",spec.Image,err)
  }
  return Record{},err
 }
 r.ContainerID=id;r.State="created";if err=s.save(r);err!=nil{return r,err};return r,nil
}
func(s *Service) containerName(id string)string{h:=sha256.Sum256([]byte(s.nodeID));return "mcpanel-"+hex.EncodeToString(h[:4])+"-"+id}
func(s *Service) containerSpec(v Spec)dockerx.ContainerSpec{return dockerx.ContainerSpec{InstanceID:v.InstanceID,NodeID:s.nodeID,Image:v.Image,Command:v.Command,Env:v.Env,MemoryMb:v.MemoryMb,CPUMillis:v.CPUMillis,DataPath:filepath.Join(s.hostRoot,"instances",v.InstanceID),Ports:v.Ports}}
func(s *Service) owned(ctx context.Context,r Record)(dockerx.ContainerState,error){
 if s.engine==nil{return dockerx.ContainerState{},errors.New("Docker 不可用")}
 id:=r.ContainerID;if id==""{id=s.containerName(r.InstanceID)}
 state,err:=s.engine.Inspect(ctx,id);if err!=nil{return state,err}
 if state.Labels["mcpanel.instanceId"]!=r.InstanceID||state.Labels["mcpanel.nodeId"]!=s.nodeID||state.Labels["mcpanel.managed"]!="true"{return state,errors.New("容器归属校验失败")}
 return state,nil
}

// ensureContainerCurrent 校验存量容器的 capability 策略与当前版本一致，不一致
// 则强制重建。Docker HostConfig 只在 create 时读取，旧版节点创建的容器重启
// 不会应用新策略（如缺 DAC_OVERRIDE 导致实例内进程 EACCES），必须重建才能
// 生效；数据在 bind mount，容器无状态，重建零成本。返回重建后（或原样）的
// 容器状态，调用方据此继续 start。
func(s *Service) ensureContainerCurrent(ctx context.Context,r Record,state dockerx.ContainerState)(dockerx.ContainerState,error){
 if dockerx.CapsUpToDate(state.CapAdd,state.CapDrop){return state,nil}
 s.closeStdin(r.InstanceID)
 if state.Running{_=s.engine.Action(ctx,state.ID,"kill",5)}
 if err:=s.engine.Remove(ctx,state.ID);err!=nil&&!dockerx.IsNotFound(err){return state,err}
 id,err:=s.engine.Create(ctx,s.containerName(r.InstanceID),s.containerSpec(r.Spec))
 var apiErr *dockerx.APIError
 if errors.As(err,&apiErr)&&apiErr.Status==409{
  // 容器名释放有延迟：与 Create 主流程同构地清理后重试一次。
  _=s.engine.Action(ctx,s.containerName(r.InstanceID),"kill",5)
  _=s.engine.Remove(ctx,s.containerName(r.InstanceID))
  id,err=s.engine.Create(ctx,s.containerName(r.InstanceID),s.containerSpec(r.Spec))
 }
 if err!=nil{return state,err}
 r.ContainerID=id
 if err:=s.save(r);err!=nil{return state,err}
 return s.engine.Inspect(ctx,id)
}

// ReconcileContainers 节点启动时对齐存量实例容器：capability 策略与当前版本
// 不一致的容器（旧版节点创建）自动重建——停止中的保持停止，运行中的重建后
// 拉起。容器缺失/归属异常的记录不越权处理，交给既有事件链路呈现。
func(s *Service) ReconcileContainers(ctx context.Context,log *slog.Logger){
 if s.engine==nil{return}
 if log==nil{log=slog.Default()}
 entries,err:=os.ReadDir(filepath.Join(s.root,"records"))
 if err!=nil{return}
 recreated,failed:=0,0
 for _,e:=range entries{
  if ctx.Err()!=nil{return}
  name:=e.Name()
  if !strings.HasSuffix(name,".json"){continue}
  id:=strings.TrimSuffix(name,".json")
  l:=s.lock(id);l.Lock()
  r,err:=s.load(id)
  if err!=nil{l.Unlock();continue}
  state,err:=s.owned(ctx,r)
  if err!=nil{l.Unlock();continue}
  if dockerx.CapsUpToDate(state.CapAdd,state.CapDrop){l.Unlock();continue}
  wasRunning:=state.Running
  fresh,err:=s.ensureContainerCurrent(ctx,r,state)
  l.Unlock()
  if err!=nil{
   failed++
   log.Warn("实例容器策略过期重建失败","instance",id,"err",err)
   continue
  }
  recreated++
  if wasRunning{
   // 运行中的实例重建后原样拉起，节点升级即完成修复，无需逐台人工干预。
   if err:=s.engine.Action(ctx,fresh.ID,"start",30);err!=nil{
    log.Warn("实例容器策略过期重建后启动失败","instance",id,"err",err)
   }else{
    log.Info("实例容器已按当前策略重建并拉起","instance",id)
   }
  }else{
   log.Info("实例容器已按当前策略重建（保持停止）","instance",id)
  }
 }
 if recreated>0||failed>0{
  log.Info("存量实例容器策略对齐完成","recreated",recreated,"failed",failed)
 }
}
func(s *Service) Inspect(ctx context.Context,id string)(Record,error){
 r,err:=s.load(id);if err!=nil{return r,err};state,err:=s.owned(ctx,r)
 if err!=nil{r.State="unknown";if dockerx.IsNotFound(err){r.State="missing"};return r,nil}
 r.State=state.State;r.ExitCode=state.ExitCode;r.ContainerID=state.ID
 // 启动检测窗口内 docker 已 running，但对外口径保持 starting（与快照一致）。
 if r.State=="running"&&s.IsStarting(id){r.State="starting"}
 return r,nil
}
func(s *Service) List(ctx context.Context,page,size int)(map[string]any,error){
 if page<1{page=1};if size<1{size=10};if size>100{size=100}
 files,err:=os.ReadDir(filepath.Join(s.root,"records"));if err!=nil{return nil,err}
 ids:=[]string{};for _,f:=range files{if strings.HasSuffix(f.Name(),".json"){ids=append(ids,strings.TrimSuffix(f.Name(),".json"))}}
 sort.Strings(ids);from:=(page-1)*size;if from>len(ids){from=len(ids)};end:=from+size;if end>len(ids){end=len(ids)}
 records:=[]Record{};for _,id:=range ids[from:end]{r,err:=s.Inspect(ctx,id);if err!=nil{return nil,err};records=append(records,r)}
 return map[string]any{"records":records,"total":len(ids),"page":page,"size":size},nil
}
func(s *Service) Update(ctx context.Context,spec Spec)(Record,error){
 if err:=spec.Validate();err!=nil{return Record{},err};r,err:=s.load(spec.InstanceID);if err!=nil{return r,err}
 state,err:=s.owned(ctx,r);if err!=nil{return r,err};if state.Running{return r,errors.New("请先停止实例再修改规格")}
 if err=s.engine.Remove(ctx,state.ID);err!=nil{return r,err}
 r.Spec=spec;r.ContainerID="";r.State="installing";if err=s.save(r);err!=nil{return r,err}
 id,err:=s.engine.Create(ctx,s.containerName(spec.InstanceID),s.containerSpec(spec));if err!=nil{return r,err}
 r.ContainerID=id;r.State="created";return r,s.save(r)
}
func(s *Service) Action(ctx context.Context,id,action string,timeout int)(any,error){
 r,err:=s.load(id);if err!=nil{return nil,err};state,err:=s.owned(ctx,r)
 if action=="delete"&&dockerx.IsNotFound(err){
  // 容器已不存在（外部删除/上次删除半途）：数据目录仍要进回收站，避免裸残留。
  trashed,merr:=s.moveToTrash(id,r.Name)
  if merr!=nil{return nil,merr}
  return map[string]any{"deleted":true,"dataRetained":!trashed,"trashed":trashed},os.Remove(s.recordPath(id))
 }
 if err!=nil{return nil,err}
 switch action{
 case "start","restart":
  // 存量容器 capability 策略过期时先重建（旧版节点创建的容器 HostConfig 已
  // 固化）。start 对 running 容器是 no-op（下方提前返回），不动运行中的服务；
  // restart 显式要求重启，顺带把旧策略容器重建掉。
  if !state.Running||action=="restart"{
   if state,err=s.ensureContainerCurrent(ctx,r,state);err!=nil{return nil,err}
  }
  if err=s.rewrite(r);err!=nil{return nil,err}
  // 启动前自动修复数据目录权限：节点侧 root 写入（装核心/整合包/文件管理）
  // 与容器内非 root uid 之间天然存在属主错位，不修复则容器内服务端对
  // root 建的目录/文件 EACCES 启动即崩（如模组写 ./config 失败）。
  if root,perr:=s.Root(id);perr==nil{
   _ = fileutil.EnsureWorldWritable(root, 90*time.Second)
  }
 case "delete":
  if state.Running{return nil,errors.New("请先停止实例")};if err=s.engine.Remove(ctx,state.ID);err!=nil{return nil,err}
  s.closeStdin(id)
  // 先移入回收站再删记录：rename 失败时记录仍在，面板重试即可；成功后数据
  // 保留在 data/trash/<id>-<毫秒>（保留期内可找回），不再是 instances/ 裸目录。
  trashed,merr:=s.moveToTrash(id,r.Name)
  if merr!=nil{return nil,merr}
  if err=os.Remove(s.recordPath(id));err!=nil{return nil,err}
  return map[string]any{"deleted":true,"dataRetained":!trashed,"trashed":trashed},nil
 case "stop","kill":
  s.closeStdin(id)
  if state.ID!=""{ _=s.engine.UpdateRestartPolicy(ctx,state.ID,"no") }
 default:return nil,errors.New("不支持的实例操作")
 }
 if timeout<1{timeout=30};if timeout>120{timeout=120}
 if action=="start"&&state.Running{return s.Inspect(ctx,id)}
 if action=="stop"&&!state.Running{return s.Inspect(ctx,id)}
 if action=="kill"&&!state.Running{
  r.State="exited";_ = s.save(r)
  return s.Inspect(ctx,id)
 }
 if err=s.engine.Action(ctx,state.ID,action,timeout);err!=nil{
  if action=="kill"&&(dockerx.IsNotFound(err)||strings.Contains(err.Error(),"not running")){
   if state.ID!=""{_ = s.engine.UpdateRestartPolicy(ctx,state.ID,"no")}
   r.State="exited";_ = s.save(r)
   return s.Inspect(ctx,id)
  }
  return nil,err
 }
 if (action=="kill"||action=="stop")&&state.ID!=""{
  _ = s.engine.UpdateRestartPolicy(ctx,state.ID,"no")
 }
 if action=="start"||action=="restart"{
  // 启动成功检测：动作返回即进入 starting 窗口（docker start 事件会幂等重进）。
  // 面板拿到 starting 立即可展示「启动中」，无需等事件链路。
  if state.ID!=""&&r.ContainerID!=state.ID{r.ContainerID=state.ID;_ = s.save(r)}
  if s.BeginStartWatch(id){
   res,_:=s.Inspect(ctx,id);res.State="starting";return res,nil
  }
 }
 return s.Inspect(ctx,id)
}
// writer 持有（或新建）实例的长连 stdin；attach 连接保持到实例停止。
func(s *Service) writer(ctx context.Context,id string)(io.WriteCloser,error){
 s.stdinMu.Lock();defer s.stdinMu.Unlock()
 if w,ok:=s.stdin[id];ok{return w,nil}
 r,err:=s.load(id);if err!=nil{return nil,err}
 state,err:=s.owned(ctx,r)
 if err!=nil{return nil,err}
 w,err:=s.engine.AttachWriter(ctx,state.ID)
 if err!=nil{return nil,err}
 s.stdin[id]=w
 return w,nil
}

func(s *Service) closeStdin(id string){
 s.stdinMu.Lock();w,ok:=s.stdin[id];delete(s.stdin,id);s.stdinMu.Unlock()
 if ok{_ = w.Close()}
}

func(s *Service) Command(ctx context.Context,id,command string)(any,error){
 if command==""||len(command)>4096||strings.ContainsAny(command,"\r\n\x00"){return nil,errors.New("控制台命令必须为单行且不超过4096字节")}
 r,err:=s.load(id);if err!=nil{return nil,err};state,err:=s.owned(ctx,r);if err!=nil{return nil,err};if !state.Running{return nil,errors.New("实例未运行")}
 w,err:=s.writer(ctx,id);if err!=nil{return nil,err}
 if _,err=w.Write([]byte(command+"\n"));err!=nil{
  // 连接可能已随容器停止失效：丢弃后重建一次。
  s.closeStdin(id)
  if w,err=s.writer(ctx,id);err!=nil{return nil,err}
  if _,err=w.Write([]byte(command+"\n"));err!=nil{return nil,err}
 }
 return map[string]bool{"sent":true},nil
}
func(s *Service) Output(ctx context.Context,id,since string,tail int)(any,error){
 r,err:=s.load(id);if err!=nil{return nil,err};state,err:=s.owned(ctx,r);if err!=nil{return nil,err}
 if tail<1{tail=200};if tail>2000{tail=2000}
 text,truncated,err:=s.engine.Logs(ctx,state.ID,since,tail);if err!=nil{return nil,err}
 // cursor 推进：取行首 docker timestamps（RFC3339Nano）的最大值，输出与
 // SinceCursor 相同的「秒.纳秒」数字格式（纳秒精度防同秒重复推送）。
 cursor:=since;for _,line:=range strings.Split(strings.TrimSuffix(text,"\n"),"\n"){
  trimmed:=strings.TrimPrefix(line,"[")
  if t,_,ok:=strings.Cut(trimmed," ");ok{if ts,err:=time.Parse(time.RFC3339Nano,t);err==nil{cursor=fmt.Sprintf("%d.%09d",ts.Unix(),ts.Nanosecond())}}
 }
 // data 为原始字节 base64（text 经 JSON 会丢失非法 UTF-8 字节），前端按所选编码解码
 return map[string]any{"text":text,"data":base64.StdEncoding.EncodeToString([]byte(text)),"nextCursor":cursor,"truncated":truncated},nil
}
func(s *Service) rewrite(r Record)error{
 switch r.Kind{case "vanilla","paper","purpur","folia","fabric","forge","neoforge","quilt","bedrock":default:return nil}
 root,err:=s.Root(r.InstanceID);if err!=nil{return err}
 path,err:=fileutil.Resolve(root,"server.properties",false);if err!=nil{return err}
 values:=map[string]string{};if b,e:=os.ReadFile(path);e==nil{for _,line:=range strings.Split(string(b),"\n"){if k,v,ok:=strings.Cut(line,"=");ok&&!strings.HasPrefix(strings.TrimSpace(k),"#"){values[strings.TrimSpace(k)]=strings.TrimSpace(v)}}}else if !os.IsNotExist(e){return e}
 for k,v:=range r.Config{values[k]=v}
 for i,p:=range r.Ports{if i==0{values["server-port"]=fmt.Sprint(p.ContainerPort);if r.Kind=="bedrock"{values["server-portv6"]=fmt.Sprint(p.ContainerPort)}}}
 keys:=make([]string,0,len(values));for k:=range values{keys=append(keys,k)};sort.Strings(keys)
 var b strings.Builder;for _,k:=range keys{fmt.Fprintf(&b,"%s=%s\n",k,values[k])}
 return fileutil.Write(root,"server.properties",base64.StdEncoding.EncodeToString([]byte(b.String())),"base64")
}

// Purge 永久删除实例数据：instances/<id> 与回收站内该实例的全部目录都清除
// （幂等）。必须先停止实例；记录可能已删（删除半失败后的重试），不视为错误。
func(s *Service) Purge(id string)error{
 s.closeStdin(id)
 root,err:=s.Root(id);if err!=nil{return err}
 if err:=os.RemoveAll(root);err!=nil{return err}
 if err:=os.Remove(s.recordPath(id));err!=nil&&!os.IsNotExist(err){return err}
 return s.purgeTrashDirs(id)
}

// purgeTrashDirs 清除回收站内属于该实例的全部目录（trashId = instanceId-毫秒）。
func(s *Service) purgeTrashDirs(id string)error{
 if !validID.MatchString(id){return errors.New("实例ID无效")}
 entries,err:=os.ReadDir(s.trashRoot());if err!=nil{
  if os.IsNotExist(err){return nil};return err
 }
 for _,e:=range entries{
  if !e.IsDir(){continue}
  // 主名 = 实例 id；兼容带毫秒后缀的旧残留（id-<毫秒>）。
  if e.Name()!=id && !strings.HasPrefix(e.Name(),id+"-"){continue}
  if err:=os.RemoveAll(filepath.Join(s.trashRoot(),e.Name()));err!=nil{return err}
 }
 return nil
}

func(s *Service) trashRoot()string{return filepath.Join(s.root,"trash")}

// SetTrashRetention 设置回收站保留天数（0=永久保留，不清扫）。
func(s *Service) SetTrashRetention(days int){if days<0{days=0};s.retentionDays=days}

// moveToTrash 把 instances/<id> 改名进 trash/（同卷 rename，原子且瞬时）。
// 回收目录主名 = 实例 id（面板按同 id 寻址）；目标已存在（外部残留）时才
// 追加毫秒后缀避免覆盖。返回 false,nil 表示数据目录本就不存在，不算错误。
// Windows 上句柄未释放会导致 rename 失败：短暂重试三次（SFTP/上传会话
// 关闭后内核释放句柄有毫秒级延迟）。
func(s *Service) moveToTrash(id,name string)(bool,error){
 root,err:=s.Root(id);if err!=nil{return false,err}
 if _,err:=os.Lstat(root);err!=nil{
  if os.IsNotExist(err){return false,nil}
  return false,err
 }
 if err:=os.MkdirAll(s.trashRoot(),0700);err!=nil{return false,err}
 target:=filepath.Join(s.trashRoot(),id)
 if _,err:=os.Lstat(target);err==nil{
  target+= "-"+strconv.FormatInt(time.Now().UnixMilli(),10)
 }
 var moveErr error
 for attempt:=0;attempt<3;attempt++{
  if moveErr=os.Rename(root,target);moveErr==nil{break}
  time.Sleep(time.Duration(attempt+1)*300*time.Millisecond)
 }
 if moveErr!=nil{return false,moveErr}
 // 元数据尽力写入：失败只影响列表展示（按目录名回退），不影响数据。
 _=atomicJSON(filepath.Join(target,trashMetaFile),trashMeta{InstanceID:id,Name:name,DeletedAt:time.Now().UnixMilli()})
 return true,nil
}

// TrashList 回收站列表（按删除时间倒序）+ 当前保留天数配置。
func(s *Service) TrashList()(map[string]any,error){
 items:=[]TrashItem{}
 entries,err:=os.ReadDir(s.trashRoot())
 if err!=nil{
  if os.IsNotExist(err){return map[string]any{"items":items,"retentionDays":s.retentionDays},nil}
  return nil,err
 }
 for _,e:=range entries{
  if !e.IsDir(){continue}
  item:=TrashItem{TrashID:e.Name(),DeletedAt:modTimeMs(e)}
  // 目录名形态 <instanceId>-<毫秒>：meta 缺失时回退解析。
  if idx:=strings.LastIndex(e.Name(),"-");idx>0{item.InstanceID=e.Name()[:idx];item.Name=e.Name()[:idx]}
  if b,err:=os.ReadFile(filepath.Join(s.trashRoot(),e.Name(),trashMetaFile));err==nil{
   var m trashMeta
   if json.Unmarshal(b,&m)==nil&&m.InstanceID!=""{
    item.InstanceID=m.InstanceID;item.Name=m.Name;item.DeletedAt=m.DeletedAt
   }
  }
  if item.Name==""{item.Name=item.InstanceID}
  items=append(items,item)
 }
 sort.Slice(items,func(i,j int)bool{return items[i].DeletedAt>items[j].DeletedAt})
 return map[string]any{"items":items,"retentionDays":s.retentionDays},nil
}

func modTimeMs(e os.DirEntry)int64{
 info,err:=e.Info();if err!=nil{return 0}
 return info.ModTime().UnixMilli()
}

// TrashDelete 手动永久清除单个回收目录（trashId 即目录名，先做字符白名单校验）。
func(s *Service) TrashDelete(trashID string)error{
 if !validTrashID.MatchString(trashID){return errors.New("回收站ID无效")}
 return os.RemoveAll(filepath.Join(s.trashRoot(),trashID))
}

// RestoreFromTrash 把回收目录改名回 instances/<targetID>（找回实例的第一步，
// 随后面板以同规格 instance.create 复用该目录）。目标已存在视为冲突。
func(s *Service) RestoreFromTrash(trashID,targetID string)error{
 if !validTrashID.MatchString(trashID){return errors.New("回收站ID无效")}
 if !validID.MatchString(targetID){return errors.New("实例ID无效")}
 src:=filepath.Join(s.trashRoot(),trashID)
 if _,err:=os.Lstat(src);err!=nil{return errors.New("回收站条目不存在或已被清除")}
 dst:=filepath.Join(s.root,"instances",targetID)
 if _,err:=os.Lstat(dst);err==nil{return errors.New("目标实例目录已存在")}
 if err:=os.Rename(src,dst);err!=nil{return err}
 // 元数据文件不能残留在实例数据目录里（会被当成服务端文件暴露给容器）。
 _=os.Remove(filepath.Join(dst,trashMetaFile))
 return nil
}

// SweepExpiredTrash 按 retentionDays 清扫过期回收目录，返回清除数量。
func(s *Service) SweepExpiredTrash(now time.Time)int{
 if s.retentionDays<=0{return 0}
 entries,err:=os.ReadDir(s.trashRoot());if err!=nil{return 0}
 deadline:=now.Add(-time.Duration(s.retentionDays)*24*time.Hour)
 removed:=0
 for _,e:=range entries{
  if !e.IsDir(){continue}
  deletedAt:=modTimeMs(e)
  if b,err:=os.ReadFile(filepath.Join(s.trashRoot(),e.Name(),trashMetaFile));err==nil{
   var m trashMeta
   if json.Unmarshal(b,&m)==nil&&m.DeletedAt>0{deletedAt=m.DeletedAt}
  }
  if deletedAt>0&&time.UnixMilli(deletedAt).Before(deadline){
   if os.RemoveAll(filepath.Join(s.trashRoot(),e.Name()))==nil{removed++}
  }
 }
 return removed
}

// SinceCursor 接受 unix 秒或 RFC3339，返回 Docker logs 可用的 since。
// 输出必须是「秒.纳秒」数字格式（Docker 自身 TimeToTimestamp 的形态）：
// 本机/常见魔改引擎对 RFC3339 字符串会按 "." 分段做 ParseInt 而直接 500；
// 但秒粒度（纯整数）会让 docker logs --since（严格大于）把「最后一秒内
// 已推送过的行」每轮轮询原样重发（控制台重复刷屏）。两者都踩过。
func SinceCursor(since string)string{
 if since==""{return ""}
 if t,err:=time.Parse(time.RFC3339Nano,since);err==nil{return fmt.Sprintf("%d.%09d",t.Unix(),t.Nanosecond())}
 if _,err:=strconv.ParseInt(since,10,64);err==nil{return since}
 return ""
}

