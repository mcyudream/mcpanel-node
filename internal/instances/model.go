package instances

import (
 "errors"
 "fmt"
 "regexp"
 "strings"

 "github.com/yudream/mcpanel-node/internal/dockerx"
)

var validID=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,63}$`)
var envKey=regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

type Spec struct {
 InstanceID string `json:"instanceId"`
 Name string `json:"name"`
 Image string `json:"image"`
 Command []string `json:"command"`
 Env map[string]string `json:"env"`
 MemoryMb int64 `json:"memoryMb"`
 CPUMillis int64 `json:"cpuMillis"`
 DiskMb int64 `json:"diskMb"`
 Ports []dockerx.PortBinding `json:"ports"`
 Kind string `json:"kind"`
 Config map[string]string `json:"config"`
 // StartDetect 启动成功检测：控制台输出包含该子串即视为启动成功（状态
 // starting → running）。空串 = 按类型默认（见 DefaultStartDetect）。
 // 面板 0.17.2+ 下发；旧面板不带该字段，行为与之前一致（start 即 running）。
 StartDetect string `json:"startDetect,omitempty"`
}

// DefaultStartDetect 按服务端类型给出启动成功标记的默认值（面板留空时使用）。
// 与 MCSM 的启动检测同思路：主流 Java 系与 Velocity 启动完成都打印 "Done ("，
// BungeeCord 打印 "Listening on"，基岩版打印 "Server started"；generic 无可靠
// 标记，不启用检测（保持原行为）。
func (s Spec) DefaultStartDetect() string {
 switch s.Kind{
 case "vanilla","paper","purpur","folia","fabric","forge","neoforge","quilt","velocity":
  return "Done ("
 case "bungee":
  return "Listening on"
 case "bedrock":
  return "Server started"
 default:
  return ""
 }
}

type Record struct {
 Spec
 State string `json:"state"`
 ContainerID string `json:"containerId,omitempty"`
 ExitCode int `json:"exitCode"`
 CreatedAt int64 `json:"createdAt"`
 UpdatedAt int64 `json:"updatedAt"`
}

func (s Spec) Validate()error {
 if !validID.MatchString(s.InstanceID){return errors.New("实例 ID 格式无效")}
 if len(strings.TrimSpace(s.Name))==0||len(s.Name)>128{return errors.New("实例名称长度应为1至128")}
 if len(s.Image)==0||len(s.Image)>255||strings.ContainsAny(s.Image," \t\r\n\x00"){return errors.New("镜像名称无效")}
 if len(s.Command)==0||len(s.Command)>64{return errors.New("必须填写启动命令，参数最多64项")}
 total:=0;for _,v:=range s.Command{total+=len(v);if strings.ContainsRune(v,0){return errors.New("启动参数含非法字符")}}
 if total>8192{return errors.New("启动命令过长")}
 if s.MemoryMb<64||s.MemoryMb>1048576||s.CPUMillis<0||(s.CPUMillis>0&&s.CPUMillis<100)||s.CPUMillis>256000||s.DiskMb<64||s.DiskMb>104857600{return errors.New("实例资源规格越界")}
 if len(s.Env)>64{return errors.New("环境变量最多64项")}
 for k,v:=range s.Env{if !envKey.MatchString(k)||len(v)>4096||strings.ContainsRune(v,0){return errors.New("环境变量格式无效")}}
 if len(s.Ports)>16{return errors.New("每实例最多16个端口")}
 seen:=map[string]bool{};targets:=map[string]bool{}
 for _,p:=range s.Ports{
  if p.Port<1024||p.Port>65535||p.ContainerPort<1||p.ContainerPort>65535||(p.Proto!="tcp"&&p.Proto!="udp"){return errors.New("端口范围或协议无效")}
  key:=fmt.Sprintf("%d/%s",p.Port,p.Proto);target:=fmt.Sprintf("%d/%s",p.ContainerPort,p.Proto)
  if seen[key]||targets[target]{return errors.New("端口映射重复")};seen[key]=true;targets[target]=true
 }
 switch s.Kind{case "vanilla","paper","purpur","folia","fabric","forge","neoforge","quilt","velocity","bungee","bedrock","generic":default:return errors.New("服务端类型不支持")}
 if len(s.StartDetect)>256||strings.ContainsAny(s.StartDetect,"\r\n\x00"){return errors.New("启动成功检测标记非法（≤256 字符，不能含换行）")}
 if len(s.Config)>128{return errors.New("配置项过多")}
 for k,v:=range s.Config{if len(k)>128||len(v)>8192||strings.ContainsAny(k,"\r\n\x00")||strings.ContainsAny(v,"\r\n\x00"){return errors.New("配置项非法")}}
 return nil
}
