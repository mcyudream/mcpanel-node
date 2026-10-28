package dockerx

import (
 "bufio"
 "bytes"
 "context"
 "encoding/binary"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "os"
 "strconv"
 "strings"
 "time"
)

type PortBinding struct {
 Port int `json:"port"`
 ContainerPort int `json:"containerPort"`
 Proto string `json:"proto"`
}

type ContainerSpec struct {
 InstanceID string
 NodeID string
 Image string
 Command []string
 Env map[string]string
 MemoryMb int64
 CPUMillis int64
 DataPath string
 Ports []PortBinding
}

type ContainerState struct {
 ID string `json:"id"`
 State string `json:"state"`
 ExitCode int `json:"exitCode"`
 Running bool `json:"running"`
 Labels map[string]string `json:"labels"`
 CapAdd []string `json:"capAdd,omitempty"`
 CapDrop []string `json:"capDrop,omitempty"`
 NanoCPUs int64 `json:"nanoCpus,omitempty"`
}

// InstanceCapAdd/InstanceCapDrop 实例容器的 capability 策略：全部丢弃后仅保留
// DAC_OVERRIDE。Windows/macOS Docker Desktop 的 bind mount 属主 uid 映射不可控，
// root 没有 DAC_OVERRIDE 时 java 创建目录会 EACCES（Paperclip cache 目录即此症状）。
var (
 InstanceCapAdd = []string{"DAC_OVERRIDE"}
 InstanceCapDrop = []string{"ALL"}
)

// CapsUpToDate 报告存量容器的 capability 策略是否与当前版本一致。Docker 的
// HostConfig 只在容器 create 时读取，旧版本节点创建的容器重启不会应用新策略，
// 调用方须先检测，不一致则重建容器（数据在 bind mount，重建零成本）。
func CapsUpToDate(capAdd, capDrop []string) bool {
 return sameStrings(capAdd, InstanceCapAdd) && sameStrings(capDrop, InstanceCapDrop)
}

func sameStrings(a, b []string) bool {
 if len(a) != len(b) { return false }
 seen := make(map[string]int, len(b))
 for _, v := range b { seen[v]++ }
 for _, v := range a {
  if seen[v] == 0 { return false }
  seen[v]--
 }
 return true
}

type APIError struct { Status int; Message string }
func (e *APIError) Error() string { return fmt.Sprintf("Docker 返回 %d：%s",e.Status,e.Message) }
func IsNotFound(err error) bool { var e *APIError; return errors.As(err,&e) && e.Status==404 }

func (c *Client) request(ctx context.Context, method,path string, body any) (*http.Response,error) {
 var r io.Reader
 if body!=nil { b,err:=json.Marshal(body); if err!=nil{return nil,err};r=bytes.NewReader(b) }
 req,err:=http.NewRequestWithContext(ctx,method,c.base+path,r);if err!=nil{return nil,err}
 if body!=nil {req.Header.Set("Content-Type","application/json")}
 resp,err:=c.httpClient.Do(req);if err!=nil{return nil,err}
 if resp.StatusCode>=200 && resp.StatusCode<300{return resp,nil}
 defer resp.Body.Close()
 var msg struct{ Message string `json:"message"` }
 _=json.NewDecoder(io.LimitReader(resp.Body,8192)).Decode(&msg)
 if len(msg.Message)>1024{msg.Message=msg.Message[:1024]}
 return nil,&APIError{resp.StatusCode,msg.Message}
}

func (c *Client) Create(ctx context.Context, name string, spec ContainerSpec)(string,error){
 ports:=map[string]any{};bindings:=map[string]any{}
 for _,p:=range spec.Ports{
  key:=strconv.Itoa(p.ContainerPort)+"/"+p.Proto
  ports[key]=map[string]any{}
  bindings[key]=[]map[string]string{{"HostIp":"0.0.0.0","HostPort":strconv.Itoa(p.Port)}}
 }
 env:=make([]string,0,len(spec.Env));for k,v:=range spec.Env{env=append(env,k+"="+v)}
 hostConfig:=map[string]any{
  "Memory":spec.MemoryMb*1024*1024,"MemorySwap":spec.MemoryMb*1024*1024,
  "PidsLimit":512,
  // capability 策略集中在 InstanceCapAdd/InstanceCapDrop（含 CapsUpToDate
  // 存量检测），Create 与对齐逻辑共用，避免两处漂移。
  "CapDrop":InstanceCapDrop,"CapAdd":InstanceCapAdd,
  "SecurityOpt":[]string{"no-new-privileges:true"},"NetworkMode":"bridge",
  "PortBindings":bindings,"RestartPolicy":map[string]string{"Name":"no"},
  "Mounts":[]map[string]any{{"Type":"bind","Source":spec.DataPath,"Target":"/data","ReadOnly":false}},
  "LogConfig":map[string]any{"Type":"json-file","Config":map[string]string{"max-size":"10m","max-file":"3"}},
 }
 if spec.CPUMillis>0 { hostConfig["NanoCpus"]=spec.CPUMillis*1000000 }
 // 继承宿主 /etc/hosts 的域名映射（节点容器需以 -v /etc/hosts:/etc/hosts:ro
 // 挂载；文件不存在时不注入，行为与旧版一致）。
 if extra:=HostsFileExtraHosts("/etc/hosts");len(extra)>0{hostConfig["ExtraHosts"]=extra}
 body:=map[string]any{
  "Image":spec.Image,"Cmd":spec.Command,"Env":env,"WorkingDir":"/data",
  "OpenStdin":true,"StdinOnce":false,"AttachStdin":false,"Tty":false,
  "Labels":map[string]string{"mcpanel.managed":"true","mcpanel.instanceId":spec.InstanceID,"mcpanel.nodeId":spec.NodeID},
  "ExposedPorts":ports,
  "HostConfig":hostConfig,
 }
 resp,err:=c.request(ctx,"POST","/containers/create?name="+url.QueryEscape(name),body);if err!=nil{return "",err};defer resp.Body.Close()
 var out struct{ID string `json:"Id"`};err=json.NewDecoder(io.LimitReader(resp.Body,65536)).Decode(&out);return out.ID,err
}

// HostsFileExtraHosts 把宿主 /etc/hosts 解析成 Docker extra_hosts（"名称:IP"），
// 供实例容器继承宿主的域名映射。每次创建容器时读取，宿主 hosts 变更对新容器生效；
// 文件不存在（未挂载 / 非 Linux 宿主）返回 nil。同名条目首见优先（与 hosts 解析
// 语义一致）；loopback 条目原样注入——注意其在实例容器内指向容器自身而非宿主。
func HostsFileExtraHosts(path string) []string {
 data, err := os.ReadFile(path)
 if err != nil {
  return nil
 }
 seen := map[string]bool{}
 var extra []string
 for _, line := range strings.Split(string(data), "\n") {
  if i := strings.IndexByte(line, '#'); i >= 0 {
   line = line[:i]
  }
  fields := strings.Fields(line)
  if len(fields) < 2 {
   continue
  }
  ip := fields[0]
  for _, name := range fields[1:] {
   if name == "" || seen[name] {
    continue
   }
   seen[name] = true
   extra = append(extra, name+":"+ip)
  }
 }
 return extra
}

func (c *Client) Inspect(ctx context.Context,id string)(ContainerState,error){
 resp,err:=c.request(ctx,"GET","/containers/"+url.PathEscape(id)+"/json",nil);if err!=nil{return ContainerState{},err};defer resp.Body.Close()
 var v struct{ID string `json:"Id"`;State struct{Status string `json:"Status"`;Running bool `json:"Running"`;ExitCode int `json:"ExitCode"`} `json:"State"`;Config struct{Labels map[string]string `json:"Labels"`} `json:"Config"`;HostConfig struct{CapAdd []string `json:"CapAdd"`;CapDrop []string `json:"CapDrop"`;NanoCPUs int64 `json:"NanoCpus"`} `json:"HostConfig"`}
 err=json.NewDecoder(io.LimitReader(resp.Body,2<<20)).Decode(&v)
 return ContainerState{v.ID,v.State.Status,v.State.ExitCode,v.State.Running,v.Config.Labels,v.HostConfig.CapAdd,v.HostConfig.CapDrop,v.HostConfig.NanoCPUs},err
}

func(c *Client) Action(ctx context.Context,id,action string,seconds int)error{
 if action!="start"&&action!="stop"&&action!="restart"&&action!="kill"{return errors.New("不支持的容器操作")}
 path:="/containers/"+url.PathEscape(id)+"/"+action
 if action=="stop"||action=="restart"{path+="?t="+strconv.Itoa(seconds)}
 resp,err:=c.request(ctx,"POST",path,nil);if err!=nil{return err};resp.Body.Close();return nil
}

// UpdateRestartPolicy 将容器重启策略设为 none，防止 kill/崩溃后被 Docker 拉起。
func (c *Client) UpdateRestartPolicy(ctx context.Context, id, policy string) error {
 if policy == "" {
  policy = "no"
 }
 path := "/containers/" + url.PathEscape(id) + "/update"
 body := map[string]any{"RestartPolicy": map[string]any{"Name": policy}}
 resp, err := c.request(ctx, "POST", path, body)
 if err != nil {
  return err
 }
 resp.Body.Close()
 return nil
}
func(c *Client) Remove(ctx context.Context,id string)error{
 resp,err:=c.request(ctx,"DELETE","/containers/"+url.PathEscape(id)+"?force=false&v=false",nil);if IsNotFound(err){return nil};if err!=nil{return err};resp.Body.Close();return nil
}

func (c *Client) Pull(ctx context.Context, image string) error {
	// Pull may exceed the short ordinary API timeout; the caller supplies a task deadline.
	// Docker Engine API 要求 fromImage 与 tag 分离；整串塞进 fromImage 会导致带 registry/tag 的镜像拉取失败。
	fromImage, tag := splitImageRef(image)
	if fromImage == "" {
		return errors.New("镜像名无效")
	}
	q := url.Values{}
	q.Set("fromImage", fromImage)
	if tag != "" {
		q.Set("tag", tag)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.base+"/images/create?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: c.httpClient.Transport}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(body))
		if len(msg) > 512 {
			msg = msg[:512]
		}
		if msg == "" {
			msg = "拉取镜像失败"
		}
		return &APIError{resp.StatusCode, msg}
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var status struct {
			Error string `json:"error"`
		}
		err = dec.Decode(&status)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if status.Error != "" {
			return errors.New(status.Error)
		}
	}
}

// splitImageRef 将 repo/name:tag 拆为 fromImage + tag；无 tag 时默认 latest。
// registry:port/repo/name:v1 以最后一个斜杠后的冒号为准。
func splitImageRef(image string) (string, string) {
	image = strings.TrimSpace(image)
	if image == "" {
		return "", ""
	}
	if i := strings.Index(image, "@"); i >= 0 {
		return image[:i], image[i+1:]
	}
	lastSlash := strings.LastIndex(image, "/")
	lastColon := strings.LastIndex(image, ":")
	if lastColon > lastSlash {
		return image[:lastColon], image[lastColon+1:]
	}
	return image, "latest"
}

// ImageInfo 面板镜像管理行。
type ImageInfo struct {
	ID       string   `json:"id"`
	RepoTags []string `json:"repoTags"`
	Size     int64    `json:"size"`
	Created  int64    `json:"created"`
}

// ListImages GET /images/json（节点本机全部镜像）。
func (c *Client) ListImages(ctx context.Context) ([]ImageInfo, error) {
	resp, err := c.request(ctx, "GET", "/images/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var raw []struct {
		ID       string   `json:"Id"`
		RepoTags []string `json:"RepoTags"`
		Size     int64    `json:"Size"`
		Created  int64    `json:"Created"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&raw); err != nil {
		return nil, err
	}
	out := make([]ImageInfo, 0, len(raw))
	for _, item := range raw {
		tags := item.RepoTags
		if tags == nil {
			tags = []string{}
		}
		out = append(out, ImageInfo{ID: item.ID, RepoTags: tags, Size: item.Size, Created: item.Created})
	}
	return out, nil
}

// RemoveImage DELETE /images/{name}。
func (c *Client) RemoveImage(ctx context.Context, image string, force bool) error {
	if strings.TrimSpace(image) == "" {
		return errors.New("镜像名无效")
	}
	path := "/images/" + url.PathEscape(image) + "?force=" + strconv.FormatBool(force) + "&noprune=false"
	resp, err := c.request(ctx, "DELETE", path, nil)
	if err != nil {
		if IsNotFound(err) {
			return nil
		}
		return err
	}
	resp.Body.Close()
	return nil
}

// ListAllContainers GET /containers/json?all=1 — 节点本机全部容器（MCSM 远程主机容器列表）。
func (c *Client) ListAllContainers(ctx context.Context) ([]map[string]any, error) {
 resp, err := c.request(ctx, "GET", "/containers/json?all=1", nil)
 if err != nil {
  return nil, err
 }
 defer resp.Body.Close()
 var raw []struct {
  ID      string   `json:"Id"`
  Names   []string `json:"Names"`
  Image   string   `json:"Image"`
  ImageID string   `json:"ImageID"`
  State   string   `json:"State"`
  Status  string   `json:"Status"`
  Labels  map[string]string `json:"Labels"`
 }
 if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&raw); err != nil {
  return nil, err
 }
 out := make([]map[string]any, 0, len(raw))
 for _, item := range raw {
  name := ""
  if len(item.Names) > 0 {
   name = strings.TrimPrefix(item.Names[0], "/")
  }
  out = append(out, map[string]any{
   "id": item.ID,
   "name": name,
   "image": item.Image,
   "imageId": item.ImageID,
   "state": item.State,
   "status": item.Status,
   "instanceId": item.Labels["mcpanel.instanceId"],
   "managed": item.Labels["mcpanel.managed"] == "true",
  })
 }
 return out, nil
}

// ImageExists reports whether the image is already present locally.
func (c *Client) ImageExists(ctx context.Context, image string) bool {
	resp, err := c.request(ctx, "GET", "/images/"+url.PathEscape(image)+"/json", nil)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func(c *Client) Logs(ctx context.Context,id,since string,tail int)(string,bool,error){
 q:=url.Values{"stdout":{"1"},"stderr":{"1"},"timestamps":{"1"},"tail":{strconv.Itoa(tail)}}
 if since!=""{q.Set("since",since)}
 resp,err:=c.request(ctx,"GET","/containers/"+url.PathEscape(id)+"/logs?"+q.Encode(),nil);if err!=nil{return "",false,err};defer resp.Body.Close()
 const max=96*1024
 var out bytes.Buffer
 r:=bufio.NewReader(resp.Body)
 for{
  var h [8]byte
  _,err=io.ReadFull(r,h[:]);if err==io.EOF{return out.String(),false,nil};if err!=nil{return "",false,err}
  n:=int64(binary.BigEndian.Uint32(h[4:]));if n>16<<20{return "",false,errors.New("Docker 日志帧超限")}
  remaining:=int64(max-out.Len());take:=n;if take>remaining{take=remaining}
  if _,err=io.CopyN(&out,r,take);err!=nil{return "",false,err}
  if n>take{return out.String(),true,nil}
 }
}

// Client 附加字段在 transport.go / operations.go 间共享：network/address 保存
// 底层拨号目标，供 attach 双向流手工劫持使用。

// AttachWriter 打开并保持一条 attach 双向流，返回其可写端。
// 8 字节帧头只存在于 daemon→client 方向；client→容器 stdin 恒为原始流
// （docker attach / docker exec -i 即裸写）。已用 docker 28.3.3 实测：即使请求
// 声明 multiplexed-stream，封帧也会把帧头原样漏进容器控制台——Paper/Leaf 静默
// 吞掉 NUL 前缀掩盖问题，Forge 原样透传导致命令必报 Unknown。101 响应的
// Content-Type 只描述输出方向，与写入方式无关。连接由调用方持有到实例停止。
func(c *Client) AttachWriter(ctx context.Context,id string)(io.WriteCloser,error){
 var d net.Dialer
 conn,err:=d.DialContext(ctx,c.network,c.address);if err!=nil{return nil,err}
 _ = conn.SetDeadline(time.Time{})
 reqStr:=fmt.Sprintf("POST /containers/%s/attach?stream=1&stdin=1&stdout=0&stderr=0 HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n",url.PathEscape(id))
 if _,err=conn.Write([]byte(reqStr));err!=nil{conn.Close();return nil,err}
 br:=bufio.NewReader(conn)
 resp,err:=http.ReadResponse(br,nil);if err!=nil{conn.Close();return nil,err}
 if resp.StatusCode!=101{conn.Close();return nil,&APIError{resp.StatusCode,"实例标准输入不可用"}}
 return conn,nil
}

func(c *Client) Command(ctx context.Context,id,command string)error{
 if command==""||len(command)>4096||strings.ContainsAny(command,"\r\n\x00"){return errors.New("控制台命令必须为单行且不超过4096字节")}
 w,err:=c.AttachWriter(ctx,id);if err!=nil{return err}
 defer w.Close()
 _,err=w.Write([]byte(command+"\n"));return err
}

// Events 订阅 mcpanel 管理容器事件，转发给 sink；返回时 ctx 已取消。
func(c *Client) Events(ctx context.Context,since string,sink func(containerID,action,instanceID string))error{
 q:=url.Values{"filters":{`{"label":["mcpanel.managed=true"]}`}}
 if since!=""{q.Set("since",since)}
 req,err:=http.NewRequestWithContext(ctx,"GET",c.base+"/events?"+q.Encode(),nil);if err!=nil{return err}
 client:=&http.Client{Transport:c.httpClient.Transport}
 resp,err:=client.Do(req);if err!=nil{return err};defer resp.Body.Close()
 if resp.StatusCode!=200{return &APIError{resp.StatusCode,"事件订阅失败"}}
 dec:=json.NewDecoder(resp.Body)
 for{
  if err:=ctx.Err();err!=nil{return err}
  var raw struct{Action string `json:"Action"`;Actor struct{ID string `json:"ID"`;Attributes map[string]string `json:"Attributes"`} `json:"Actor"`}
  if err:=dec.Decode(&raw);err!=nil{return err}
  switch raw.Action{case "start","die","stop","destroy","pause","unpause":
   sink(raw.Actor.ID,raw.Action,raw.Actor.Attributes["mcpanel.instanceId"])
  }
 }
}
