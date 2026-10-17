package wsserver

import (
	"context"
	"encoding/base64"
	"sync"
	"time"

	"github.com/yudream/mcpanel-node/internal/proto"
)

// 会话级实例输出订阅：instanceID → 取消函数。面板控制台页订阅后，
// 节点将容器 stdout/stderr 以 evt instance.output（含增量文本）推送到会话。
type outputSub struct {
	cancel context.CancelFunc
}

// outputAttachable 容器状态是否允许 attach 实时输出。
func outputAttachable(state string) bool {
	return state == "running" || state == "starting"
}

func (s *Server) startOutputSub(ctx context.Context, instanceID string) error {
	if err := requireEngine(s); err != nil {
		return err
	}
	if instanceID == "" {
		return errBadPayload("缺少 instanceId")
	}
	rec, err := s.instances.Inspect(ctx, instanceID)
	if err != nil {
		return err
	}
	// 容器未运行时 attach 必然失败：在 RPC 层明确报错，面板立即看到原因
	// 而不是订阅"成功"后控制台无限等待。starting（启动成功检测窗口）时
	// docker 容器实际已 running，attach 正常——启动阶段的控制台输出恰恰
	// 是启动检测/排查启动失败最需要的，拒绝会把整个启动窗口的日志全丢。
	if !outputAttachable(rec.State) {
		return errInternal("容器未运行（当前状态：" + rec.State + "），实例启动后再订阅实时输出")
	}
	s.sessionMu.Lock()
	sess := s.current
	s.sessionMu.Unlock()
	if sess == nil {
		return errInternal("会话不存在")
	}
	return sess.startOutputPump(ctx, s, rec.ContainerID, instanceID)
}

func (s *Server) stopOutputSub(instanceID string) {
	s.sessionMu.Lock()
	sess := s.current
	s.sessionMu.Unlock()
	if sess != nil {
		sess.stopOutputPump(instanceID)
	}
}

func (s *Server) pushSimpleEvent(topic string, payload map[string]any) {
	s.sessionMu.Lock()
	sess := s.current
	s.sessionMu.Unlock()
	if sess == nil {
		return
	}
	sess.sendTopicEvent(topic, payload)
}

var (
	outputMu sync.Mutex
)

// ---- session 侧实现（session.go 中调用） ----

func (s *session) startOutputPump(ctx context.Context, srv *Server, containerID, instanceID string) error {
	s.outputMu.Lock()
	if s.outputSubs == nil {
		s.outputSubs = map[string]context.CancelFunc{}
	}
	if old, ok := s.outputSubs[instanceID]; ok {
		old()
	}
	pctx, cancel := context.WithCancel(ctx)
	s.outputSubs[instanceID] = cancel
	s.outputMu.Unlock()

	stream, err := srv.engine.AttachStream(pctx, containerID, true)
	if err != nil {
		// attach 失败（竞态：订阅后容器恰好退出等）：清理登记并回错误给 RPC。
		cancel()
		s.outputMu.Lock()
		delete(s.outputSubs, instanceID)
		s.outputMu.Unlock()
		s.log.Warn("output subscribe failed", "instance", instanceID, "err", err)
		return err
	}
	go func() {
		defer func() {
			stream.Close()
			s.outputMu.Lock()
			if _, ok := s.outputSubs[instanceID]; ok {
				delete(s.outputSubs, instanceID)
			}
			s.outputMu.Unlock()
		}()
		// 读/聚合分离：阻塞 Read 放专职 goroutine，避免聚合泵的 select
		// 被 default 分支的阻塞读饿死，定时 flush 永不触发。
		rawCh := make(chan []byte, 64)
		go func() {
			defer close(rawCh)
			var chunk [4096]byte
			for {
				n, err := stream.Read(chunk[:])
				if n > 0 {
					b := make([]byte, n)
					copy(b, chunk[:n])
					select {
					case rawCh <- b:
					case <-pctx.Done():
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
		var buffer []byte
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()
		flush := func() {
			if len(buffer) == 0 {
				return
			}
			// data 承载原始字节的 base64：JSON 字符串会把非法 UTF-8（如 GBK 控制台
			// 输出）强制替换为 U+FFFD，text 只是兜底可读视图，面板/前端按 data 重解码。
			data := base64.StdEncoding.EncodeToString(buffer)
			text := string(buffer)
			buffer = buffer[:0]
			seq := s.nextSeq("instance.output")
			evt, err := proto.NewEvt("instance.output", seq, map[string]any{
				"instanceId": instanceID, "text": text, "data": data,
			})
			if err != nil {
				return
			}
			s.send(evt)
		}
		for {
			select {
			case b, ok := <-rawCh:
				if !ok {
					flush()
					return
				}
				buffer = append(buffer, b...)
				if len(buffer) >= 8*1024 {
					flush()
				}
			case <-ticker.C:
				flush()
			case <-pctx.Done():
				flush()
				return
			}
		}
	}()
	return nil
}

func (s *session) stopOutputPump(instanceID string) {
	s.outputMu.Lock()
	cancel, ok := s.outputSubs[instanceID]
	s.outputMu.Unlock()
	if ok {
		cancel()
	}
}

func (s *session) stopAllOutputPumps() {
	s.outputMu.Lock()
	cancels := make([]context.CancelFunc, 0, len(s.outputSubs))
	for _, cancel := range s.outputSubs {
		cancels = append(cancels, cancel)
	}
	s.outputSubs = map[string]context.CancelFunc{}
	s.outputMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (s *session) sendTopicEvent(topic string, payload map[string]any) {
	seq := s.nextSeq(topic)
	evt, err := proto.NewEvt(topic, seq, payload)
	if err != nil {
		return
	}
	s.send(evt)
}
