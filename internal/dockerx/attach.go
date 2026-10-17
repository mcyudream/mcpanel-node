package dockerx

import (
 "bufio"
 "context"
 "encoding/binary"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
)

// AttachStream 打开容器 stdout/stderr 的实时流（可选附带历史日志），
// 返回已解复用的纯文本流：8 字节多路复用帧头在此层剥离，读到的即
// 可直接展示的控制台文本。流随 ctx 取消或容器停止而结束。
func (c *Client) AttachStream(ctx context.Context, id string, includeHistory bool) (io.ReadCloser, error) {
 var d net.Dialer
 conn, err := d.DialContext(ctx, c.network, c.address)
 if err != nil {
  return nil, err
 }
 q := "stream=1&stdout=1&stderr=1"
 if includeHistory {
  q += "&logs=1"
 }
 reqStr := fmt.Sprintf("POST /containers/%s/attach?%s HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n",
  url.PathEscape(id), q)
 if _, err := conn.Write([]byte(reqStr)); err != nil {
  conn.Close()
  return nil, err
 }
 br := bufio.NewReader(conn)
 resp, err := http.ReadResponse(br, nil)
 if err != nil {
  conn.Close()
  return nil, err
 }
 if resp.StatusCode != http.StatusSwitchingProtocols {
  conn.Close()
  return nil, &APIError{resp.StatusCode, "容器输出流不可用"}
 }
 go func() {
  <-ctx.Done()
  _ = conn.Close()
 }()
 // 节点侧二进制 Linux 守护为多路复用流；Windows Docker Desktop 代理返回
 // 原始文本流（无帧头）。按响应 Content-Type 分支解码。
 if isMultiplexed(resp.Header.Get("Content-Type")) {
  return &muxTextReader{r: br, conn: conn}, nil
 }
 return &plainTextReader{r: br}, nil
}

func isMultiplexed(contentType string) bool {
 return contentType == "" || contentType == "application/vnd.docker.multiplexed-stream" ||
  contentType == "application/vnd.docker.raw-stream"
}

// muxTextReader 剥离 Docker 多路复用帧头，输出 stdout/stderr 文本。
type muxTextReader struct {
 r    *bufio.Reader
 conn io.Closer
 pend []byte
}

func (m *muxTextReader) Close() error { return m.conn.Close() }

func (m *muxTextReader) Read(p []byte) (int, error) {
 for len(m.pend) == 0 {
  var header [8]byte
  if _, err := io.ReadFull(m.r, header[:]); err != nil {
   return 0, err
  }
  n := int64(binary.BigEndian.Uint32(header[4:8]))
  if n <= 0 || n > 16<<20 {
   return 0, fmt.Errorf("Docker 输出帧长度异常: %d", n)
  }
  chunk := make([]byte, n)
  if _, err := io.ReadFull(m.r, chunk); err != nil {
   return 0, err
  }
  // 仅转发 stdout（stream=1）；stderr 同样是控制台文本，一并转发。
  m.pend = chunk
 }
 n := copy(p, m.pend)
 m.pend = m.pend[n:]
 return n, nil
}

type plainTextReader struct{ r *bufio.Reader }

func (p *plainTextReader) Read(b []byte) (int, error) { return p.r.Read(b) }
func (p *plainTextReader) Close() error               { return nil }
