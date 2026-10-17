// Package dockerx implements a strictly read-only Docker Engine API client
// over the standard DOCKER_HOST transports (unix socket, Windows named pipe,
// TCP). It intentionally avoids the heavyweight SDK: the M1 surface is four
// GET endpoints, and a hand-rolled client keeps the dependency tree small
// and makes read-only enforceable by construction.
//
// Endpoints used (nothing else exists at this layer):
//
//	GET /_ping
//	GET /version
//	GET /containers/json?all=0&filters={label}
//	GET /containers/{id}/stats?stream=0&one-shot=1
package dockerx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Client is a lazily-used read-only Docker Engine API client.
// network/address 保留底层拨号目标，供 attach 手工劫持双向流复用。
type Client struct {
 httpClient *http.Client
 base       string // e.g. http://docker (path-less origin)
 network    string
 address    string
 mu         sync.Mutex
 version    string
 vErr       error
}

// New builds the client from DOCKER_HOST (or the platform default).
// No connection is attempted here; use Ping to probe availability.
func New() (*Client, error) {
	host := os.Getenv("DOCKER_HOST")
	if host == "" {
		host = defaultHost()
	}
	return newFromHost(host)
}

func newFromHost(host string) (*Client, error) {
	switch {
	case strings.HasPrefix(host, "unix://"):
		path := strings.TrimPrefix(host, "unix://")
		return &Client{
			base: "http://docker", network: "unix", address: path,
			httpClient: &http.Client{
				Timeout:   30 * time.Second,
				Transport: &http.Transport{DialContext: unixDialContext(path)},
			},
		}, nil
	case strings.HasPrefix(host, "npipe://"):
		// Deliberately unsupported: the node's Docker features target Linux
		// deployment (unix socket). Point tcp:// at a loopback daemon for
		// local development on Windows instead.
		return nil, errors.New("npipe DOCKER_HOST is not supported by this build; use the unix socket on Linux or tcp://127.0.0.1 for a local daemon")
	case strings.HasPrefix(host, "tcp://"), strings.HasPrefix(host, "http://"):
		u, err := url.Parse(host)
		if err != nil {
			return nil, fmt.Errorf("parse DOCKER_HOST: %w", err)
		}
		if !isLoopbackHost(u.Hostname()) {
			return nil, errors.New("plaintext tcp DOCKER_HOST is only allowed for loopback targets; remote daemons require TLS which this read-only client does not implement")
		}
		return &Client{
			base: "http://" + u.Host, network: "tcp", address: u.Host,
			httpClient: &http.Client{Timeout: 30 * time.Second},
		}, nil
	case strings.HasPrefix(host, "https://"):
		return nil, errors.New("https DOCKER_HOST requires a TLS client config which this read-only client does not implement; use the unix socket")
	default:
		return nil, fmt.Errorf("unsupported DOCKER_HOST scheme: %s (use unix:// or tcp://loopback)", host)
	}
}

func isLoopbackHost(hostname string) bool {
	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

// get performs a GET against the engine and decodes the JSON body into out.
func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		io.CopyN(io.Discard, resp.Body, 4<<10) //nolint:errcheck // best effort drain
		return fmt.Errorf("docker api %s: http %d", path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

// Ping probes daemon reachability.
func (c *Client) Ping(ctx context.Context) error {
	return c.get(ctx, "/_ping", nil)
}

// Version returns the daemon version string, cached for the process life.
func (c *Client) Version(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.version != "" || c.vErr != nil {
		return c.version, c.vErr
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var v struct {
		Version string `json:"Version"`
	}
	if err := c.get(ctx, "/version", &v); err != nil {
		c.vErr = err
		return "", err
	}
	c.version = v.Version
	return c.version, nil
}

// ContainerRef identifies a running container discovered by list.
type ContainerRef struct {
	ID     string
	Name   string
	State  string
	Labels map[string]string
}

// ListRunning returns currently running containers, optionally filtered by
// label. For mcpanel-managed instances the label filter is
// mcpanel.managed=true; without the filter this is a host-wide observation.
func (c *Client) ListRunning(ctx context.Context, labelFilter string) ([]ContainerRef, error) {
	return c.listContainers(ctx, "all=0", labelFilter)
}

// ListManagedAll returns all containers (including stopped/exited/created)
// matching the label filter. The stats snapshot needs the full managed set so
// the panel can reconcile instance state even when no docker event was
// observed (events stream gap / WS reconnect): a container that exited must
// still appear in the snapshot with state=exited instead of vanishing.
func (c *Client) ListManagedAll(ctx context.Context, labelFilter string) ([]ContainerRef, error) {
	return c.listContainers(ctx, "all=1", labelFilter)
}

func (c *Client) listContainers(ctx context.Context, query, labelFilter string) ([]ContainerRef, error) {
	path := "/containers/json?" + query
	if labelFilter != "" {
		filtersJSON, _ := json.Marshal(map[string][]string{"label": {labelFilter}})
		path += "&filters=" + url.QueryEscape(string(filtersJSON))
	}
	var list []struct {
		Id     string            `json:"Id"`
		Names  []string          `json:"Names"`
		State  string            `json:"State"`
		Labels map[string]string `json:"Labels"`
	}
	if err := c.get(ctx, path, &list); err != nil {
		return nil, fmt.Errorf("container list: %w", err)
	}
	out := make([]ContainerRef, 0, len(list))
	for _, s := range list {
		name := ""
		if len(s.Names) > 0 {
			name = strings.TrimPrefix(s.Names[0], "/")
		}
		out = append(out, ContainerRef{ID: s.Id, Name: name, State: s.State, Labels: s.Labels})
	}
	return out, nil
}

// ContainerSample is the parsed per-container resource reading.
type ContainerSample struct {
	CPUPercent float64
	MemBytes   uint64
}

// StatsOneShot fetches a single non-streaming stats sample for a container.
// The response includes precpu fields, enabling a delta CPU percentage from
// one round trip. Falls back to the plain non-streaming stats endpoint when
// one-shot is unsupported (pre-1.41 API).
func (c *Client) StatsOneShot(ctx context.Context, id string) (ContainerSample, error) {
	if err := ctx.Err(); err != nil {
		return ContainerSample{}, err
	}
	s, err := c.statsOnce(ctx, id, true)
	if err == nil {
		return s, nil
	}
	// Fallback: engines older than API 1.41 reject one-shot.
	s2, err2 := c.statsOnce(ctx, id, false)
	if err2 != nil {
		return ContainerSample{}, err
	}
	return s2, nil
}

func (c *Client) statsOnce(ctx context.Context, id string, oneShot bool) (ContainerSample, error) {
	path := "/containers/" + url.PathEscape(id) + "/stats?stream=0"
	if oneShot {
		path += "&one-shot=1"
	}
	var raw statsJSON
	if err := c.get(ctx, path, &raw); err != nil {
		return ContainerSample{}, fmt.Errorf("container stats: %w", err)
	}
	return ContainerSample{
		CPUPercent: raw.CPUPercent(),
		MemBytes:   raw.MemoryStats.Usage,
	}, nil
}

// Close satisfies the previous interface; the stdlib client holds no
// persistent resources.
func (c *Client) Close() error { return nil }

func defaultHost() string {
	if isWindows() {
		// Windows default points at the unsupported pipe on purpose; New()
		// then fails with the explicit guidance message.
		return "npipe:////./pipe/docker_engine"
	}
	return "unix:///var/run/docker.sock"
}
