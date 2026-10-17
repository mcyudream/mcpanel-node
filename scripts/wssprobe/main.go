// Command wssprobe is a minimal WSS control-channel probe for cross-language
// integration testing. It dials a node's /control endpoint with the frozen
// handshake headers, performs the node.hello exchange, prints the hello res
// and the first node.stats evt, then exits.
//
// Usage:
//
//	wssprobe -url wss://127.0.0.1:7443 -node-id <id> -secret <secret> [-pin <sha256hex>] [-timeout 10s]
//
// TEST/DEV ONLY: the secret is passed via flag for probe convenience and is
// a test credential, not a production one.
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
	"time"

	"github.com/coder/websocket"

	"github.com/yudream/mcpanel-node/internal/proto"
)

func main() {
	url := flag.String("url", "wss://127.0.0.1:7443", "node control URL (wss://host[:port])")
	nodeID := flag.String("node-id", "", "nodeId (X-Mcpanel-Node-Id)")
	secret := flag.String("secret", "", "nodeSecret (Bearer)")
	pin := flag.String("pin", "", "expected leaf certificate SHA-256 (64 hex, optional but recommended)")
	waitStats := flag.Bool("wait-stats", true, "wait for the first node.stats evt")
	timeout := flag.Duration("timeout", 15*time.Second, "overall timeout")
	flag.Parse()

	if *nodeID == "" || *secret == "" {
		fmt.Fprintln(os.Stderr, "-node-id and -secret are required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if *pin != "" {
		want, err := hex.DecodeString(*pin)
		if err != nil || len(want) != 32 {
			fmt.Fprintln(os.Stderr, "-pin must be 64 hex chars")
			os.Exit(2)
		}
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // pinned probe
		tlsCfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return context.Canceled
			}
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != *pin {
				return fmt.Errorf("certificate pin mismatch")
			}
			return nil
		}
	}

	header := http.Header{}
	header.Set("X-Mcpanel-Node-Id", *nodeID)
	header.Set("Authorization", "Bearer "+*secret)

	conn, resp, err := websocket.Dial(ctx, *url+"/control", &websocket.DialOptions{
		HTTPClient:  &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}},
		HTTPHeader:  header,
		Subprotocols: []string{},
	})
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		fmt.Fprintf(os.Stderr, "dial failed (http %d): %v\n", status, err)
		os.Exit(1)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	req, err := proto.NewReq(proto.MethodNodeHello, map[string]string{"panelVersion": "0.1.0"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "build hello:", err)
		os.Exit(1)
	}
	data, err := req.Encode()
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode hello:", err)
		os.Exit(1)
	}
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		fmt.Fprintln(os.Stderr, "write hello:", err)
		os.Exit(1)
	}

	for i := 0; i < 2; i++ {
		mt, raw, err := conn.Read(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read:", err)
			os.Exit(1)
		}
		if mt != websocket.MessageText {
			fmt.Fprintln(os.Stderr, "unexpected binary frame")
			os.Exit(1)
		}
		env, err := proto.Decode(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "decode:", err)
			os.Exit(1)
		}
		switch env.T {
		case proto.TypeRes:
			pretty, _ := json.MarshalIndent(json.RawMessage(env.P), "", "  ")
			fmt.Printf("hello res (id match=%v):\n%s\n", env.ID == req.ID, pretty)
		case proto.TypeEvt:
			pretty, _ := json.MarshalIndent(json.RawMessage(env.P), "", "  ")
			seq := int64(-1)
			if env.Seq != nil {
				seq = *env.Seq
			}
			fmt.Printf("evt %s seq=%d:\n%s\n", env.M, seq, pretty)
			if env.M == proto.TopicNodeStats || !*waitStats {
				fmt.Println("PROBE OK")
				return
			}
		case proto.TypeErr:
			fmt.Fprintf(os.Stderr, "err frame: %s\n", env.P)
			os.Exit(1)
		}
	}
	fmt.Println("PROBE OK")
}
