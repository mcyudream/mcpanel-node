// Package proto implements the MC panel wire protocol v1 envelope.
//
// Envelope (JSON, UTF-8):
//
//	{
//	  "v": 1,              // protocol version, must be 1
//	  "id": "01J...",      // ULID; req/res correlation; empty for evt
//	  "t": "req|res|err|evt",
//	  "m": "node.hello",   // method name; for evt this is the topic
//	  "ts": 1737619200000, // epoch ms
//	  "p": {}              // payload; for err: {code, message, retryable}
//	}
//
// Frame budget: single frames are bounded at MaxFrameBytes (256 KiB).
// Authentication is transport-level (TLS + handshake Authorization bearer
// secret); there is deliberately no per-frame HMAC in v1.
package proto

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// MaxFrameBytes is the hard upper bound for a single wire frame (JSON envelope).
const MaxFrameBytes = 4 << 20 // 4 MiB（面板按 hello.maxFrame 协商，旧面板仍按 256KiB 自限）

// ProtocolVersion is the only supported envelope version.
const ProtocolVersion = 1

// Frame types.
const (
	TypeReq = "req"
	TypeRes = "res"
	TypeErr = "err"
	TypeEvt = "evt"
)

// Method and topic names implemented by this agent (M1).
const (
	MethodNodeHello = "node.hello"
	TopicNodeStats  = "node.stats"
	// TopicP2PSessionState 节点回报 P2P 会话状态（connecting/direct/failed/closed + 候选与字节数）。
	TopicP2PSessionState = "p2p.session.state"
)

// Envelope is the top-level wire frame (contract: docs/mc-panel-protocol-v1.md §4).
type Envelope struct {
	V   int             `json:"v"`
	ID  string          `json:"id,omitempty"`
	T   string          `json:"t"`
	M   string          `json:"m"`
	TS  int64           `json:"ts"`
	Seq *int64          `json:"seq,omitempty"` // evt only: per-connection per-topic counter from 0
	P   json.RawMessage `json:"p,omitempty"`
}

// ErrPayload is the payload of t=err frames.
type ErrPayload struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// Error codes sent by the node inside err frames (protocol §6).
const (
	CodeUnknownMethod = "proto.unknownMethod"
	CodeBadFrame      = "proto.badFrame"
	CodeBadPayload    = "proto.badPayload"
	CodeInternal      = "internal.error"
)

// NewEvt builds an evt frame for topic with the given sequence number.
// seq is scoped to the (connection, topic) pair and starts at 0.
func NewEvt(topic string, seq int64, p any) (*Envelope, error) {
	raw, err := marshalPayload(p)
	if err != nil {
		return nil, err
	}
	return &Envelope{V: ProtocolVersion, T: TypeEvt, M: topic, TS: nowMillis(), Seq: &seq, P: raw}, nil
}

func newID() string { return ulid.Make().String() }

// NewReq builds a req frame. p may be nil.
func NewReq(method string, p any) (*Envelope, error) {
	raw, err := marshalPayload(p)
	if err != nil {
		return nil, err
	}
	return &Envelope{V: ProtocolVersion, ID: newID(), T: TypeReq, M: method, TS: nowMillis(), P: raw}, nil
}

// NewRes builds a res frame answering reqID.
func NewRes(reqID, method string, p any) (*Envelope, error) {
	raw, err := marshalPayload(p)
	if err != nil {
		return nil, err
	}
	return &Envelope{V: ProtocolVersion, ID: reqID, T: TypeRes, M: method, TS: nowMillis(), P: raw}, nil
}

// NewErr builds an err frame answering reqID. code uses the protocol error
// vocabulary (e.g. proto.unknownMethod); handshake failures do NOT use err
// frames, they are plain HTTP 401/429 at the transport layer.
func NewErr(reqID, method, code, message string, retryable bool) *Envelope {
	raw, _ := json.Marshal(ErrPayload{Code: code, Message: message, Retryable: retryable})
	return &Envelope{V: ProtocolVersion, ID: reqID, T: TypeErr, M: method, TS: nowMillis(), P: raw}
}

// Decode validates and decodes a frame. Enforces protocol version, frame type
// and the req/res id correlation rule. Frame size enforcement (read side)
// happens at the websocket layer via SetReadLimit(MaxFrameBytes).
func Decode(data []byte) (*Envelope, error) {
	if len(data) > MaxFrameBytes {
		return nil, fmt.Errorf("frame exceeds %d bytes", MaxFrameBytes)
	}
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("bad json: %w", err)
	}
	if e.V != ProtocolVersion {
		return nil, fmt.Errorf("unsupported protocol version %d", e.V)
	}
	switch e.T {
	case TypeReq, TypeRes:
		if e.ID == "" {
			return nil, errors.New("req/res frames require id")
		}
		if e.M == "" {
			return nil, errors.New("req/res frames require m")
		}
	case TypeEvt:
		if e.M == "" {
			return nil, errors.New("evt frames require topic m")
		}
	case TypeErr:
	default:
		return nil, fmt.Errorf("unknown frame type %q", e.T)
	}
	return &e, nil
}

// Encode marshals the envelope and enforces the outbound frame budget.
func (e *Envelope) Encode() ([]byte, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFrameBytes {
		return nil, fmt.Errorf("encoded frame exceeds %d bytes", MaxFrameBytes)
	}
	return data, nil
}

// ErrPayloadOf decodes the payload of an err frame.
func ErrPayloadOf(e *Envelope) ErrPayload {
	var p ErrPayload
	_ = json.Unmarshal(e.P, &p)
	return p
}

func marshalPayload(p any) (json.RawMessage, error) {
	if p == nil {
		return nil, nil
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return raw, nil
}

func nowMillis() int64 { return time.Now().UnixMilli() }
