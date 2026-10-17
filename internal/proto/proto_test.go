package proto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReqResRoundTrip(t *testing.T) {
	req, err := NewReq(MethodNodeHello, map[string]string{"panelVersion": "0.1.0"})
	require.NoError(t, err)

	data, err := req.Encode()
	require.NoError(t, err)
	require.LessOrEqual(t, len(data), MaxFrameBytes)

	got, err := Decode(data)
	require.NoError(t, err)
	require.Equal(t, 1, got.V)
	require.Equal(t, TypeReq, got.T)
	require.Equal(t, MethodNodeHello, got.M)
	require.Equal(t, req.ID, got.ID)

	res, err := NewRes(got.ID, got.M, map[string]any{"nodeId": "n1"})
	require.NoError(t, err)
	resData, err := res.Encode()
	require.NoError(t, err)

	resDecoded, err := Decode(resData)
	require.NoError(t, err)
	require.Equal(t, req.ID, resDecoded.ID)
	require.Equal(t, TypeRes, resDecoded.T)

	var payload map[string]string
	require.NoError(t, json.Unmarshal(resDecoded.P, &payload))
	require.Equal(t, "n1", payload["nodeId"])
}

func TestEvtFrame(t *testing.T) {
	evt, err := NewEvt(TopicNodeStats, 0, map[string]any{"cpuPercent": 1.5})
	require.NoError(t, err)
	require.Empty(t, evt.ID, "evt frames carry no id")

	data, err := evt.Encode()
	require.NoError(t, err)
	got, err := Decode(data)
	require.NoError(t, err)
	require.Equal(t, TypeEvt, got.T)
	require.Equal(t, TopicNodeStats, got.M)
	require.NotNil(t, got.Seq)
	require.Equal(t, int64(0), *got.Seq)
	require.Empty(t, got.ID)

	evt2, err := NewEvt(TopicNodeStats, 7, nil)
	require.NoError(t, err)
	data2, err := evt2.Encode()
	require.NoError(t, err)
	got2, err := Decode(data2)
	require.NoError(t, err)
	require.Equal(t, int64(7), *got2.Seq)
	// seq absent on non-evt frames
	_, err = NewReq(MethodNodeHello, nil)
	require.NoError(t, err)
}

func TestErrFrame(t *testing.T) {
	e := NewErr("req-1", "port.check", CodeUnknownMethod, "port.check not implemented by this agent", false)
	data, err := e.Encode()
	require.NoError(t, err)

	got, err := Decode(data)
	require.NoError(t, err)
	require.Equal(t, TypeErr, got.T)
	require.Equal(t, "port.check", got.M)
	p := ErrPayloadOf(got)
	require.Equal(t, CodeUnknownMethod, p.Code)
	require.False(t, p.Retryable)
}

func TestDecodeRejects(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"wrong version", `{"v":2,"id":"a","t":"req","m":"x","ts":1}`},
		{"bad type", `{"v":1,"id":"a","t":"zzz","m":"x","ts":1}`},
		{"req without id", `{"v":1,"id":"","t":"req","m":"x","ts":1}`},
		{"req without m", `{"v":1,"id":"a","t":"req","m":"","ts":1}`},
		{"evt without topic", `{"v":1,"id":"","t":"evt","m":"","ts":1}`},
		{"not json", `hello`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode([]byte(tc.data))
			require.Error(t, err)
		})
	}
}

func TestEncodeRejectsOversize(t *testing.T) {
	big := make([]byte, MaxFrameBytes)
	for i := range big {
		big[i] = 'a'
	}
	_, err := NewReq("big", map[string]string{"blob": string(big)})
	require.NoError(t, err)
	// The marshaled frame of the request above exceeds the budget.
	// NewReq does not enforce; Encode does.
	big2 := make([]byte, MaxFrameBytes)
	for i := range big2 {
		big2[i] = 'a'
	}
	req, err := NewReq("big", map[string]string{"blob": string(big2)})
	require.NoError(t, err)
	_, err = req.Encode()
	require.Error(t, err)
}
