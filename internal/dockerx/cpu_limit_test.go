package dockerx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateUnlimitedCpuOmitsQuotaAndPositiveCpuUsesNanoCpus(t *testing.T) {
	for _, cpu := range []int64{0, 100, 1500} {
		t.Run(string(rune('a'+cpu/100)), func(t *testing.T) {
			var host map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				host = body["HostConfig"].(map[string]any)
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"Id":"created"}`))
			}))
			defer server.Close()
			client := &Client{base: server.URL, httpClient: server.Client()}
			if _, err := client.Create(context.Background(), "test", ContainerSpec{CPUMillis: cpu, MemoryMb: 512}); err != nil {
				t.Fatal(err)
			}
			value, exists := host["NanoCpus"]
			if cpu == 0 && exists {
				t.Fatalf("unlimited CPU must omit NanoCpus, got %v", value)
			}
			if cpu > 0 && (!exists || int64(value.(float64)) != cpu*1000000) {
				t.Fatalf("quota: %v", value)
			}
		})
	}
}
