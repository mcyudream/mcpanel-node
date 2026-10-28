package instances

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func TestCpuZeroIsUnlimitedAndInvalidRangesAreRejected(t *testing.T) {
	for _, cpu := range []int64{0, 100, 1000, 256000} {
		spec := validSpec()
		spec.CPUMillis = cpu
		if err := spec.Validate(); err != nil {
			t.Fatalf("CPU %d: %v", cpu, err)
		}
	}
	for _, cpu := range []int64{-1, 1, 99, 256001} {
		spec := validSpec()
		spec.CPUMillis = cpu
		if err := spec.Validate(); err == nil {
			t.Fatalf("CPU %d must fail", cpu)
		}
	}
}

func TestExplicitStartRemovesOldCpuQuotaWithoutRestartingDuringReconcile(t *testing.T) {
	svc, engine := newTestService(t)
	ctx := context.Background()
	spec := validSpec()
	spec.CPUMillis = 0
	rec, err := svc.Create(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	state := engine.byContainer[rec.ContainerID]
	state.NanoCPUs = 1000000000
	state.State = "running"
	engine.byContainer[rec.ContainerID] = state
	creates := len(engine.created)
	svc.ReconcileContainers(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if len(engine.created) != creates {
		t.Fatal("CPU migration should wait for explicit start/restart")
	}
	state.State = "exited"
	engine.byContainer[rec.ContainerID] = state
	out, err := svc.Action(ctx, rec.InstanceID, "start", 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(engine.created) != creates+1 {
		t.Fatal("old quota was not replaced on start")
	}
	fresh := out.(Record)
	if engine.byContainer[fresh.ContainerID].NanoCPUs != 0 {
		t.Fatal("quota still applied")
	}
}
