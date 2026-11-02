package linter

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/logger"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// blockingBackend is an in-process backend whose HandleRequest blocks until
// release is closed, simulating a hung Go linter.
type blockingBackend struct {
	stubBackend
	release chan struct{}
}

func (b blockingBackend) HandleRequest(_ context.Context, _ *LinterInstance, lreq *LintingRequest) []LintingResult {
	if lreq.B64Input == "HANG" {
		<-b.release
	}
	return []LintingResult{{Severity: SEVERITY_ERROR, Finding: "ok"}}
}

// useInstances replaces the global list of linter instances for the duration of a test.
func useInstances(t *testing.T, instances ...*LinterInstance) {
	t.Helper()
	saved := linterInstances
	linterInstances = instances
	t.Cleanup(func() { linterInstances = saved })
}

// useBackendTimeout sets linter.backendTimeout for the duration of a test.
func useBackendTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	saved := config.Config.Linter.BackendTimeout
	config.Config.Linter.BackendTimeout = d
	t.Cleanup(func() { config.Config.Linter.BackendTimeout = saved })
}

func newInProcessInstance(name string) *LinterInstance {
	return &LinterInstance{
		Linter: &Linter{
			Name:                  name,
			Version:               "v0",
			ReqChannel:            make(chan LintingRequest, 8),
			useHandleRequest:      true,
			queueTimeSummary:      prometheus.NewSummary(prometheus.SummaryOpts{Name: name + "_queue"}),
			processingTimeSummary: prometheus.NewSummary(prometheus.SummaryOpts{Name: name + "_processing"}),
		},
		Mutex: &sync.Mutex{},
	}
}

func gaugeValue(t *testing.T, g prometheus.GaugeFunc) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return m.GetGauge().GetValue()
}

// waitFor polls cond until it returns true or the timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return cond()
}

func TestWatchdog_InProcessInstanceStuckAndRecovered(t *testing.T) {
	useBackendTimeout(t, 200*time.Millisecond)
	lin := newInProcessInstance("watchdog_inproc")
	useInstances(t, lin)
	gauge := lin.Linter.registerStuckInstancesMetric()

	core, logs := observer.New(zap.InfoLevel)
	savedLogger := logger.Logger
	logger.Logger = zap.New(core)
	t.Cleanup(func() { logger.Logger = savedLogger })

	ctx, cancel := context.WithCancel(context.Background())
	backend := blockingBackend{release: make(chan struct{})}
	done := make(chan struct{})
	ShutdownWG.Add(1)
	go func() {
		lin.serverLoop(ctx, backend)
		close(done)
	}()
	watchdogDone := make(chan struct{})
	go func() {
		runWatchdog(ctx, 10*time.Millisecond)
		close(watchdogDone)
	}()
	defer func() {
		cancel()
		<-done
		<-watchdogDone
	}()

	reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reqCancel()
	hung := make(chan []LintingResult, 1)
	go func() { hung <- runLint(lin, reqCtx, "HANG") }()

	// Busy, but not yet for longer than the backend timeout.
	if !waitFor(t, time.Second, func() bool { return lin.busySince.Load() != 0 }) {
		t.Fatal("instance never became busy")
	}
	if AnyInstanceStuck() {
		t.Error("instance reported stuck before the backend timeout elapsed")
	}

	// Stuck once the backend timeout has elapsed.
	if !waitFor(t, 2*time.Second, AnyInstanceStuck) {
		t.Fatal("instance was not reported stuck")
	}
	if got := gaugeValue(t, gauge); got != 1 {
		t.Errorf("stuck_instances = %v, want 1", got)
	}
	if !waitFor(t, time.Second, func() bool { return logs.FilterMessageSnippet("is stuck").Len() == 1 }) {
		t.Errorf("expected one 'stuck' log entry, got %v", logs.All())
	}

	// Recovers once the request completes.
	close(backend.release)
	if r := <-hung; !hasResult(r, SEVERITY_ERROR, "ok") {
		t.Errorf("hung request results = %+v", r)
	}
	if AnyInstanceStuck() {
		t.Error("instance still reported stuck after the request completed")
	}
	if got := gaugeValue(t, gauge); got != 0 {
		t.Errorf("stuck_instances = %v, want 0", got)
	}
	if !waitFor(t, time.Second, func() bool { return logs.FilterMessageSnippet("no longer stuck").Len() == 1 }) {
		t.Errorf("expected one 'no longer stuck' log entry, got %v", logs.All())
	}
	if n := logs.FilterMessageSnippet("is stuck").Len(); n != 1 {
		t.Errorf("got %d 'stuck' log entries, want 1", n)
	}

	// The instance serves subsequent requests.
	if r := runLint(lin, reqCtx, "hello"); !hasResult(r, SEVERITY_ERROR, "ok") {
		t.Errorf("instance did not serve the next request: %+v", r)
	}
}

func TestWatchdog_IgnoresIdleAndExternalInstances(t *testing.T) {
	useBackendTimeout(t, time.Millisecond)
	longAgo := time.Now().Add(-time.Hour).UnixNano()

	idle := newInProcessInstance("watchdog_idle")
	external := newInProcessInstance("watchdog_external")
	external.external = true
	external.busySince.Store(longAgo)
	notHandleRequest := newInProcessInstance("watchdog_nohandle")
	notHandleRequest.useHandleRequest = false
	notHandleRequest.busySince.Store(longAgo)
	useInstances(t, idle, external, notHandleRequest)

	if AnyInstanceStuck() {
		t.Error("idle or external instance reported stuck")
	}

	idle.busySince.Store(longAgo)
	if !AnyInstanceStuck() {
		t.Error("busy in-process instance not reported stuck")
	}
}
