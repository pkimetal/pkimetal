package linter

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/config"

	"github.com/prometheus/client_golang/prometheus"
)

// --- parseResultToken ---

func TestParseResultToken_EndOfResults(t *testing.T) {
	results, end, err := parseResultToken("pkilint", PKIMETAL_ENDOFRESULTS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !end {
		t.Error("expected end=true for the end-of-results sentinel")
	}
	if results != nil {
		t.Errorf("expected no results, got %v", results)
	}
}

func TestParseResultToken_LegacySeverities(t *testing.T) {
	cases := map[string]SeverityLevel{
		"D: debug msg":   SEVERITY_DEBUG,
		"I: info msg":    SEVERITY_INFO,
		"N: notice msg":  SEVERITY_NOTICE,
		"W: warning msg": SEVERITY_WARNING,
		"E: error msg":   SEVERITY_ERROR,
		"B: bug msg":     SEVERITY_BUG,
		"F: fatal msg":   SEVERITY_FATAL,
	}
	for token, wantSeverity := range cases {
		results, end, err := parseResultToken("certlint", token)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", token, err)
			continue
		}
		if end {
			t.Errorf("%q: unexpected end=true", token)
		}
		if len(results) != 1 {
			t.Errorf("%q: expected 1 result, got %d", token, len(results))
			continue
		}
		if results[0].Severity != wantSeverity {
			t.Errorf("%q: got severity %d, want %d", token, results[0].Severity, wantSeverity)
		}
		if results[0].LinterName != "certlint" {
			t.Errorf("%q: got linter name %q, want certlint", token, results[0].LinterName)
		}
		if results[0].Finding != token[3:] {
			t.Errorf("%q: got finding %q, want %q", token, results[0].Finding, token[3:])
		}
	}
}

func TestParseResultToken_LegacyErrors(t *testing.T) {
	for _, token := range []string{"E: ", "E:x", "Z: unknown severity"} {
		if _, _, err := parseResultToken("certlint", token); err == nil {
			t.Errorf("%q: expected an error, got nil", token)
		}
	}
}

func TestParseResultToken_JSON(t *testing.T) {
	token := `{"results":[{"node_path":"tbsCertificate.extensions","validator":"v","finding_descriptions":[{"severity":"ERROR","code":"cabf.some_finding","message":"m"}]}]}`
	results, end, err := parseResultToken("pkilint", token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if end {
		t.Error("unexpected end=true")
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.LinterName != "pkilint" || r.Finding != "cabf.some_finding" || r.Code != "cabf.some_finding" || r.Field != "tbsCertificate.extensions" {
		t.Errorf("unexpected result: %+v", r)
	}
	if r.Severity != SEVERITY_ERROR {
		t.Errorf("got severity %d, want %d", r.Severity, SEVERITY_ERROR)
	}
}

func TestParseResultToken_JSONMultiple(t *testing.T) {
	token := `{"results":[{"node_path":"a","finding_descriptions":[{"severity":"WARNING","code":"c1"},{"severity":"NOTICE","code":"c2"}]},{"node_path":"b","finding_descriptions":[{"severity":"INFO","code":"c3"}]}]}`
	results, _, err := parseResultToken("pkilint", token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
}

func TestParseResultToken_JSONEmptyResults(t *testing.T) {
	results, end, err := parseResultToken("pkilint", `{"results":[]}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if end || len(results) != 0 {
		t.Errorf("expected no results and end=false, got end=%v results=%v", end, results)
	}
}

func TestParseResultToken_Malformed(t *testing.T) {
	// Empty and single-character tokens must not panic (regression: token[1]
	// used to be indexed before the length was checked).
	for _, token := range []string{"", "{", "x", "hello", "{bad json"} {
		if _, _, err := parseResultToken("pkilint", token); err == nil {
			t.Errorf("%q: expected an error, got nil", token)
		}
	}
}

// --- sendResult ---

func TestSendResult_DeadlineExceeded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Deadline already exceeded.
	lreq := &LintingRequest{
		Ctx:         ctx,
		RespChannel: make(chan LintingResult), // Unbuffered, no reader.
	}
	var lin LinterInstance
	if lin.sendResult(lreq, LintingResult{Finding: "x"}) {
		t.Error("sendResult should return false when the request deadline is exceeded")
	}
}

func TestSendResult_Delivered(t *testing.T) {
	lreq := &LintingRequest{
		Ctx:         context.Background(),
		RespChannel: make(chan LintingResult, 1),
	}
	var lin LinterInstance
	if !lin.sendResult(lreq, LintingResult{Finding: "x"}) {
		t.Fatal("sendResult should return true when the result is delivered")
	}
	if got := <-lreq.RespChannel; got.Finding != "x" {
		t.Errorf("got finding %q, want x", got.Finding)
	}
}

// --- serverLoop against a live subprocess backend ---
//
// These tests exercise serverLoop against a real subprocess backend that speaks
// pkimetal's stdin/stdout protocol, covering the clean, crash, backend-timeout,
// and client-gave-up (drain, no restart) paths.

const helperArg = "pkimetal-backend-helper"

// TestHelperProcess is not a real test: it is re-executed as a stub external
// linter backend.  It only activates when invoked with the helperArg sentinel,
// so during a normal `go test` run it is a no-op.
//
// Protocol: for each request it reads a profile-id line and an input line, then
// emits result token(s) terminated by the end-of-results sentinel.  The input
// line doubles as a behaviour marker.
func TestHelperProcess(t *testing.T) {
	if !slices.Contains(os.Args, helperArg) {
		return
	}
	if slices.Contains(os.Args, "warmup") {
		time.Sleep(400 * time.Millisecond) // Simulate slow initialisation.
		fmt.Println(PKIMETAL_READY)
	}
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() { // Profile-id line.
		if !in.Scan() { // Input line.
			break
		}
		switch in.Text() {
		case "CRASH": // Exit without emitting the sentinel (simulates a crash/desync).
			os.Exit(1)
		case "SLEEP": // Never respond in time (simulates a hang).
			time.Sleep(2 * time.Second)
		case "SLOWOK": // Respond, but only after the client is likely to have given up.
			time.Sleep(150 * time.Millisecond)
		}
		fmt.Println("E: ok")
		fmt.Println(PKIMETAL_ENDOFRESULTS)
	}
	os.Exit(0)
}

type stubBackend struct{}

func (stubBackend) StartInstance() (bool, string, string, []string) { return false, ".", "", nil }
func (stubBackend) StopInstance(*LinterInstance)                    {}
func (stubBackend) HandleRequest(context.Context, *LinterInstance, *LintingRequest) []LintingResult {
	return nil
}
func (stubBackend) ProcessResult(r LintingResult) LintingResult { return r }

// startStubBackend spawns the stub backend, runs serverLoop against it, and
// returns a stop function that tears both down.
func startStubBackend(t *testing.T, readySignal string, extraArgs ...string) (lin *LinterInstance, stop func()) {
	t.Helper()
	lin = &LinterInstance{
		Linter: &Linter{
			Name:                  "stub",
			Version:               "v0",
			ReqChannel:            make(chan LintingRequest, 8),
			ReadySignal:           readySignal,
			queueTimeSummary:      prometheus.NewSummary(prometheus.SummaryOpts{Name: "stub_queue"}),
			processingTimeSummary: prometheus.NewSummary(prometheus.SummaryOpts{Name: "stub_processing"}),
		},
		Mutex: &sync.Mutex{},
	}
	args := append([]string{"-test.run=TestHelperProcess", helperArg}, extraArgs...)
	lin.startInstance_external(".", os.Args[0], args...)

	ctx, cancel := context.WithCancel(context.Background())
	ShutdownWG.Add(1)
	go lin.serverLoop(ctx, stubBackend{})

	return lin, func() {
		cancel()
		ShutdownWG.Wait()
		if lin.command != nil && lin.command.Process != nil {
			_ = lin.command.Process.Kill()
			_ = lin.command.Wait()
		}
	}
}

// runLint submits one request and collects results until the end-of-results
// sentinel arrives or the request context is done.
func runLint(lin *LinterInstance, ctx context.Context, input string) []LintingResult {
	lreq := LintingRequest{
		Ctx:         ctx,
		B64Input:    input,
		ProfileId:   0,
		QueuedAt:    time.Now(),
		RespChannel: make(chan LintingResult),
	}
	lin.ReqChannel <- lreq

	var results []LintingResult
	for {
		select {
		case r := <-lreq.RespChannel:
			if r.LinterName == PKIMETAL_NAME && r.Finding == PKIMETAL_ENDOFRESULTS {
				return results
			}
			results = append(results, r)
		case <-ctx.Done():
			return results
		}
	}
}

func backendPID(lin *LinterInstance) int {
	if lin.command != nil && lin.command.Process != nil {
		return lin.command.Process.Pid
	}
	return -1
}

func hasResult(results []LintingResult, severity SeverityLevel, findingSubstr string) bool {
	for _, r := range results {
		if r.Severity == severity && strings.Contains(r.Finding, findingSubstr) {
			return true
		}
	}
	return false
}

func TestBackend_CleanRequest(t *testing.T) {
	lin, stop := startStubBackend(t, "")
	defer stop()
	pid := backendPID(lin)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results := runLint(lin, ctx, "hello")
	if !hasResult(results, SEVERITY_ERROR, "ok") {
		t.Errorf("expected an 'ok' result, got %+v", results)
	}
	if backendPID(lin) != pid {
		t.Error("backend should not have restarted on a clean request")
	}
}

func TestBackend_RestartsOnCrash(t *testing.T) {
	lin, stop := startStubBackend(t, "")
	defer stop()
	pid := backendPID(lin)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results := runLint(lin, ctx, "CRASH")
	if !hasResult(results, SEVERITY_FATAL, "stub") {
		t.Errorf("expected a FATAL result after a crash, got %+v", results)
	}
	if backendPID(lin) == pid {
		t.Error("backend should have restarted after a crash")
	}

	// The restarted backend must serve the next request.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if r := runLint(lin, ctx2, "hello"); !hasResult(r, SEVERITY_ERROR, "ok") {
		t.Errorf("restarted backend did not serve the next request: %+v", r)
	}
}

func TestBackend_RestartsOnBackendTimeout(t *testing.T) {
	saved := config.Config.Linter.BackendTimeout
	config.Config.Linter.BackendTimeout = 200 * time.Millisecond
	defer func() { config.Config.Linter.BackendTimeout = saved }()

	lin, stop := startStubBackend(t, "")
	defer stop()
	pid := backendPID(lin)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results := runLint(lin, ctx, "SLEEP")
	if !hasResult(results, SEVERITY_FATAL, "timed out") {
		t.Errorf("expected a backend-timeout FATAL, got %+v", results)
	}
	if backendPID(lin) == pid {
		t.Error("backend should have restarted after exceeding the backend timeout")
	}
}

func TestBackend_ClientGoneKeepsBackendWarm(t *testing.T) {
	lin, stop := startStubBackend(t, "")
	defer stop()
	pid := backendPID(lin)

	// Give up on the request before the (deliberately slow) backend responds.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_ = runLint(lin, ctx, "SLOWOK")

	// A follow-up request proves the backend drained the abandoned request and
	// stayed warm rather than being restarted.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if r := runLint(lin, ctx2, "hello"); !hasResult(r, SEVERITY_ERROR, "ok") {
		t.Errorf("backend did not serve the follow-up request: %+v", r)
	}
	if backendPID(lin) != pid {
		t.Error("backend should NOT restart when only the client gave up")
	}
}

func TestBackend_WarmUpAbsorbsSlowInit(t *testing.T) {
	savedTimeout := config.Config.Linter.BackendTimeout
	// A per-request timeout shorter than the stub's init; warm-up must absorb the init.
	config.Config.Linter.BackendTimeout = 200 * time.Millisecond
	defer func() { config.Config.Linter.BackendTimeout = savedTimeout }()

	lin, stop := startStubBackend(t, PKIMETAL_READY, "warmup")
	defer stop()
	pid := backendPID(lin)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Warm-up absorbs the slow init, so the request completes within the short
	// per-request backend timeout without a restart.
	results := runLint(lin, ctx, "hello")
	if !hasResult(results, SEVERITY_ERROR, "ok") {
		t.Errorf("expected an 'ok' result, got %+v", results)
	}
	if backendPID(lin) != pid {
		t.Error("backend should not have restarted; warm-up should absorb slow init")
	}
}
