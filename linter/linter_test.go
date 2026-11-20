package linter

import (
	"bufio"
	"context"
	"fmt"
	"io"
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

func TestLineScannerOversizedLineDrainsAndContinues(t *testing.T) {
	scanner := newLineScanner(strings.NewReader("12345678901234567\n[EndOfResults]\nnext"), 16)

	if !scanner.Scan() || !scanner.Oversized() {
		t.Fatal("expected the first line to be reported as oversized")
	}
	if scanner.Text() != "1234567890123456" || scanner.Size() != 17 {
		t.Fatalf("oversized line: got text=%q size=%d, want the first 16 bytes and size 17", scanner.Text(), scanner.Size())
	}
	if scanner.Err() != nil {
		t.Fatalf("unexpected scanner error after oversized line: %v", scanner.Err())
	}
	if !scanner.Scan() || scanner.Oversized() || scanner.Text() != PKIMETAL_ENDOFRESULTS {
		t.Fatalf("scanner did not resume at end-of-results: text=%q oversized=%v", scanner.Text(), scanner.Oversized())
	}
	if !scanner.Scan() || scanner.Oversized() || scanner.Text() != "next" {
		t.Fatalf("scanner did not continue after end-of-results: text=%q oversized=%v", scanner.Text(), scanner.Oversized())
	}
	if scanner.Scan() {
		t.Fatal("scanner returned an unexpected line after the final line")
	}
	if scanner.Err() != io.EOF {
		t.Fatalf("expected EOF after final line, got %v", scanner.Err())
	}
}

func TestLineScannerSpansReadBuffer(t *testing.T) {
	// Lines longer than the internal read buffer must be assembled across reads,
	// both when they fit the limit and when they exceed it.
	fits := strings.Repeat("a", 3*stdoutLineBufferSize)
	tooLong := strings.Repeat("b", 3*stdoutLineBufferSize+1)
	scanner := newLineScanner(strings.NewReader(fits+"\n"+tooLong+"\nnext\r\n"), len(fits))

	if !scanner.Scan() || scanner.Oversized() || scanner.Text() != fits {
		t.Fatalf("line at the limit: oversized=%v len=%d, want %d bytes", scanner.Oversized(), len(scanner.Text()), len(fits))
	}
	if !scanner.Scan() || !scanner.Oversized() || scanner.Text() != tooLong[:len(fits)] || scanner.Size() != len(tooLong) {
		t.Fatalf("line over the limit: oversized=%v len=%d size=%d", scanner.Oversized(), len(scanner.Text()), scanner.Size())
	}
	if !scanner.Scan() || scanner.Text() != "next" {
		t.Fatalf("scanner did not continue after an oversized line: text=%q", scanner.Text())
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
		case "OVERSIZED": // Emit a response line beyond the production stdout limit.
			fmt.Println(strings.Repeat("x", maxStdoutLineSize+1))
		case "STDERRFLOOD": // An over-long stderr line, then more stderr than a pipe buffer holds.
			fmt.Fprintln(os.Stderr, strings.Repeat("x", maxStderrLineSize+1))
			for range 1024 {
				fmt.Fprintln(os.Stderr, strings.Repeat("y", 1023))
			}
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

func TestExternalStdinWriteDeadline(t *testing.T) {
	lin := &LinterInstance{Linter: &Linter{Name: "stub"}}
	lin.startInstance_external(".", os.Args[0], "-test.run=TestHelperProcess", helperArg)
	defer func() {
		_ = lin.command.Process.Kill()
		_ = lin.command.Wait()
	}()

	if lin.stdinFile == nil {
		t.Fatalf("stdin pipe %T does not support write deadlines", lin.Stdin)
	}
	if err := lin.stdinFile.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("setting stdin write deadline: %v", err)
	}
	if _, err := io.WriteString(lin.Stdin, "0\nhello\n"); !os.IsTimeout(err) {
		t.Fatalf("write with expired deadline: got %v, want a timeout", err)
	}
	if err := lin.stdinFile.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing stdin write deadline: %v", err)
	}
	if _, err := io.WriteString(lin.Stdin, "0\nhello\n"); err != nil {
		t.Fatalf("write after clearing deadline: %v", err)
	}
	if err := lin.stdoutFile.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("setting stdout read deadline: %v", err)
	}
	if !lin.Stdout.Scan() || lin.Stdout.Text() != "E: ok" {
		t.Fatalf("unexpected backend response: %q, error: %v", lin.Stdout.Text(), lin.Stdout.Err())
	}
}

type stubBackend struct{}

func (stubBackend) StartInstance() (bool, string, string, []string) { return false, ".", "", nil }
func (stubBackend) StopInstance(*LinterInstance)                    {}
func (stubBackend) HandleRequest(context.Context, *LinterInstance, *LintingRequest) []LintingResult {
	return nil
}
func (stubBackend) ProcessResult(r LintingResult) LintingResult { return r }

type panickingBackend struct{ stubBackend }

func (panickingBackend) HandleRequest(_ context.Context, _ *LinterInstance, lreq *LintingRequest) []LintingResult {
	if lreq.B64Input == "PANIC" {
		panic("boom")
	}
	return []LintingResult{{Severity: SEVERITY_ERROR, Finding: "ok"}}
}

type failingInProcessBackend struct {
	stubBackend
	calls        int
	initialPID   int
	restartedPID int
}

func (b *failingInProcessBackend) HandleRequestWithError(_ context.Context, lin *LinterInstance, _ *LintingRequest) ([]LintingResult, error) {
	b.calls++
	if b.calls == 1 {
		b.initialPID = lin.command.Process.Pid
		return nil, fmt.Errorf("worker response mismatch")
	}
	b.restartedPID = lin.command.Process.Pid
	return []LintingResult{{Severity: SEVERITY_ERROR, Finding: "ok"}}, nil
}

func TestInProcess_RecoversFromPanic(t *testing.T) {
	lin := &LinterInstance{
		Linter: &Linter{
			Name:                  "inproc",
			Version:               "v0",
			ReqChannel:            make(chan LintingRequest, 8),
			useHandleRequest:      true,
			queueTimeSummary:      prometheus.NewSummary(prometheus.SummaryOpts{Name: "inproc_queue"}),
			processingTimeSummary: prometheus.NewSummary(prometheus.SummaryOpts{Name: "inproc_processing"}),
		},
		Mutex: &sync.Mutex{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	ShutdownWG.Add(1)
	go func() {
		lin.serverLoop(ctx, panickingBackend{})
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reqCancel()
	if r := runLint(lin, reqCtx, "PANIC"); !hasResult(r, SEVERITY_FATAL, "Recovered from panic") {
		t.Errorf("expected a FATAL panic result, got %+v", r)
	}

	// The instance must still serve the next request.
	if r := runLint(lin, reqCtx, "hello"); !hasResult(r, SEVERITY_ERROR, "ok") {
		t.Errorf("instance did not serve the next request: %+v", r)
	}
}

func TestInProcess_RestartsExternalWorkerOnHandlerError(t *testing.T) {
	backend := &failingInProcessBackend{}
	lin := &LinterInstance{
		Linter: &Linter{
			Name:                  "stub",
			Version:               "v0",
			ReqChannel:            make(chan LintingRequest, 8),
			useHandleRequest:      true,
			external:              true,
			queueTimeSummary:      prometheus.NewSummary(prometheus.SummaryOpts{Name: "stub_error_queue"}),
			processingTimeSummary: prometheus.NewSummary(prometheus.SummaryOpts{Name: "stub_error_processing"}),
		},
		Mutex:     &sync.Mutex{},
		directory: ".",
		cmd:       os.Args[0],
		args:      []string{"-test.run=TestHelperProcess", helperArg},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	ShutdownWG.Add(1)
	go func() {
		lin.serverLoop(ctx, backend)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
		if lin.command != nil && lin.command.Process != nil {
			_ = lin.command.Process.Kill()
			_ = lin.command.Wait()
		}
	}()

	reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reqCancel()
	if results := runLint(lin, reqCtx, "first"); !hasResult(results, SEVERITY_FATAL, "worker response mismatch") {
		t.Fatalf("expected a fatal handler error, got %+v", results)
	}
	if results := runLint(lin, reqCtx, "second"); !hasResult(results, SEVERITY_ERROR, "ok") {
		t.Fatalf("instance did not serve a request after restart: %+v", results)
	}
	if backend.initialPID == backend.restartedPID {
		t.Errorf("worker process was not restarted: pid %d", backend.initialPID)
	}
}

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
	done := make(chan struct{})
	ShutdownWG.Add(1)
	go func() {
		lin.serverLoop(ctx, stubBackend{})
		close(done)
	}()

	return lin, func() {
		cancel()
		<-done
		if lin.command != nil && lin.command.Process != nil {
			_ = lin.command.Process.Kill()
			_ = lin.command.Wait()
		}
	}
}

// startExternalStub runs a stub backend via serverLoop's own (serialised) start
// path (external = true) rather than starting it manually, so serverLoop owns the
// process lifecycle and the returned stop function only cancels the loop.
func startExternalStub(t *testing.T, readySignal string, extraArgs ...string) (lin *LinterInstance, stop func()) {
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
	lin.external = true
	lin.directory = "."
	lin.cmd = os.Args[0]
	lin.args = append([]string{"-test.run=TestHelperProcess", helperArg}, extraArgs...)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	ShutdownWG.Add(1)
	go func() {
		lin.serverLoop(ctx, stubBackend{})
		close(done)
	}()

	return lin, func() {
		cancel()
		<-done
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

func TestBackend_OversizedResponseDoesNotRestart(t *testing.T) {
	lin, stop := startStubBackend(t, "")
	defer stop()
	pid := backendPID(lin)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := runLint(lin, ctx, "OVERSIZED")
	if !hasResult(results, SEVERITY_FATAL, ErrResponseTooLong.Error()) {
		t.Fatalf("expected a FATAL result for oversized response, got %+v", results)
	}
	if backendPID(lin) != pid {
		t.Fatal("backend should not have restarted after an oversized response")
	}
	if results = runLint(lin, ctx, "hello"); !hasResult(results, SEVERITY_ERROR, "ok") {
		t.Errorf("backend did not serve the next request after an oversized response: %+v", results)
	}
}

func TestBackend_OversizedStderrLineKeepsBackendResponsive(t *testing.T) {
	saved := config.Config.Linter.BackendTimeout
	config.Config.Linter.BackendTimeout = 5 * time.Second
	defer func() { config.Config.Linter.BackendTimeout = saved }()

	lin, stop := startStubBackend(t, "")
	defer stop()
	pid := backendPID(lin)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// If the stderr reader stopped at the over-long line, the backend would block
	// writing the rest of its stderr and the request would time out.
	if r := runLint(lin, ctx, "STDERRFLOOD"); !hasResult(r, SEVERITY_ERROR, "ok") || hasResult(r, SEVERITY_FATAL, "") {
		t.Fatalf("backend did not complete a request after an over-long stderr line: %+v", r)
	}
	if backendPID(lin) != pid {
		t.Error("backend should not have restarted after an over-long stderr line")
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

func TestBackend_ExternalLifecycle(t *testing.T) {
	lin, stop := startExternalStub(t, PKIMETAL_READY, "warmup")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// serverLoop forks and warms up the backend before serving.
	r := runLint(lin, ctx, "hello")
	stop() // Cancels the loop, which tears down the backend process.

	if !hasResult(r, SEVERITY_ERROR, "ok") {
		t.Errorf("expected an 'ok' result via the external path, got %+v", r)
	}
	if lin.command == nil || lin.command.ProcessState == nil {
		t.Error("backend process should have been torn down on shutdown")
	}
}

func TestBackend_InitialisationIsSerialised(t *testing.T) {
	// Two backends that each sleep ~400ms during init.  Serialised initialisation
	// takes ~800ms; if it ran in parallel it would take ~400ms.
	start := time.Now()
	lin1, stop1 := startExternalStub(t, PKIMETAL_READY, "warmup")
	defer stop1()
	lin2, stop2 := startExternalStub(t, PKIMETAL_READY, "warmup")
	defer stop2()

	var wg sync.WaitGroup
	for _, lin := range []*LinterInstance{lin1, lin2} {
		wg.Add(1)
		go func(l *LinterInstance) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			runLint(l, ctx, "hello")
		}(lin)
	}
	wg.Wait()

	if elapsed := time.Since(start); elapsed < 700*time.Millisecond {
		t.Errorf("initialisation does not appear serialised: both backends ready in %v (expected >= ~800ms)", elapsed)
	}
}

func TestRegister_RejectsDuplicateName(t *testing.T) {
	saved := Linters
	t.Cleanup(func() { Linters = saved })

	(&Linter{Name: "duplicate-test"}).Register() // NumInstances 0: no instances or metrics are created.
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), `linter "duplicate-test" is already registered`) {
			t.Fatalf("expected a duplicate-name panic, got %v", r)
		}
	}()
	(&Linter{Name: "duplicate-test"}).Register()
}
