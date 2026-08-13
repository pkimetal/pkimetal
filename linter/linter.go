package linter

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/logger"
	"github.com/pkimetal/pkimetal/utils"

	json "github.com/goccy/go-json"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/zmap/zcrypto/x509"

	"go.uber.org/zap"
)

type LinterInterface interface {
	StartInstance() (useHandleRequest bool, directory, cmd string, args []string)
	StopInstance(lin *LinterInstance)
	HandleRequest(ctx context.Context, lin *LinterInstance, lreq *LintingRequest) []LintingResult
	ProcessResult(lresult LintingResult) LintingResult
}

type Linter struct {
	Name                  string
	Version               string
	Url                   string
	Unsupported           []ProfileId
	NumInstances          int
	ReqChannel            chan LintingRequest
	ReadySignal           string // If set, an external backend emits this line once it has finished initialising.
	external              bool
	useHandleRequest      bool
	queueTimeSummary      prometheus.Summary
	processingTimeSummary prometheus.Summary
	Interface             func() LinterInterface
}

type LinterSlice []*Linter

type LinterInstance struct {
	*Linter
	instanceNumber int
	command        *exec.Cmd
	Mutex          *sync.Mutex
	Stdin          io.WriteCloser
	Stdout         *bufio.Scanner
	stderr         *bufio.Scanner
	stdinFile      *os.File // Underlying STDIN pipe, retained so that write deadlines can be set.
	stdoutFile     *os.File // Underlying STDOUT pipe, retained so that read deadlines can be set.
	directory      string   // Retained so that the backend can be restarted after a failure.
	cmd            string
	args           []string
}

type LintingRequest struct {
	Ctx            context.Context // Carries the per-request deadline through to the linter backends.
	B64Input       string
	DecodedInput   []byte
	Cert           *x509.Certificate
	ProfileId      ProfileId
	QueuedAt       time.Time
	ChecksAdded    []string
	ChecksDisabled []string
	RespChannel    chan LintingResult
}

type LintingResult struct {
	LinterName string
	Finding    string
	Field      string
	Code       string
	Severity   SeverityLevel
}

var (
	Linters         LinterSlice
	linterInstances []*LinterInstance
	ShutdownWG      sync.WaitGroup
)

const (
	PKIMETAL_NAME         = "pkimetal"
	PKIMETAL_ENDOFRESULTS = "[EndOfResults]"
	PKIMETAL_READY        = "[Ready]"
	NOT_INSTALLED         = "not installed"
)

func (l *Linter) Register() {
	Linters = append(Linters, l)
	if l.NumInstances > 0 {
		// Register this linter.
		logger.Logger.Info("Registering Linter", zap.Int("nInstances", l.NumInstances), zap.String("name", l.Name), zap.String("version", l.Version))
		registerLinterWithProfiles(l)
		l.ReqChannel = make(chan LintingRequest, config.Config.Linter.MaxQueueSize)

		// Preconfigure this linter's instances.
		baseInstanceNumber := len(linterInstances)
		for i := 0; i < l.NumInstances; i++ {
			linterInstances = append(linterInstances, &LinterInstance{
				Linter:         l,
				instanceNumber: baseInstanceNumber + i,
				Mutex:          &sync.Mutex{},
			})
		}

		l.queueTimeSummary = promauto.NewSummary(prometheus.SummaryOpts{
			Namespace:   config.ApplicationNamespace,
			Subsystem:   "linter",
			Name:        "queue_time",
			Help:        "Number of seconds before processing a linting request.",
			ConstLabels: map[string]string{"linter_name": l.Name},
		})
		l.processingTimeSummary = promauto.NewSummary(prometheus.SummaryOpts{
			Namespace:   config.ApplicationNamespace,
			Subsystem:   "linter",
			Name:        "processing_time",
			Help:        "Number of seconds to process a linting request.",
			ConstLabels: map[string]string{"linter_name": l.Name},
		})
	} else {
		logger.Logger.Info("Unused Linter", zap.String("name", l.Name))
	}
}

func (slice LinterSlice) Len() int {
	return len(slice)
}

func (slice LinterSlice) Less(i, j int) bool {
	return strings.Compare(slice[i].Name, slice[j].Name) < 0
}

func (slice LinterSlice) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func StartLinters(ctx context.Context) {
	generateOrderedListOfProfiles()

	// Sort the linters by name.
	sort.Sort(Linters)

	for _, lin := range linterInstances {
		if lif := lin.Interface(); lif != nil {
			logger.Logger.Info("Starting Linter", zap.Int("instance#", lin.instanceNumber), zap.String("name", lin.Name))

			// Start the linter backend.
			var directory, cmd string
			var args []string
			if lin.useHandleRequest, directory, cmd, args = lif.StartInstance(); len(cmd) > 0 {
				ShutdownWG.Add(1)
				lin.external = true
				lin.startInstance_external(directory, cmd, args...)
			}

			// Run the linter server loop.
			ShutdownWG.Add(1)
			go lin.serverLoop(ctx, lif)
		}
	}
}

func (lin *LinterInstance) startInstance_external(directory, cmd string, arg ...string) {
	// Retain the start parameters so that the backend can be restarted after a failure.
	lin.directory, lin.cmd, lin.args = directory, cmd, arg

	// Configure the linter backend so that it will run the linter in a forked process.
	lin.command = exec.Command(cmd, arg...)
	lin.command.Dir = directory

	// Set up pipes.
	var err error
	if lin.Stdin, err = lin.command.StdinPipe(); err != nil {
		logger.Logger.Fatal("Cmd.StdinPipe() failed", zap.Error(err), zap.String("cmd", cmd), zap.String("directory", directory), zap.String("name", lin.Name))
	}
	lin.stdinFile, _ = lin.Stdin.(*os.File)

	var stdout io.ReadCloser
	if stdout, err = lin.command.StdoutPipe(); err != nil {
		logger.Logger.Fatal("Cmd.StdoutPipe() failed", zap.Error(err), zap.String("cmd", cmd), zap.String("directory", directory), zap.String("name", lin.Name))
	}
	lin.Stdout = bufio.NewScanner(stdout)
	lin.stdoutFile, _ = stdout.(*os.File)

	var stderr io.ReadCloser
	if stderr, err = lin.command.StderrPipe(); err != nil {
		logger.Logger.Fatal("Cmd.StderrPipe() failed", zap.Error(err), zap.String("cmd", cmd), zap.String("directory", directory), zap.String("name", lin.Name))
	}
	lin.stderr = bufio.NewScanner(stderr)

	// Continuously log STDERR output as it is produced.
	go func(lin *LinterInstance) {
		for lin.stderr.Scan() {
			logger.Logger.Info("From stderr", zap.Int("instance#", lin.instanceNumber), zap.String("name", lin.Name), zap.String("text", lin.stderr.Text()))
		}
	}(lin)

	// Start the linter backend.
	lin.command.Start()
	if lin.command.Process == nil {
		logger.Logger.Fatal("Cmd.Start() failed", zap.Error(err), zap.String("cmd", cmd), zap.String("directory", directory), zap.String("name", lin.Name))
	}
}

func StopLinters(ctx context.Context) {
	// Stop the linter backends.
	for _, lin := range linterInstances {
		if lif := lin.Interface(); lif != nil {
			if lin.external {
				lin.stopInstance_external()
				ShutdownWG.Done()
			}

			lif.StopInstance(lin)

			logger.Logger.Info("Stopped Linter", zap.Int("instance#", lin.instanceNumber), zap.String("name", lin.Name))
		}
	}
}

func (lin *LinterInstance) stopInstance_external() {
	lin.Stdin.Close()

	if err := lin.command.Wait(); err != nil {
		logger.Logger.Error("Cmd.Wait failed", zap.Error(err), zap.Int("instance#", lin.instanceNumber), zap.String("name", lin.Name))
	}
}

// restartInstance_external kills the current backend process (which has hung,
// crashed, or desynced from the request/response protocol) and starts a fresh
// one, so that subsequent requests to this instance are not affected.  The
// caller must hold lin.Mutex.
func (lin *LinterInstance) restartInstance_external(reason error) {
	if lin.command != nil && lin.command.Process != nil {
		_ = lin.command.Process.Kill()
		_ = lin.command.Wait()
	}
	logger.Logger.Warn("Restarting Linter backend", zap.Int("instance#", lin.instanceNumber), zap.String("name", lin.Name), zap.Error(reason))
	lin.startInstance_external(lin.directory, lin.cmd, lin.args...)
	lin.warmUp()
}

// warmUp waits for an external backend that advertises a readiness signal to
// finish its (potentially slow) initialisation before it is sent any requests,
// so that start-up cost is not charged against a request's backend timeout.  It
// is a no-op for in-process backends and for backends with no ReadySignal.
func (lin *LinterInstance) warmUp() {
	if lin.ReadySignal == "" || lin.stdoutFile == nil {
		return
	}
	logger.Logger.Info("Warming up Linter backend", zap.Int("instance#", lin.instanceNumber), zap.String("name", lin.Name))
	// Wait (without a read deadline) for the backend to finish initialising and emit
	// its readiness signal.  A slow init - e.g. several backends initialising at once
	// under CPU contention - must not be cut short, otherwise the instance would be
	// restarted, re-initialised, and time out again in a cascade.  A backend that
	// crashes during init closes its STDOUT, which ends the scan.
	for lin.Stdout.Scan() {
		if lin.Stdout.Text() == lin.ReadySignal {
			logger.Logger.Info("Linter backend ready", zap.Int("instance#", lin.instanceNumber), zap.String("name", lin.Name))
			return
		}
	}
	logger.Logger.Error("Linter backend exited during warm-up", zap.Int("instance#", lin.instanceNumber), zap.String("name", lin.Name), zap.Error(lin.Stdout.Err()))
}

// sendResult sends a linting result to the request's response channel, unless
// the request's deadline is exceeded first.  It returns false if the deadline
// was exceeded, in which case the caller should stop processing the request.
func (lin *LinterInstance) sendResult(lreq *LintingRequest, lres LintingResult) bool {
	select {
	case lreq.RespChannel <- lres:
		return true
	case <-lreq.Ctx.Done():
		return false
	}
}

// parseResultToken parses a single response token emitted by an external linter
// backend on its STDOUT into zero or more linting results.  end is true for the
// end-of-results sentinel.  Two wire formats are supported: the certlint /
// x509lint "S: description" format and pkilint's JSON format.
func parseResultToken(linterName, token string) (results []LintingResult, end bool, err error) {
	if token == PKIMETAL_ENDOFRESULTS {
		end = true
		return
	}
	if len(token) < 2 {
		err = fmt.Errorf("unexpected response token: '%s'", token)
		return
	}

	if token[1] == ':' { // Certlint/x509lint response format.
		if len(token) < 4 {
			err = fmt.Errorf("description of finding is unexpectedly short: '%s'", token)
			return
		}
		lresult := LintingResult{
			LinterName: linterName,
			Finding:    token[3:],
		}
		switch token[0:3] {
		case "D: ":
			lresult.Severity = SEVERITY_DEBUG
		case "I: ":
			lresult.Severity = SEVERITY_INFO
		case "N: ":
			lresult.Severity = SEVERITY_NOTICE
		case "W: ":
			lresult.Severity = SEVERITY_WARNING
		case "E: ":
			lresult.Severity = SEVERITY_ERROR
		case "B: ":
			lresult.Severity = SEVERITY_BUG
		case "F: ":
			lresult.Severity = SEVERITY_FATAL
		default:
			err = fmt.Errorf("unexpected linting result: '%s'", token)
			return
		}
		results = append(results, lresult)
		return

	} else if token[0] == '{' { // JSON response format.
		type findingDescription struct {
			Severity string `json:"severity"`
			Code     string `json:"code"`
			Message  string `json:"message"`
		}
		type pkilintResult struct {
			NodePath            string               `json:"node_path"`
			Validator           string               `json:"validator"`
			FindingDescriptions []findingDescription `json:"finding_descriptions"`
		}
		type pkilintResults struct {
			Results []pkilintResult `json:"results"`
		}
		var pr pkilintResults
		if err = json.Unmarshal(utils.S2B(token), &pr); err != nil {
			return
		}
		for _, r := range pr.Results {
			for _, fd := range r.FindingDescriptions {
				results = append(results, LintingResult{
					LinterName: linterName,
					Finding:    fd.Code,
					Field:      r.NodePath,
					Code:       fd.Code,
					Severity:   Severity[strings.ToLower(fd.Severity)],
				})
			}
		}
		return
	}

	err = fmt.Errorf("unknown response format: '%s'", token)
	return
}

func (lin *LinterInstance) serverLoop(ctx context.Context, lif LinterInterface) {
	// Wait for a slow-initialising backend to become ready before serving, so that
	// its one-time start-up cost is not charged against the first request's backend
	// timeout (which would otherwise cause a restart, re-init, timeout cascade).
	lin.warmUp()

	for {
		select {
		case lreq := <-lin.ReqChannel: // Multiple backends can share the same request channel, but only one backend will receive each request.
			// Acquire mutex.  Each internal or external backend will only process one linting request at a time.
			lin.Mutex.Lock()

			// Skip requests whose deadline has already passed (e.g. whilst queued);
			// the client has stopped waiting, so there is no point processing them.
			if lreq.Ctx.Err() != nil {
				lin.Mutex.Unlock()
				continue
			}

			// Record how long this linting request was queued for.
			queuedFor := time.Since(lreq.QueuedAt)
			start := time.Now()

			if lin.useHandleRequest {
				// Process this linting request in-process, bounded by the request's deadline.
				for _, lres := range lif.HandleRequest(lreq.Ctx, lin, &lreq) {
					lres.LinterName = lin.Name
					if !lin.sendResult(&lreq, lres) {
						break
					}
				}

			} else {
				// Bound the subprocess I/O by a backend timeout measured from now, so
				// that time spent queued does not count against the backend and a
				// slow-but-healthy backend is not restarted just because the client
				// gave up.
				backendDeadline := time.Now().Add(config.Config.Linter.BackendTimeout)
				if lin.stdinFile != nil {
					_ = lin.stdinFile.SetWriteDeadline(backendDeadline)
				}
				if lin.stdoutFile != nil {
					_ = lin.stdoutFile.SetReadDeadline(backendDeadline)
				}

				var err error
				clientGone := false
			label_forloop:
				// Write the request to the linter backend's STDIN.
				for _, err = lin.Stdin.Write(utils.S2B(fmt.Sprintf("%d\n%s\n", lreq.ProfileId, strings.TrimSpace(lreq.B64Input)))); err == nil; {
					// Scan the next token from the linter backend's STDOUT.
					if !lin.Stdout.Scan() {
						if err = lin.Stdout.Err(); err == nil {
							err = fmt.Errorf("stdout.Scan() => false")
						}
						break label_forloop
					}

					// Parse the response token from the linter backend's STDOUT into linting result(s).
					var results []LintingResult
					var end bool
					if results, end, err = parseResultToken(lin.Name, lin.Stdout.Text()); err != nil || end {
						break label_forloop
					}
					for _, lresult := range results {
						// Deliver results whilst the client is still waiting.  Once it
						// has given up, keep reading the backend to completion so that
						// the backend stays in sync and warm, but stop delivering.
						if clientGone {
							continue
						}
						if !lin.sendResult(&lreq, lif.ProcessResult(lresult)) {
							clientGone = true
						}
					}
				}
				// Clear the subprocess I/O deadlines.
				if lin.stdinFile != nil {
					_ = lin.stdinFile.SetWriteDeadline(time.Time{})
				}
				if lin.stdoutFile != nil {
					_ = lin.stdoutFile.SetReadDeadline(time.Time{})
				}

				// A non-nil error means the backend crashed, desynced, or exceeded the
				// backend timeout: report it (if the client is still waiting) and
				// restart the backend so that subsequent requests are unaffected.  A
				// client that merely gave up whilst the backend was healthy does not
				// trigger a restart.
				if err != nil {
					if !clientGone {
						finding := fmt.Sprintf("%s: %v", lin.Name, err)
						if os.IsTimeout(err) {
							finding = fmt.Sprintf("%s: linting backend timed out", lin.Name)
						}
						lin.sendResult(&lreq, LintingResult{
							LinterName: PKIMETAL_NAME,
							Severity:   SEVERITY_FATAL,
							Finding:    finding,
						})
					}
					lin.restartInstance_external(err)
				}
			}
			// Record meta information.
			runtime := time.Since(start)
			lin.sendResult(&lreq, LintingResult{
				LinterName: lin.Name,
				Severity:   SEVERITY_META,
				Finding:    fmt.Sprintf("Queued: %v; Runtime: %v; Version: %s", queuedFor, runtime, VersionString(lin.Version)),
			})
			lin.queueTimeSummary.Observe(float64(queuedFor) / float64(time.Second))
			lin.processingTimeSummary.Observe(float64(runtime) / float64(time.Second))

			// Add a dummy linting result to signal the end of the results.
			lin.sendResult(&lreq, LintingResult{
				LinterName: PKIMETAL_NAME,
				Severity:   SEVERITY_META,
				Finding:    PKIMETAL_ENDOFRESULTS,
			})

			lin.Mutex.Unlock()

		// Respond to graceful shutdown requests.
		case <-ctx.Done():
			ShutdownWG.Done()
			return
		}
	}
}

func GetPackageVersion(packageNamePrefix string) string {
	// Extract the package version from the build info embedded into the executable.
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, m := range bi.Deps {
			if strings.HasPrefix(m.Path, packageNamePrefix) {
				return m.Version
			}
		}
	}

	return NOT_INSTALLED
}

func VersionString(version string) string {
	if version == NOT_INSTALLED {
		return "[" + version + "]"
	} else if strings.Contains(version, "-g") {
		// git describe format: v0.0.0-0-gabcdef1
		return version
	} else if idx := strings.LastIndex(version, "-"); idx != -1 && len(version)-idx > 7 {
		// go.mod version format: v0.0.0-20210101000000-abcdef123456
		return version
	} else if strings.Contains(version, ".") {
		// Stable version format: v0.0.0
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
		return version
	} else if len(version) >= 7 {
		// Git commit hash format: abcdef123456...
		return "g" + version[0:7]
	} else {
		return "(" + version + ")"
	}
}

func GetPackagePath() string {
	// Extract the package's repository URL from the build info embedded into the executable.
	if bi, ok := debug.ReadBuildInfo(); ok {
		return bi.Path
	}
	return ""
}
