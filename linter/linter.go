package linter

import (
	"bufio"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/logger"
	"github.com/pkimetal/pkimetal/utils"

	json "github.com/goccy/go-json"

	"go.uber.org/zap"
)

type LinterInterface interface {
	StartInstance() (useHandleRequest bool, directory, cmd string, args []string)
	StopInstance(lin *LinterInstance)
	HandleRequest(lin *LinterInstance, lreq *LintingRequest, ctx context.Context) []LintingResult
}

type Linter struct {
	Name             string
	Version          string
	Url              string
	Unsupported      []ProfileId
	NumInstances     int
	ReqChannel       chan LintingRequest
	external         bool
	useHandleRequest bool
	Interface        func() LinterInterface
}

type LinterInstance struct {
	*Linter
	instanceNumber int
	command        *exec.Cmd
	Mutex          *sync.Mutex
	Stdin          io.WriteCloser
	Stdout         *bufio.Scanner
	stderr         *bufio.Scanner
}

type LintingRequest struct {
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
	Field      string
	Finding    string
	Severity   SeverityLevel
}

var (
	Linters         []*Linter
	linterInstances []*LinterInstance
	ShutdownWG      sync.WaitGroup
)

const (
	PKIMETAL_NAME         = "pkimetal"
	PKIMETAL_ENDOFRESULTS = "[EndOfResults]"
	NOT_INSTALLED         = "not installed"
)

func (l *Linter) Register() {
	Linters = append(Linters, l)
	if l.NumInstances > 0 {
		// Register this linter.
		logger.Logger.Info(
			"Registering Linter",
			zap.Int("nInstances", l.NumInstances),
			zap.String("name", l.Name),
		)
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
	} else {
		logger.Logger.Info(
			"Unused Linter",
			zap.String("name", l.Name),
		)
	}
}

func StartLinters(ctx context.Context) {
	for _, lin := range linterInstances {
		if lif := lin.Interface(); lif != nil {
			logger.Logger.Info(
				"Starting Linter",
				zap.Int("instance#", lin.instanceNumber),
				zap.String("name", lin.Name),
			)

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
			go lin.serverLoop(lif, ctx)
		}
	}
}

func (lin *LinterInstance) startInstance_external(directory, cmd string, arg ...string) {
	// Configure the linter backend so that it will run the linter in a forked process.
	lin.command = exec.Command(cmd, arg...)
	lin.command.Dir = directory

	// Set up pipes.
	var err error
	if lin.Stdin, err = lin.command.StdinPipe(); err != nil {
		logger.Logger.Fatal(
			"Cmd.StdinPipe() failed",
			zap.Error(err),
			zap.String("cmd", cmd),
			zap.String("directory", directory),
			zap.String("name", lin.Name),
		)
	}

	var stdout io.ReadCloser
	if stdout, err = lin.command.StdoutPipe(); err != nil {
		logger.Logger.Fatal(
			"Cmd.StdoutPipe() failed",
			zap.Error(err),
			zap.String("cmd", cmd),
			zap.String("directory", directory),
			zap.String("name", lin.Name),
		)
	}
	lin.Stdout = bufio.NewScanner(stdout)

	var stderr io.ReadCloser
	if stderr, err = lin.command.StderrPipe(); err != nil {
		logger.Logger.Fatal(
			"Cmd.StderrPipe() failed",
			zap.Error(err),
			zap.String("cmd", cmd),
			zap.String("directory", directory),
			zap.String("name", lin.Name),
		)
	}
	lin.stderr = bufio.NewScanner(stderr)

	// Start the linter backend.
	lin.command.Start()
	if lin.command.Process == nil {
		logger.Logger.Fatal(
			"Cmd.Start() failed",
			zap.Error(err),
			zap.String("cmd", cmd),
			zap.String("directory", directory),
			zap.String("name", lin.Name),
		)
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

			logger.Logger.Info(
				"Stopped Linter",
				zap.Int("instance#", lin.instanceNumber),
				zap.String("name", lin.Name),
			)
		}
	}
}

func (lin *LinterInstance) stopInstance_external() {
	lin.Stdin.Close()

	// Log any STDERR output from the linter backend.
	for lin.stderr.Scan() {
		logger.Logger.Info(
			"From stderr",
			zap.Int("instance#", lin.instanceNumber),
			zap.String("name", lin.Name),
			zap.String("text", lin.stderr.Text()),
		)
	}

	if err := lin.command.Wait(); err != nil {
		logger.Logger.Error(
			"Cmd.Wait failed",
			zap.Error(err),
			zap.Int("instance#", lin.instanceNumber),
			zap.String("name", lin.Name),
		)
	}
}

func (lin *LinterInstance) serverLoop(lif LinterInterface, ctx context.Context) {
	for {
		select {
		case lreq := <-lin.ReqChannel: // Multiple backends can share the same request channel, but only one backend will receive each request.
			// Acquire mutex.  Each internal or external backend will only process one linting request at a time.
			lin.Mutex.Lock()

			// Record how long this linting request was queued for.
			queuedFor := time.Since(lreq.QueuedAt)
			start := time.Now()

			if lin.useHandleRequest {
				// Process this linting request in-process.
				for _, lres := range lif.HandleRequest(lin, &lreq, ctx) {
					lres.LinterName = lin.Name
					lreq.RespChannel <- lres
				}

			} else {
				var err error
			label_forloop:
				// Write the request to the linter backend's STDIN.
				for _, err = lin.Stdin.Write(utils.S2B(fmt.Sprintf("%d\n%s\n", lreq.ProfileId, strings.TrimSpace(lreq.B64Input)))); err == nil; {
					// Scan the next token from the linter backend's STDOUT.
					if !lin.Stdout.Scan() {
						err = fmt.Errorf("stdout.Scan() => false")
						break label_forloop
					}

					// Read the scanned response token from the linter backend's STDOUT.
					token := lin.Stdout.Text()
					// Process this response token, and produce linting result(s).
					if token == PKIMETAL_ENDOFRESULTS {
						break label_forloop
					} else if token[1] == ':' { // Certlint/x509lint response format.
						if len(token) < 4 {
							err = fmt.Errorf("description of finding is unexpectedly short: '%s'", token)
							break label_forloop
						}
						lresult := LintingResult{
							LinterName: lin.Name,
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
							break label_forloop
						}
						// Send this linting result to the response channel.
						lreq.RespChannel <- lresult
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
							break label_forloop
						} else {
							for _, r := range pr.Results {
								for _, fd := range r.FindingDescriptions {
									lresult := LintingResult{
										LinterName: lin.Name,
										Field:      r.NodePath,
										Finding:    fd.Code,
										Severity:   Severity[strings.ToLower(fd.Severity)],
									}

									// Send this linting result to the response channel.
									lreq.RespChannel <- lresult
								}
							}
						}

					} else {
						err = fmt.Errorf("unknown response format: '%s'", token)
						break label_forloop

					}
				}
				// Handle any errors that occurred during the request.
				if err != nil {
					lreq.RespChannel <- LintingResult{
						LinterName: PKIMETAL_NAME,
						Severity:   SEVERITY_FATAL,
						Finding:    fmt.Sprintf("%s: %v", lin.Name, err),
					}
				}
			}
			// Record meta information.
			lreq.RespChannel <- LintingResult{
				LinterName: lin.Name,
				Severity:   SEVERITY_META,
				Finding:    fmt.Sprintf("Queued: %v; Runtime: %v; Version: %s", queuedFor, time.Since(start), VersionString(lin.Version)),
			}

			// Add a dummy linting result to signal the end of the results.
			lreq.RespChannel <- LintingResult{
				LinterName: PKIMETAL_NAME,
				Severity:   SEVERITY_META,
				Finding:    PKIMETAL_ENDOFRESULTS,
			}

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
				return strings.TrimPrefix(m.Version, "v")
			}
		}
	}

	return NOT_INSTALLED
}

func GetPackageVersionOrGitDescribeTagsAlways(packageName, gitDescribeTagsAlways string) string {
	if packageVersion := GetPackageVersion(packageName); packageVersion == gitDescribeTagsAlways {
		return packageVersion
	} else if idx := strings.LastIndex(packageVersion, "-"); idx == -1 {
		return packageVersion
	} else if idx2 := strings.LastIndex(gitDescribeTagsAlways, "-g"); idx2 == -1 {
		return packageVersion
	} else {
		packageGitCommit := packageVersion[idx+1:]
		gitDescCommit := gitDescribeTagsAlways[idx2+2:]
		var length int
		if len(packageGitCommit) < len(gitDescCommit) {
			length = len(packageGitCommit)
		} else {
			length = len(gitDescCommit)
		}

		if packageGitCommit[:length] == gitDescCommit[:length] {
			return gitDescribeTagsAlways
		} else {
			return packageVersion
		}
	}
}

func VersionString(version string) string {
	if version == NOT_INSTALLED {
		return "[" + version + "]"
	} else if strings.Contains(version, "-g") {
		// git describe format: v0.0.0-0-gabcdef1
		return version
	} else if idx := strings.LastIndex(version, "-"); idx != -1 && len(version)-idx > 7 {
		// go.mod version format: v0.0.0-20210101000000-abcdef123456
		return "g" + version[idx+1:idx+8]
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
