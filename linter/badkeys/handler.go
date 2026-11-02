package badkeys

import (
	"context"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/linter/badkeys/worker"
)

type Badkeys struct{}

var Version, PythonDir string

func init() {
	if config.Config.Linter.Badkeys.NumProcesses > 0 {
		// Get badkeys package details, either embedded during the build process or from pipx; if requested in the config, autodetect the site-packages directory.
		if Version != "" {
			config.Config.Linter.Badkeys.PythonDir = PythonDir
		} else {
			Version, config.Config.Linter.Badkeys.PythonDir = linter.GetPackageDetailsFromPipx("badkeys", config.Config.Linter.Badkeys.PythonDir)
		}

		switch config.Config.Linter.Badkeys.PythonDir {
		case "", "autodetect":
			panic("badkeys: PythonDir must be set")
		}
	}

	// Register badkeys.
	(&linter.Linter{
		Name:         "badkeys",
		Version:      Version,
		Url:          "https://github.com/badkeys/badkeys",
		Unsupported:  linter.NonCertificateProfileIDs,
		NumInstances: config.Config.Linter.Badkeys.NumProcesses,
		Interface:    func() linter.LinterInterface { return &Badkeys{} },
	}).Register()
}

func (l *Badkeys) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	// Start badkeys server and configure STDIN/STDOUT pipes.
	return false, config.Config.Linter.Badkeys.PythonDir, "python3",
		[]string{"-c", worker.Script}
}

func (l *Badkeys) StopInstance(lin *linter.LinterInstance) {
}

func (l *Badkeys) HandleRequest(ctx context.Context, lin *linter.LinterInstance, lreq *linter.LintingRequest) []linter.LintingResult {
	// Not used.
	return nil
}

func (l *Badkeys) ProcessResult(lresult linter.LintingResult) linter.LintingResult {
	return lresult
}
