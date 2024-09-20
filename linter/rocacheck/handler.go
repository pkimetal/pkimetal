package rocacheck

import (
	"context"
	"crypto/rsa"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"

	"github.com/titanous/rocacheck"
)

type Rocacheck struct{}

func init() {
	// Register rocacheck.
	(&linter.Linter{
		Name:         "rocacheck",
		Version:      linter.GetPackageVersion("github.com/titanous/rocacheck"),
		Url:          "https://github.com/titanous/rocacheck",
		Unsupported:  linter.NonCertificateProfileIDs,
		NumInstances: config.Config.Linter.Rocacheck.NumGoroutines,
		Interface:    func() linter.LinterInterface { return &Rocacheck{} },
	}).Register()
}

func (l *Rocacheck) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	return true, "", "", nil // rocacheck is run in Goroutine(s) in the pkimetal process, so there are no "external" instances.
}

func (l *Rocacheck) StopInstance(lin *linter.LinterInstance) {
}

func (l *Rocacheck) HandleRequest(lin *linter.LinterInstance, lreq *linter.LintingRequest, ctx context.Context) []linter.LintingResult {
	lres := linter.LintingResult{
		Severity: linter.SEVERITY_INFO,
		Finding:  "Public Key is not a ROCA weak key",
	}
	switch lreq.Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if rocacheck.IsWeak(lreq.Cert.PublicKey.(*rsa.PublicKey)) {
			lres.Severity = linter.SEVERITY_ERROR
			lres.Finding = "Public Key is a ROCA weak key"
		}
	}
	return []linter.LintingResult{lres}
}

func (l *Rocacheck) ProcessResult(lresult linter.LintingResult) linter.LintingResult {
	return lresult
}
