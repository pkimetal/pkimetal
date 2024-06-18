package dwklint

import (
	"context"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"

	"github.com/CVE-2008-0166/dwklint"
)

type Dwklint struct{}

func init() {
	if err := dwklint.LoadBlocklists(config.Config.Linter.Dwklint.BlocklistDir); err != nil {
		panic(err)
	}

	// Register dwklint.
	(&linter.Linter{
		Name:         "dwklint",
		Version:      linter.GetPackageVersion("github.com/CVE-2008-0166/dwklint"),
		Unsupported:  linter.NonCertificateProfileIDs,
		NumInstances: config.Config.Linter.Dwklint.NumGoroutines,
		Interface:    func() linter.LinterInterface { return &Dwklint{} },
	}).Register()
}

func (l *Dwklint) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	return true, "", "", nil // dwklint is run in Goroutine(s) in the pkimetal process, so there are no "external" instances.
}

func (l *Dwklint) StopInstance(lin *linter.LinterInstance) {
}

func (l *Dwklint) HandleRequest(lin *linter.LinterInstance, lreq *linter.LintingRequest, ctx context.Context) []linter.LintingResult {
	var lres linter.LintingResult
	dwkStatus := dwklint.HasDebianWeakKey(lreq.Cert)
	switch dwkStatus {
	case dwklint.NotWeak:
		lres.Severity = linter.SEVERITY_INFO
		lres.Finding = "Public Key is not a Debian weak key"
	case dwklint.UnknownButTLSBRExceptionGranted:
		lres.Severity = linter.SEVERITY_NOTICE
		lres.Finding = "No Debian weak key blocklist is available for this key algorithm/size, but Public Key is larger than RSA-8192"
	case dwklint.Unknown:
		lres.Severity = linter.SEVERITY_WARNING
		lres.Finding = "No Debian weak key blocklist is available for this key algorithm/size"
	case dwklint.Weak:
		lres.Severity = linter.SEVERITY_ERROR
		lres.Finding = "Public Key is a Debian weak key"
	case dwklint.Error:
		lres.Severity = linter.SEVERITY_FATAL
		lres.Finding = "Public Key could not be decoded for Debian weak key check"
	default:
		lres.Severity = linter.SEVERITY_FATAL
		lres.Finding = "Unexpected response from Debian weak key check"
	}
	return []linter.LintingResult{lres}
}
