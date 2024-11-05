package dwklint

import (
	"context"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"

	dwklint "github.com/CVE-2008-0166/dwklint/v2"
)

type Dwklint struct{}

var BlocklistDBPath string

func init() {
	if config.Config.Linter.Dwklint.BlocklistDBPath != "" {
		BlocklistDBPath = config.Config.Linter.Dwklint.BlocklistDBPath
	}

	// dwklint's database connection can only be used by one goroutine at time, so multiple backends cannot be supported.
	switch config.Config.Linter.Dwklint.NumGoroutines {
	case 0:
	case 1:
		if BlocklistDBPath == "" {
			panic("dwklint: blocklistDBPath must be set")
		} else if err := dwklint.OpenBlocklistDatabase(BlocklistDBPath); err != nil {
			panic("dwklint: " + err.Error())
		}
	default:
		panic("dwklint: numGoroutines must be 0 or 1")
	}

	// Register dwklint.
	(&linter.Linter{
		Name:         "dwklint",
		Version:      linter.GetPackageVersion("github.com/CVE-2008-0166/dwklint/v2"),
		Url:          "https://github.com/CVE-2008-0166/dwklint",
		Unsupported:  linter.NonCertificateProfileIDs,
		NumInstances: config.Config.Linter.Dwklint.NumGoroutines,
		Interface:    func() linter.LinterInterface { return &Dwklint{} },
	}).Register()
}

func (l *Dwklint) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	return true, "", "", nil // dwklint is run in Goroutine(s) in the pkimetal process, so there are no "external" instances.
}

func (l *Dwklint) StopInstance(lin *linter.LinterInstance) {
	if lin.NumInstances > 0 {
		dwklint.CloseBlocklistDatabase()
	}
}

func (l *Dwklint) HandleRequest(ctx context.Context, lin *linter.LinterInstance, lreq *linter.LintingRequest) []linter.LintingResult {
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

func (l *Dwklint) ProcessResult(lresult linter.LintingResult) linter.LintingResult {
	return lresult
}
