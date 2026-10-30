package section7

import (
	"context"
	"crypto/x509"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"

	"github.com/cps-kit/section7"
)

type Section7 struct{}

var profiles *section7.ProfileSet

func init() {
	if config.Config.Linter.Section7.NumGoroutines > 0 {
		var err error
		profiles, err = section7.LoadProfileSet(config.Config.Linter.Section7.ProfilesDir)
		if err != nil {
			panic("section7: " + err.Error())
		}
	}

	(&linter.Linter{
		Name:         "section7",
		Version:      linter.GetPackageVersion("github.com/cps-kit/section7"),
		Url:          "https://github.com/cps-kit/section7",
		Unsupported:  linter.NonCertificateProfileIDs,
		NumInstances: config.Config.Linter.Section7.NumGoroutines,
		Interface:    func() linter.LinterInterface { return &Section7{} },
	}).Register()
}

func (backend *Section7) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	return true, "", "", nil // section7 is run in Goroutine(s) in the pkimetal process, so there are no "external" instances.
}

func (backend *Section7) StopInstance(instance *linter.LinterInstance) {
}

func (backend *Section7) HandleRequest(ctx context.Context, instance *linter.LinterInstance, request *linter.LintingRequest) []linter.LintingResult {
	cert, err := x509.ParseCertificate(request.DecodedInput)
	if err != nil {
		return []linter.LintingResult{{Severity: linter.SEVERITY_FATAL, Finding: "Failed to parse certificate: " + err.Error()}}
	}
	return lintCertificate(ctx, cert, profiles)
}

func lintCertificate(ctx context.Context, cert *x509.Certificate, candidates *section7.ProfileSet) []linter.LintingResult {
	if ctx.Err() != nil {
		return nil
	}
	path, findings := candidates.LintCertificate(cert)
	results := make([]linter.LintingResult, 0, len(findings))
	for _, finding := range findings {
		severity := linter.SEVERITY_INFO
		switch finding.Severity {
		case section7.Error:
			severity = linter.SEVERITY_ERROR
		case section7.Warning:
			severity = linter.SEVERITY_WARNING
		}
		results = append(results, linter.LintingResult{
			Severity: severity,
			Code:     finding.RuleID,
			Finding:  finding.Message,
			Field:    path,
		})
	}
	return results
}

func (backend *Section7) ProcessResult(result linter.LintingResult) linter.LintingResult {
	return result
}
