package zlint

import (
	"context"
	"fmt"
	"slices"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/logger"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"

	"go.uber.org/zap"
)

type Zlint struct{}

var (
	defaultRegistry         lint.Registry
	cabforumTLSLeafRegistry lint.Registry
	notCabforumRegistry     lint.Registry
)

func init() {
	// Register Zlint.
	(&linter.Linter{
		Name:         "zlint",
		Version:      linter.GetPackageVersion("github.com/zmap/zlint"),
		Url:          "https://github.com/zmap/zlint",
		Unsupported:  linter.OcspProfileIDs,
		NumInstances: config.Config.Linter.Zlint.NumGoroutines,
		Interface:    func() linter.LinterInterface { return &Zlint{} },
	}).Register()

	defaultRegistry = lint.GlobalRegistry()

	// RFC5280's "SHOULD be present" for SKI in end-entity certificates is superseded by the TLS BRs' "NOT RECOMMENDED".
	var err error
	if cabforumTLSLeafRegistry, err = defaultRegistry.Filter(lint.FilterOptions{
		ExcludeNames: []string{"w_ext_subject_key_identifier_missing_sub_cert"},
	}); err != nil {
		logger.Logger.Fatal("Failed to configure filtered Zlint registry for BR/EVG TLS Server leaf certificates", zap.Error(err))
	}

	// Filter out CABForum lints for non-CABForum profiles.
	if notCabforumRegistry, err = defaultRegistry.Filter(lint.FilterOptions{
		ExcludeSources: []lint.LintSource{
			lint.CABFBaselineRequirements,
			lint.CABFEVGuidelines,
			lint.CABFSMIMEBaselineRequirements,
		},
	}); err != nil {
		logger.Logger.Fatal("Failed to configure filtered Zlint registry for disabling CABForum lints", zap.Error(err))
	}
}

func (l *Zlint) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	return true, "", "", nil // Zlint is run in Goroutine(s) in the pkimetal process, so there are no external backends.
}

func (l *Zlint) StopInstance(lin *linter.LinterInstance) {
}

func lintCert(lreq *linter.LintingRequest, registry *lint.Registry) []linter.LintingResult {
	var lres []linter.LintingResult
	if cert, err := x509.ParseCertificate(lreq.DecodedInput); err != nil {
		lres = append(lres, linter.LintingResult{
			Severity: linter.SEVERITY_FATAL,
			Finding:  fmt.Sprintf("Could not parse certificate: %v", err),
		})
	} else {
		zlintResultSet := zlint.LintCertificateEx(cert, *registry)
		for k, v := range zlintResultSet.Results {
			lresult := linter.LintingResult{
				Finding: defaultRegistry.CertificateLints().ByName(k).Description,
			}
			switch v.Status {
			case lint.Notice:
				lresult.Severity = linter.SEVERITY_NOTICE
			case lint.Warn:
				lresult.Severity = linter.SEVERITY_WARNING
			case lint.Error:
				lresult.Severity = linter.SEVERITY_ERROR
			case lint.Fatal:
				lresult.Severity = linter.SEVERITY_FATAL
			default:
				continue
			}
			lres = append(lres, lresult)
		}
	}
	return lres
}

func lintCRL(lreq *linter.LintingRequest, registry *lint.Registry) []linter.LintingResult {
	var lres []linter.LintingResult
	if crl, err := x509.ParseRevocationList(lreq.DecodedInput); err != nil {
		lres = append(lres, linter.LintingResult{
			Severity: linter.SEVERITY_FATAL,
			Finding:  fmt.Sprintf("Could not parse CRL: %v", err),
		})
	} else {
		zlintResultSet := zlint.LintRevocationListEx(crl, *registry)
		for k, v := range zlintResultSet.Results {
			lresult := linter.LintingResult{
				Finding: defaultRegistry.RevocationListLints().ByName(k).Description,
			}
			switch v.Status {
			case lint.Notice:
				lresult.Severity = linter.SEVERITY_NOTICE
			case lint.Warn:
				lresult.Severity = linter.SEVERITY_WARNING
			case lint.Error:
				lresult.Severity = linter.SEVERITY_ERROR
			case lint.Fatal:
				lresult.Severity = linter.SEVERITY_FATAL
			default:
				continue
			}
			lres = append(lres, lresult)
		}
	}
	return lres
}

func (l *Zlint) HandleRequest(lin *linter.LinterInstance, lreq *linter.LintingRequest, ctx context.Context) []linter.LintingResult {
	var registry *lint.Registry
	var ok bool
	if slices.Contains(linter.TbrTevgLeafProfileIDs, lreq.ProfileId); ok {
		registry = &cabforumTLSLeafRegistry
	} else if slices.Contains(linter.NonCabforumProfileIDs, lreq.ProfileId); ok {
		registry = &notCabforumRegistry
	} else {
		registry = &defaultRegistry
	}

	if slices.Contains(linter.CrlProfileIDs, lreq.ProfileId); ok {
		return lintCRL(lreq, registry)
	} else {
		return lintCert(lreq, registry)
	}
}
