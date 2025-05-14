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

	"golang.org/x/crypto/ocsp"
)

type Zlint struct{}

var (
	defaultRegistry                lint.Registry
	cabforumTLSSubordinateRegistry lint.Registry
	cabforumTLSLeafRegistry        lint.Registry
	notCabforumRegistry            lint.Registry
)

func init() {
	// Register zlint.
	(&linter.Linter{
		Name:         "zlint",
		Version:      linter.GetPackageVersion("github.com/zmap/zlint"),
		Url:          "https://github.com/zmap/zlint",
		Unsupported:  nil,
		NumInstances: config.Config.Linter.Zlint.NumGoroutines,
		Interface:    func() linter.LinterInterface { return &Zlint{} },
	}).Register()

	defaultRegistry = lint.GlobalRegistry()

	// RFC5280's "MUST mark this extension as critical" for Name Constraints in intermediate certificates is superseded by the TLS BRs' "MAY be marked non‐critical".
	var err error
	if cabforumTLSSubordinateRegistry, err = defaultRegistry.Filter(lint.FilterOptions{
		ExcludeNames: []string{"e_ext_name_constraints_not_critical"},
	}); err != nil {
		logger.Logger.Fatal("Failed to configure filtered zlint registry for BR/EVG TLS Server subordinate certificates", zap.Error(err))
	}

	// RFC5280's "SHOULD be present" for SKI in end-entity certificates is superseded by the TLS BRs' "NOT RECOMMENDED".
	if cabforumTLSLeafRegistry, err = defaultRegistry.Filter(lint.FilterOptions{
		ExcludeNames: []string{"w_ext_subject_key_identifier_missing_sub_cert"},
	}); err != nil {
		logger.Logger.Fatal("Failed to configure filtered zlint registry for BR/EVG TLS Server leaf certificates", zap.Error(err))
	}

	// Filter out CABForum lints for non-CABForum profiles.
	if notCabforumRegistry, err = defaultRegistry.Filter(lint.FilterOptions{
		ExcludeSources: []lint.LintSource{
			lint.CABFBaselineRequirements,
			lint.CABFEVGuidelines,
			lint.CABFSMIMEBaselineRequirements,
		},
	}); err != nil {
		logger.Logger.Fatal("Failed to configure filtered zlint registry for disabling CABForum lints", zap.Error(err))
	}
}

func (l *Zlint) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	return true, "", "", nil // zlint is run in Goroutine(s) in the pkimetal process, so there are no external backends.
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
			certificateLint := defaultRegistry.CertificateLints().ByName(k)
			lresult := linter.LintingResult{
				Finding: certificateLint.Description,
				Code:    certificateLint.Name,
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
			crlLint := defaultRegistry.RevocationListLints().ByName(k)
			lresult := linter.LintingResult{
				Finding: crlLint.Description,
				Code:    crlLint.Name,
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

func lintOCSPResponse(lreq *linter.LintingRequest, registry *lint.Registry) []linter.LintingResult {
	var lres []linter.LintingResult
	if ocspResponse, err := ocsp.ParseResponse(lreq.DecodedInput, nil); err != nil {
		lres = append(lres, linter.LintingResult{
			Severity: linter.SEVERITY_FATAL,
			Finding:  fmt.Sprintf("Could not parse OCSP Response: %v", err),
		})
	} else {
		zlintResultSet := zlint.LintOcspResponseEx(ocspResponse, *registry)
		for k, v := range zlintResultSet.Results {
			ocspResponseLint := defaultRegistry.OcspResponseLints().ByName(k)
			lresult := linter.LintingResult{
				Finding: ocspResponseLint.Description,
				Code:    ocspResponseLint.Name,
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

func (l *Zlint) HandleRequest(ctx context.Context, lin *linter.LinterInstance, lreq *linter.LintingRequest) []linter.LintingResult {
	var registry *lint.Registry
	if slices.Contains(linter.TbrTevgLeafProfileIDs, lreq.ProfileId) {
		registry = &cabforumTLSLeafRegistry
	} else if slices.Contains(linter.TbrTevgCertificateProfileIDs, lreq.ProfileId) {
		registry = &cabforumTLSSubordinateRegistry
	} else if slices.Contains(linter.NonCabforumProfileIDs, lreq.ProfileId) {
		registry = &notCabforumRegistry
	} else {
		registry = &defaultRegistry
	}

	if slices.Contains(linter.OcspProfileIDs, lreq.ProfileId) {
		return lintOCSPResponse(lreq, registry)
	} else if slices.Contains(linter.CrlProfileIDs, lreq.ProfileId) {
		return lintCRL(lreq, registry)
	} else {
		return lintCert(lreq, registry)
	}
}

func (l *Zlint) ProcessResult(lresult linter.LintingResult) linter.LintingResult {
	return lresult
}
