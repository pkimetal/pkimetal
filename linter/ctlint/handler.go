package ctlint

import (
	"context"
	"slices"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/logger"

	"github.com/crtsh/ctlint"
	"github.com/crtsh/ctloglists"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Ctlint struct{}

var _ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
	Namespace: config.ApplicationNamespace,
	Subsystem: "loglist",
	Name:      "oldest_timestamp_age_seconds",
	Help:      "Age in seconds of the oldest log list timestamp among lists with a 70-day enforcement cut-off.",
}, func() float64 {
	oldest := ctloglists.OldestTimestampForLogListWithEnforcementCutOff()
	if oldest.IsZero() {
		return 0
	}
	return time.Since(oldest).Seconds()
})

func init() {
	if err := ctloglists.LoadLogLists(); err != nil {
		logger.Logger.Fatal("ctlint: " + err.Error())
	}

	// Register ctlint.
	(&linter.Linter{
		Name:         "ctlint",
		Version:      linter.GetPackageVersion("github.com/crtsh/ctlint"),
		Url:          "https://github.com/crtsh/ctlint",
		Unsupported:  linter.NonCertificateProfileIDs,
		NumInstances: config.Config.Linter.Ctlint.NumGoroutines,
		Interface:    func() linter.LinterInterface { return &Ctlint{} },
	}).Register()
}

func (l *Ctlint) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	return true, "", "", nil // ctlint is run in Goroutine(s) in the pkimetal process, so there are no "external" instances.
}

func (l *Ctlint) StopInstance(lin *linter.LinterInstance) {
}

func (l *Ctlint) HandleRequest(ctx context.Context, lin *linter.LinterInstance, lreq *linter.LintingRequest) []linter.LintingResult {
	var lres []linter.LintingResult

	cert, err := x509.ParseCertificate(lreq.Cert.Raw)
	if err != nil {
		return []linter.LintingResult{{Severity: linter.SEVERITY_FATAL, Finding: "Failed to parse certificate: " + err.Error()}}
	}

	var results []string
	if slices.Contains(linter.PrecertificateProfileIDs, lreq.ProfileId) {
		results = ctlint.CheckPrecertificate(cert)
	} else if slices.Contains(linter.TbrTevgLeafProfileIDs, lreq.ProfileId) {
		results = ctlint.CheckCertificate(cert, nil, ctlint.ServerAuthenticationCertificate)
	} else if slices.Contains(linter.MarkCertificateProfileIDs, lreq.ProfileId) {
		results = ctlint.CheckCertificate(cert, nil, ctlint.MarkCertificate)
	} else {
		results = ctlint.CheckCertificate(cert, nil)
	}

	for _, result := range results {
		lresult := linter.LintingResult{
			Finding: result[3:],
		}
		switch result[0:3] {
		case "I: ":
			lresult.Severity = linter.SEVERITY_INFO
		case "N: ":
			lresult.Severity = linter.SEVERITY_NOTICE
		case "W: ":
			lresult.Severity = linter.SEVERITY_WARNING
		case "E: ":
			lresult.Severity = linter.SEVERITY_ERROR
		case "B: ":
			lresult.Severity = linter.SEVERITY_BUG
		case "F: ":
			lresult.Severity = linter.SEVERITY_FATAL
		default:
			continue
		}
		lres = append(lres, lresult)
	}

	return lres
}

func (l *Ctlint) ProcessResult(lresult linter.LintingResult) linter.LintingResult {
	return lresult
}
