package pwnedkeys

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
)

type Pwnedkeys struct{}

var httpClient http.Client

func init() {
	httpClient = http.Client{
		Timeout: config.Config.Linter.Pwnedkeys.HTTPTimeout,
	}

	// Register pwnedkeys.
	(&linter.Linter{
		Name:         "pwnedkeys",
		Version:      "1.0.0",
		Url:          "https://pwnedkeys.com/api/v1",
		Unsupported:  linter.NonCertificateProfileIDs,
		NumInstances: config.Config.Linter.Pwnedkeys.NumGoroutines,
		Interface:    func() linter.LinterInterface { return &Pwnedkeys{} },
	}).Register()
}

func (l *Pwnedkeys) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	return true, "", "", nil // The pwnedkeys API is called from Goroutine(s) in the pkimetal process, so there are no "external" instances.
}

func (l *Pwnedkeys) StopInstance(lin *linter.LinterInstance) {
}

func (l *Pwnedkeys) HandleRequest(lin *linter.LinterInstance, lreq *linter.LintingRequest, ctx context.Context) []linter.LintingResult {
	var lres []linter.LintingResult
	var httpRequest *http.Request
	var err error
	s := sha256.Sum256(lreq.Cert.RawSubjectPublicKeyInfo)
	if httpRequest, err = http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://v1.pwnedkeys.com/%s", hex.EncodeToString(s[:])), nil); err != nil {
		lres = append(lres, linter.LintingResult{
			Severity: linter.Severity[config.Config.Linter.Pwnedkeys.APIErrorSeverity],
			Finding:  err.Error(),
		})
		return lres
	}

	httpRequest.Header.Set("User-Agent", linter.PKIMETAL_NAME)
	httpRequest.Header.Set("Accept", "application/pkcs10")
	var httpResponse *http.Response
	if httpResponse, err = httpClient.Do(httpRequest); err != nil {
		if os.IsTimeout(err) {
			lres = append(lres, linter.LintingResult{
				Severity: linter.Severity[config.Config.Linter.Pwnedkeys.TimeoutSeverity],
				Finding:  "API request timed out",
			})
		} else {
			lres = append(lres, linter.LintingResult{
				Severity: linter.Severity[config.Config.Linter.Pwnedkeys.APIErrorSeverity],
				Finding:  err.Error(),
			})
		}
		return lres
	}

	defer httpResponse.Body.Close()
	switch httpResponse.StatusCode {
	case http.StatusOK:
		var body []byte
		var req *x509.CertificateRequest
		if body, err = io.ReadAll(httpResponse.Body); err == nil {
			if req, err = x509.ParseCertificateRequest(body); err == nil {
				if err = req.CheckSignature(); err == nil {
					lres = append(lres, linter.LintingResult{
						Severity: linter.SEVERITY_ERROR,
						Finding:  "Public key is pwned",
					})
					break
				}
			}
		}
		lres = append(lres, linter.LintingResult{
			Severity: linter.Severity[config.Config.Linter.Pwnedkeys.APIErrorSeverity],
			Finding:  err.Error(),
		})
	case http.StatusNotFound:
		lres = append(lres, linter.LintingResult{
			Severity: linter.SEVERITY_INFO,
			Finding:  "Public Key is not pwned",
		})
	case http.StatusTooManyRequests:
		lres = append(lres, linter.LintingResult{
			Severity: linter.Severity[config.Config.Linter.Pwnedkeys.RateLimitSeverity],
			Finding:  "API request was rate limited",
		})
	default:
		lres = append(lres, linter.LintingResult{
			Severity: linter.Severity[config.Config.Linter.Pwnedkeys.APIErrorSeverity],
		})
	}

	return lres
}

func (l *Pwnedkeys) ProcessResult(lresult linter.LintingResult) linter.LintingResult {
	return lresult
}
