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
	"strconv"
	"sync"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
)

type Pwnedkeys struct{}

type PwnedkeysTransport struct {
	http.RoundTripper
}

func (pt *PwnedkeysTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", linter.PKIMETAL_NAME)
	req.Header.Set("Accept", "application/pkcs10")
	return pt.RoundTripper.RoundTrip(req)
}

var httpClient http.Client
var retryAfterMutex sync.RWMutex
var retryAfter time.Time

func init() {
	httpClient = http.Client{
		Timeout:   config.Config.Linter.Pwnedkeys.HTTPTimeout,
		Transport: &PwnedkeysTransport{RoundTripper: http.DefaultTransport},
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

func (l *Pwnedkeys) HandleRequest(ctx context.Context, lin *linter.LinterInstance, lreq *linter.LintingRequest) []linter.LintingResult {
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

	retryAfterMutex.RLock()
	currentlyRateLimited := retryAfter.After(time.Now())
	retryAfterMutex.RUnlock()
	if currentlyRateLimited {
		lres = append(lres, linter.LintingResult{
			Severity: linter.Severity[config.Config.Linter.Pwnedkeys.RateLimitSeverity],
			Finding:  "API requests are currently rate limited",
		})
		return lres
	}

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
					return lres
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
		respectRetryAfter(httpResponse.Header.Get("Retry-After"))
		lres = append(lres, linter.LintingResult{
			Severity: linter.Severity[config.Config.Linter.Pwnedkeys.RateLimitSeverity],
			Finding:  "API request was rate limited",
		})
	default:
		lres = append(lres, linter.LintingResult{
			Severity: linter.Severity[config.Config.Linter.Pwnedkeys.APIErrorSeverity],
			Finding:  "API request failed: HTTP " + httpResponse.Status,
		})
	}

	return lres
}

func (l *Pwnedkeys) ProcessResult(lresult linter.LintingResult) linter.LintingResult {
	return lresult
}

func respectRetryAfter(retryAfterHeader string) {
	if retryAfterHeader != "" {
		var ra time.Time
		if i, err := strconv.Atoi(retryAfterHeader); err == nil {
			ra = time.Now().Add(time.Second * time.Duration(i))
		} else if ra, err = time.Parse(time.RFC1123, retryAfterHeader); err != nil {
			return
		}

		retryAfterMutex.Lock()
		if ra.After(retryAfter) {
			retryAfter = ra
		}
		retryAfterMutex.Unlock()
	}
}
