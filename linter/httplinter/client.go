package httplinter

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"

	json "github.com/goccy/go-json"
)

// maxResponseSize is the largest response body accepted from an endpoint: the
// same limit that applies to the output of pkimetal's external linter backends.
const maxResponseSize = 16 << 20

// HTTPLinter is the backend for one configured HTTP linter endpoint.  It is
// shared by all of the endpoint's Goroutines.
type HTTPLinter struct {
	client          *http.Client
	url             string
	headers         map[string]string
	errorSeverity   linter.SeverityLevel
	timeoutSeverity linter.SeverityLevel
}

// request is the JSON body sent to an endpoint.  The field names match the
// parameters of pkimetal's own lint endpoints (see doc/openapi.yaml).
type request struct {
	B64Input string `json:"b64input"`
	Profile  string `json:"profile"`
	Artifact string `json:"artifact"`
}

// finding is one element of an endpoint's response.  The field names match
// LintFinding in doc/openapi.yaml; any "Linter" value is ignored.
type finding struct {
	Finding  string
	Field    string
	Code     string
	Severity string
}

// newClient returns the HTTP client for one endpoint.  Redirects are not
// followed, so that configured headers (e.g. credentials) are never sent to
// another URL.
func newClient(timeout time.Duration, maxConns int, scheme string, tlsCfg config.HTTPLinterTLSConfig) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if maxConns > 0 {
		transport.MaxIdleConnsPerHost = maxConns
	}
	if tlsCfg != (config.HTTPLinterTLSConfig{}) {
		if scheme != "https" {
			return nil, errors.New("tls is only valid for https URLs")
		}
		tlsConfig, err := loadTLSConfig(tlsCfg)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConfig
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func loadTLSConfig(cfg config.HTTPLinterTLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		caPEM, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("tls.caFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("tls.caFile %s: no PEM certificates found", cfg.CAFile)
		}
		tlsConfig.RootCAs = pool
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, errors.New("tls.certFile and tls.keyFile must be set together")
	}
	if cfg.CertFile != "" {
		clientCert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}
	return tlsConfig, nil
}

// lint sends one artifact to the endpoint and returns its findings or, if the
// request fails or the response is invalid, a single finding describing why.
func (l *HTTPLinter) lint(ctx context.Context, req request) []linter.LintingResult {
	body, err := json.Marshal(req)
	if err != nil {
		return l.failure(err.Error())
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, l.url, bytes.NewReader(body))
	if err != nil {
		return l.failure(err.Error())
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("User-Agent", linter.PKIMETAL_NAME)
	for name, value := range l.headers {
		httpRequest.Header.Set(name, value)
	}

	httpResponse, err := l.client.Do(httpRequest)
	if err != nil {
		return l.requestError(err)
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK {
		return l.failure("API request failed: HTTP " + httpResponse.Status)
	}

	responseBody, err := io.ReadAll(io.LimitReader(httpResponse.Body, maxResponseSize+1))
	if err != nil {
		return l.requestError(err)
	}
	if len(responseBody) > maxResponseSize {
		return l.failure("invalid API response: larger than 16 MiB")
	}
	results, err := parseFindings(responseBody)
	if err != nil {
		return l.failure("invalid API response: " + err.Error())
	}
	return results
}

func (l *HTTPLinter) requestError(err error) []linter.LintingResult {
	if os.IsTimeout(err) || errors.Is(err, context.DeadlineExceeded) {
		return []linter.LintingResult{{Severity: l.timeoutSeverity, Finding: "API request timed out"}}
	}
	// Report the cause without the endpoint URL, which may contain a secret.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	return l.failure(err.Error())
}

func (l *HTTPLinter) failure(message string) []linter.LintingResult {
	return []linter.LintingResult{{Severity: l.errorSeverity, Finding: message}}
}

// parseFindings converts an endpoint's response body into linting results.  An
// invalid response is rejected as a whole, so that endpoint authors notice.
func parseFindings(body []byte) ([]linter.LintingResult, error) {
	var findings []finding
	if err := json.Unmarshal(body, &findings); err != nil {
		return nil, err
	}
	if findings == nil { // "null" decodes without error.
		return nil, errors.New("response is not a JSON array")
	}
	results := make([]linter.LintingResult, 0, len(findings))
	for i, f := range findings {
		if f.Finding == "" {
			return nil, fmt.Errorf("finding %d has no Finding", i)
		}
		severity, ok := linter.Severity[strings.ToLower(f.Severity)]
		if !ok || severity == linter.SEVERITY_META { // The empty string maps to META.
			return nil, fmt.Errorf("finding %d has invalid Severity %q", i, f.Severity)
		}
		results = append(results, linter.LintingResult{
			Severity: severity,
			Finding:  f.Finding,
			Field:    f.Field,
			Code:     f.Code,
		})
	}
	return results, nil
}
