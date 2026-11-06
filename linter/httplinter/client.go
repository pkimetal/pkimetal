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
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/logger"

	json "github.com/goccy/go-json"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// maxResponseSize is the largest response body accepted from an endpoint: the
// same limit that applies to the output of pkimetal's external linter backends.
const maxResponseSize = 16 << 20

// failuresTotal counts failed requests to HTTP linter endpoints, by linter and
// reason, so that an unavailable or misbehaving endpoint can be noticed and
// alerted on.
// Reasons for a failed request, as recorded in failuresTotal and the log.
const (
	reasonRequest    = "request"    // The request could not be built.
	reasonConnection = "connection" // The endpoint could not be reached, or the connection failed.
	reasonTimeout    = "timeout"    // The endpoint accepted the request but did not answer in time.
	reasonStatus     = "status"     // The endpoint answered with a status other than 200.
	reasonResponse   = "response"   // The endpoint's response was invalid.
)

var failuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: config.ApplicationNamespace,
	Subsystem: "linter",
	Name:      "http_failures_total",
	Help:      "Number of failed requests to HTTP linter endpoints.",
}, []string{"linter_name", "reason"})

// HTTPLinter is the backend for one configured HTTP linter endpoint.  It is
// shared by all of the endpoint's Goroutines.
type HTTPLinter struct {
	name            string
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
		return l.failure(reasonRequest, err.Error())
	}
	// Record whether a connection was obtained, so that an unreachable endpoint
	// is reported as such even when connecting times out.
	var connected atomic.Bool
	traceCtx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { connected.Store(true) },
	})
	httpRequest, err := http.NewRequestWithContext(traceCtx, http.MethodPost, l.url, bytes.NewReader(body))
	if err != nil {
		return l.failure(reasonRequest, err.Error())
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("User-Agent", linter.PKIMETAL_NAME)
	for name, value := range l.headers {
		httpRequest.Header.Set(name, value)
	}

	httpResponse, err := l.client.Do(httpRequest)
	if err != nil {
		return l.requestError(ctx, err, connected.Load())
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK {
		return l.failure(reasonStatus, "API request failed: HTTP "+httpResponse.Status)
	}

	responseBody, err := io.ReadAll(io.LimitReader(httpResponse.Body, maxResponseSize+1))
	if err != nil {
		return l.requestError(ctx, err, true)
	}
	if len(responseBody) > maxResponseSize {
		return l.failure(reasonResponse, "invalid API response: larger than 16 MiB")
	}
	results, err := parseFindings(responseBody)
	if err != nil {
		return l.failure(reasonResponse, "invalid API response: "+err.Error())
	}
	return results
}

// requestError describes a request that did not complete.  ctx is the context of
// pkimetal's own request; connected reports whether a connection to the
// endpoint was obtained.
func (l *HTTPLinter) requestError(ctx context.Context, err error, connected bool) []linter.LintingResult {
	if ctx.Err() != nil {
		// pkimetal's request was cancelled or reached its deadline, so this result
		// will not be used.  It is not a failure of the endpoint.
		return []linter.LintingResult{{Severity: l.timeoutSeverity, Finding: "API request abandoned"}}
	}
	timedOut := os.IsTimeout(err) || errors.Is(err, context.DeadlineExceeded)
	switch {
	case !connected && timedOut:
		// e.g. a firewall silently dropping packets: as unreachable as a refused
		// connection, so it is reported at the same severity.
		return l.failure(reasonConnection, "API request failed: could not connect within the timeout")
	case !connected:
		return l.failure(reasonConnection, "API request failed: could not connect: "+errorCause(err))
	case timedOut:
		l.record(reasonTimeout, "API request timed out")
		return []linter.LintingResult{{Severity: l.timeoutSeverity, Finding: "API request timed out"}}
	default:
		return l.failure(reasonConnection, "API request failed: "+errorCause(err))
	}
}

// errorCause returns err's message without the endpoint URL, which may contain a
// secret.
func errorCause(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	return err.Error()
}

func (l *HTTPLinter) failure(reason, message string) []linter.LintingResult {
	l.record(reason, message)
	return []linter.LintingResult{{Severity: l.errorSeverity, Finding: message}}
}

// record logs and counts a failed request.
func (l *HTTPLinter) record(reason, message string) {
	failuresTotal.WithLabelValues(l.name, reason).Inc()
	logger.Logger.Warn("HTTP linter request failed", zap.String("name", l.name), zap.String("reason", reason), zap.String("finding", message))
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
