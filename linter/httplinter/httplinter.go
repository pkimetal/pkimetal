// Package httplinter registers HTTP linters: external endpoints, declared under
// linter.httpLinters in config.yaml, that pkimetal sends each artifact to and
// whose findings it reports.  See doc/linters/http.md.
package httplinter

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
)

// Values accepted in an HTTP linter's "artifacts" list, and sent as "artifact".
const (
	ArtifactCertificate = "certificate"
	ArtifactCRL         = "crl"
	ArtifactOCSP        = "ocsp"
)

const (
	defaultNumGoroutines   = 1
	defaultTimeout         = 5 * time.Second
	defaultErrorSeverity   = linter.SEVERITYSTRING_BUG
	defaultTimeoutSeverity = linter.SEVERITYSTRING_NOTICE
)

func init() {
	linters, err := buildLinters(config.Config.Linter.HTTPLinters)
	if err != nil {
		panic("httplinter: " + err.Error())
	}
	for _, l := range linters {
		l.Register() // Register panics if the name clashes with any other linter's.
	}
}

// buildLinters validates the HTTP linter declarations and converts each one into
// a linter.Linter, ready to be registered.
func buildLinters(cfgs []config.HTTPLinterConfig) ([]*linter.Linter, error) {
	var linters []*linter.Linter
	seen := make(map[string]bool)
	for i, cfg := range cfgs {
		if cfg.Name == "" {
			return nil, fmt.Errorf("linter.httpLinters[%d]: name is required", i)
		}
		if cfg.Name == linter.PKIMETAL_NAME {
			// pkimetal's own results (e.g. its end-of-results marker) use this name.
			return nil, fmt.Errorf("linter.httpLinters[%d]: name %q is reserved", i, cfg.Name)
		}
		if seen[cfg.Name] {
			return nil, fmt.Errorf("http linter %q: declared more than once", cfg.Name)
		}
		seen[cfg.Name] = true

		l, err := buildLinter(cfg)
		if err != nil {
			return nil, fmt.Errorf("http linter %q: %w", cfg.Name, err)
		}
		linters = append(linters, l)
	}
	return linters, nil
}

func buildLinter(cfg config.HTTPLinterConfig) (*linter.Linter, error) {
	numInstances := defaultNumGoroutines
	if cfg.NumGoroutines != nil {
		numInstances = *cfg.NumGoroutines
	}
	if numInstances < 0 {
		return nil, fmt.Errorf("numGoroutines must not be negative, got %d", numInstances)
	}

	if cfg.URL == "" {
		return nil, errors.New("url is required")
	}
	endpoint, err := url.Parse(cfg.URL)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" {
		return nil, fmt.Errorf("url %q must be an absolute http or https URL", cfg.URL)
	}
	// The URL is published (in /linters and on the web page), so it must not
	// contain credentials, and its query (which might contain an API key) is
	// omitted from the published copy.
	if endpoint.User != nil {
		return nil, errors.New("url must not contain credentials; use headers instead")
	}
	published := *endpoint
	published.RawQuery, published.ForceQuery, published.Fragment = "", false, ""

	timeout, err := requestTimeout(cfg.Timeout)
	if err != nil {
		return nil, err
	}
	unsupported, err := unsupportedProfiles(cfg.Artifacts)
	if err != nil {
		return nil, err
	}
	errorSeverity, err := parseSeverity("errorSeverity", cfg.ErrorSeverity, defaultErrorSeverity)
	if err != nil {
		return nil, err
	}
	timeoutSeverity, err := parseSeverity("timeoutSeverity", cfg.TimeoutSeverity, defaultTimeoutSeverity)
	if err != nil {
		return nil, err
	}
	if err = checkHeaders(cfg.Headers); err != nil {
		return nil, err
	}
	client, err := newClient(timeout, numInstances, endpoint.Scheme, cfg.TLS)
	if err != nil {
		return nil, err
	}

	backend := &HTTPLinter{
		client:          client,
		url:             cfg.URL,
		headers:         cfg.Headers,
		errorSeverity:   errorSeverity,
		timeoutSeverity: timeoutSeverity,
	}
	return &linter.Linter{
		Name:         cfg.Name,
		Version:      cfg.Version,
		Url:          published.String(),
		Unsupported:  unsupported,
		NumInstances: numInstances,
		Interface:    func() linter.LinterInterface { return backend },
	}, nil
}

// requestTimeout returns the per-request timeout.  It must be less than
// linter.backendTimeout, beyond which pkimetal reports an in-process linter
// instance as stuck and fails /livez, leaving time to encode the request and
// parse the response.
func requestTimeout(configured time.Duration) (time.Duration, error) {
	backendTimeout := config.Config.Linter.BackendTimeout
	switch {
	case backendTimeout <= 0:
		return 0, fmt.Errorf("linter.backendTimeout must be positive, got %v", backendTimeout)
	case configured == 0:
		return min(defaultTimeout, backendTimeout/2), nil
	case configured < 0:
		return 0, fmt.Errorf("timeout must be positive, got %v", configured)
	case configured >= backendTimeout:
		return 0, fmt.Errorf("timeout %v must be less than linter.backendTimeout (%v)", configured, backendTimeout)
	}
	return configured, nil
}

// checkHeaders rejects headers that would make every request fail, or that
// would be silently ignored, so that the mistake is reported at startup.
func checkHeaders(headers map[string]string) error {
	for name, value := range headers {
		if name == "" || strings.ContainsFunc(name, func(r rune) bool { return !isTokenChar(r) }) {
			return fmt.Errorf("invalid header name %q", name)
		}
		if strings.EqualFold(name, "Host") {
			return errors.New("the Host header cannot be set; it is taken from url")
		}
		if strings.ContainsFunc(value, func(r rune) bool { return (r < ' ' && r != '\t') || r == 0x7f }) {
			return fmt.Errorf("invalid value for header %q", name)
		}
	}
	return nil
}

// isTokenChar reports whether r may appear in an HTTP header name (RFC 9110
// section 5.6.2).
func isTokenChar(r rune) bool {
	return r < 0x7f && (r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || strings.ContainsRune("!#$%&'*+-.^_`|~", r))
}

func parseSeverity(setting, value, defaultValue string) (linter.SeverityLevel, error) {
	if value == "" {
		value = defaultValue
	}
	severity, ok := linter.Severity[strings.ToLower(value)]
	if !ok || severity == linter.SEVERITY_META {
		return 0, fmt.Errorf("%s %q is not a valid severity", setting, value)
	}
	return severity, nil
}

// unsupportedProfiles returns the profiles whose artifact type is not in
// artifacts (default: certificates only), so that the endpoint is only sent the
// artifact types it declares.
func unsupportedProfiles(artifacts []string) ([]linter.ProfileId, error) {
	if len(artifacts) == 0 {
		artifacts = []string{ArtifactCertificate}
	}
	for _, artifact := range artifacts {
		switch artifact {
		case ArtifactCertificate, ArtifactCRL, ArtifactOCSP:
		default:
			return nil, fmt.Errorf("unknown artifact %q (want %s, %s or %s)", artifact, ArtifactCertificate, ArtifactCRL, ArtifactOCSP)
		}
	}

	var unsupported []linter.ProfileId
	for id := range linter.AllProfiles {
		if id != linter.AUTODETECT && !slices.Contains(artifacts, artifactOf(id)) {
			unsupported = append(unsupported, id)
		}
	}
	slices.Sort(unsupported)
	return unsupported, nil
}

func artifactOf(id linter.ProfileId) string {
	switch {
	case slices.Contains(linter.CrlProfileIDs, id):
		return ArtifactCRL
	case slices.Contains(linter.OcspProfileIDs, id):
		return ArtifactOCSP
	default:
		return ArtifactCertificate
	}
}

func (l *HTTPLinter) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	return true, "", "", nil // HTTP linters are called from Goroutine(s) in the pkimetal process, so there are no "external" instances.
}

func (l *HTTPLinter) StopInstance(lin *linter.LinterInstance) {
}

func (l *HTTPLinter) HandleRequest(ctx context.Context, lin *linter.LinterInstance, lreq *linter.LintingRequest) []linter.LintingResult {
	return l.lint(ctx, request{
		B64Input: base64.StdEncoding.EncodeToString(lreq.DecodedInput),
		Profile:  linter.AllProfiles[lreq.ProfileId].Name,
		Artifact: artifactOf(lreq.ProfileId),
	})
}

func (l *HTTPLinter) ProcessResult(lresult linter.LintingResult) linter.LintingResult {
	return lresult
}
