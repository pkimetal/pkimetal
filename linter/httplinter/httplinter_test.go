package httplinter

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
)

func intPtr(i int) *int { return &i }

func buildOne(t *testing.T, cfg config.HTTPLinterConfig) (*linter.Linter, *HTTPLinter) {
	t.Helper()
	linters, err := buildLinters([]config.HTTPLinterConfig{cfg})
	if err != nil {
		t.Fatalf("buildLinters: %v", err)
	}
	if len(linters) != 1 {
		t.Fatalf("got %d linters, want 1", len(linters))
	}
	backend, ok := linters[0].Interface().(*HTTPLinter)
	if !ok {
		t.Fatalf("Interface() returned %T, want *HTTPLinter", linters[0].Interface())
	}
	return linters[0], backend
}

func TestBuildLinters_MapsConfig(t *testing.T) {
	l, backend := buildOne(t, config.HTTPLinterConfig{
		Name:            "mylinter",
		URL:             "http://mylinter:8000/lint",
		NumGoroutines:   intPtr(3),
		Timeout:         2 * time.Second,
		ErrorSeverity:   "error",
		TimeoutSeverity: "WARNING",
		Version:         "1.2.3",
		Headers:         map[string]string{"authorization": "Bearer abc"},
	})

	if l.Name != "mylinter" || l.Version != "1.2.3" || l.Url != "http://mylinter:8000/lint" || l.NumInstances != 3 {
		t.Errorf("linter: got name %q, version %q, url %q, instances %d", l.Name, l.Version, l.Url, l.NumInstances)
	}
	if backend.url != "http://mylinter:8000/lint" || backend.headers["authorization"] != "Bearer abc" {
		t.Errorf("backend: got url %q, headers %v", backend.url, backend.headers)
	}
	if backend.errorSeverity != linter.SEVERITY_ERROR || backend.timeoutSeverity != linter.SEVERITY_WARNING {
		t.Errorf("severities: got %v / %v", backend.errorSeverity, backend.timeoutSeverity)
	}
	if backend.client.Timeout != 2*time.Second {
		t.Errorf("client timeout: got %v, want 2s", backend.client.Timeout)
	}
	if useHandleRequest, dir, cmd, args := l.Interface().StartInstance(); !useHandleRequest || dir != "" || cmd != "" || args != nil {
		t.Errorf("StartInstance: got (%v, %q, %q, %v), want an in-process linter", useHandleRequest, dir, cmd, args)
	}
}

func TestBuildLinters_Defaults(t *testing.T) {
	l, backend := buildOne(t, config.HTTPLinterConfig{Name: "x", URL: "https://x.example/lint"})

	if l.NumInstances != 1 {
		t.Errorf("NumInstances: got %d, want 1", l.NumInstances)
	}
	if backend.client.Timeout != 5*time.Second {
		t.Errorf("timeout: got %v, want 5s", backend.client.Timeout)
	}
	if backend.errorSeverity != linter.SEVERITY_BUG || backend.timeoutSeverity != linter.SEVERITY_NOTICE {
		t.Errorf("severities: got %v / %v, want bug / notice", backend.errorSeverity, backend.timeoutSeverity)
	}
	want := slices.Sorted(slices.Values(slices.Concat(linter.CrlProfileIDs, linter.OcspProfileIDs)))
	if !slices.Equal(l.Unsupported, want) {
		t.Errorf("Unsupported: got %v, want the CRL and OCSP profiles %v", l.Unsupported, want)
	}
}

func TestBuildLinters_PublishedURLOmitsQuery(t *testing.T) {
	l, backend := buildOne(t, config.HTTPLinterConfig{Name: "x", URL: "https://x.example/lint?api_key=SECRET"})

	if l.Url != "https://x.example/lint" {
		t.Errorf("published Url: got %q, want the URL without its query (shown by /linters and the web page)", l.Url)
	}
	if backend.url != "https://x.example/lint?api_key=SECRET" {
		t.Errorf("request URL: got %q, want the configured URL", backend.url)
	}
}

func TestBuildLinters_ExplicitZeroDisables(t *testing.T) {
	l, _ := buildOne(t, config.HTTPLinterConfig{Name: "x", URL: "http://x/", NumGoroutines: intPtr(0)})

	if l.NumInstances != 0 {
		t.Errorf("NumInstances: got %d, want 0", l.NumInstances)
	}
}

func TestBuildLinters_DefaultTimeoutCappedByBackendTimeout(t *testing.T) {
	saved := config.Config.Linter.BackendTimeout
	t.Cleanup(func() { config.Config.Linter.BackendTimeout = saved })
	config.Config.Linter.BackendTimeout = 2 * time.Second

	_, backend := buildOne(t, config.HTTPLinterConfig{Name: "x", URL: "http://x/"})

	if backend.client.Timeout != time.Second {
		t.Errorf("timeout: got %v, want half of linter.backendTimeout (1s)", backend.client.Timeout)
	}
}

func TestBuildLinters_RejectsNonPositiveBackendTimeout(t *testing.T) {
	saved := config.Config.Linter.BackendTimeout
	t.Cleanup(func() { config.Config.Linter.BackendTimeout = saved })
	config.Config.Linter.BackendTimeout = 0

	_, err := buildLinters([]config.HTTPLinterConfig{{Name: "x", URL: "http://x/"}})

	if err == nil || !strings.Contains(err.Error(), "linter.backendTimeout must be positive") {
		t.Errorf("got error %v, want one about linter.backendTimeout", err)
	}
}

func TestBuildLinters_Artifacts(t *testing.T) {
	for _, tc := range []struct {
		artifacts       []string
		wantSupported   []linter.ProfileId
		wantUnsupported []linter.ProfileId
	}{
		{
			artifacts:       []string{"certificate"},
			wantSupported:   []linter.ProfileId{linter.TBR_LEAF_TLSSERVER_OV, linter.RFC5280_ROOT},
			wantUnsupported: []linter.ProfileId{linter.RFC5280_CRL, linter.TBR_ARL, linter.RFC6960_OCSPRESPONSE},
		},
		{
			artifacts:       []string{"crl"},
			wantSupported:   []linter.ProfileId{linter.RFC5280_CRL, linter.TBR_ARL},
			wantUnsupported: []linter.ProfileId{linter.TBR_LEAF_TLSSERVER_OV, linter.RFC6960_OCSPRESPONSE},
		},
		{
			artifacts:       []string{"ocsp"},
			wantSupported:   []linter.ProfileId{linter.RFC6960_OCSPRESPONSE, linter.TBR_OCSPRESPONSE},
			wantUnsupported: []linter.ProfileId{linter.TBR_LEAF_TLSSERVER_OV, linter.RFC5280_CRL},
		},
		{
			artifacts:     []string{"certificate", "crl", "ocsp"},
			wantSupported: []linter.ProfileId{linter.TBR_LEAF_TLSSERVER_OV, linter.RFC5280_CRL, linter.RFC6960_OCSPRESPONSE},
		},
	} {
		t.Run(strings.Join(tc.artifacts, "+"), func(t *testing.T) {
			l, _ := buildOne(t, config.HTTPLinterConfig{Name: "x", URL: "http://x/", Artifacts: tc.artifacts})

			for _, id := range tc.wantSupported {
				if slices.Contains(l.Unsupported, id) {
					t.Errorf("%s should be supported", linter.AllProfiles[id].Name)
				}
			}
			for _, id := range tc.wantUnsupported {
				if !slices.Contains(l.Unsupported, id) {
					t.Errorf("%s should be unsupported", linter.AllProfiles[id].Name)
				}
			}
			if slices.Contains(l.Unsupported, linter.AUTODETECT) {
				t.Error("autodetect should never be listed as unsupported")
			}
		})
	}
}

func TestBuildLinters_Errors(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	tooLong := config.Config.Linter.BackendTimeout + time.Second

	for _, tc := range []struct {
		name    string
		cfgs    []config.HTTPLinterConfig
		wantErr string
	}{
		{"missing name", []config.HTTPLinterConfig{{URL: "http://x/"}}, "linter.httpLinters[0]: name is required"},
		{"missing url", []config.HTTPLinterConfig{{Name: "x"}}, `http linter "x": url is required`},
		{"relative url", []config.HTTPLinterConfig{{Name: "x", URL: "/lint"}}, "must be an absolute http or https URL"},
		{"unsupported scheme", []config.HTTPLinterConfig{{Name: "x", URL: "ftp://x/lint"}}, "must be an absolute http or https URL"},
		{"unparseable url", []config.HTTPLinterConfig{{Name: "x", URL: "http://[::1"}}, "must be an absolute http or https URL"},
		{"credentials in url", []config.HTTPLinterConfig{{Name: "x", URL: "https://user:pass@x/lint"}}, "url must not contain credentials; use headers instead"},
		{"duplicate names", []config.HTTPLinterConfig{{Name: "x", URL: "http://x/"}, {Name: "x", URL: "http://y/"}}, `http linter "x": declared more than once`},
		{"unknown artifact", []config.HTTPLinterConfig{{Name: "x", URL: "http://x/", Artifacts: []string{"cert"}}}, `unknown artifact "cert"`},
		{"unknown errorSeverity", []config.HTTPLinterConfig{{Name: "x", URL: "http://x/", ErrorSeverity: "serious"}}, `errorSeverity "serious" is not a valid severity`},
		{"meta timeoutSeverity", []config.HTTPLinterConfig{{Name: "x", URL: "http://x/", TimeoutSeverity: "meta"}}, `timeoutSeverity "meta" is not a valid severity`},
		{"negative numGoroutines", []config.HTTPLinterConfig{{Name: "x", URL: "http://x/", NumGoroutines: intPtr(-1)}}, "numGoroutines must not be negative"},
		{"negative timeout", []config.HTTPLinterConfig{{Name: "x", URL: "http://x/", Timeout: -time.Second}}, "timeout must be positive"},
		{"timeout above backendTimeout", []config.HTTPLinterConfig{{Name: "x", URL: "http://x/", Timeout: tooLong}}, "must be less than linter.backendTimeout"},
		{"timeout equal to backendTimeout", []config.HTTPLinterConfig{{Name: "x", URL: "http://x/", Timeout: config.Config.Linter.BackendTimeout}}, "must be less than linter.backendTimeout"},
		{"reserved name", []config.HTTPLinterConfig{{Name: "pkimetal", URL: "http://x/"}}, `name "pkimetal" is reserved`},
		{"invalid header name", []config.HTTPLinterConfig{{Name: "x", URL: "http://x/", Headers: map[string]string{"bad name": "v"}}}, `invalid header name "bad name"`},
		{"invalid header value", []config.HTTPLinterConfig{{Name: "x", URL: "http://x/", Headers: map[string]string{"authorization": "Bearer a\nb"}}}, `invalid value for header "authorization"`},
		{"host header", []config.HTTPLinterConfig{{Name: "x", URL: "http://x/", Headers: map[string]string{"host": "other.example"}}}, "the Host header cannot be set"},
		{"tls on http url", []config.HTTPLinterConfig{{Name: "x", URL: "http://x/", TLS: config.HTTPLinterTLSConfig{CAFile: notPEM}}}, "tls is only valid for https URLs"},
		{"certFile without keyFile", []config.HTTPLinterConfig{{Name: "x", URL: "https://x/", TLS: config.HTTPLinterTLSConfig{CertFile: notPEM}}}, "tls.certFile and tls.keyFile must be set together"},
		{"keyFile without certFile", []config.HTTPLinterConfig{{Name: "x", URL: "https://x/", TLS: config.HTTPLinterTLSConfig{KeyFile: notPEM}}}, "tls.certFile and tls.keyFile must be set together"},
		{"missing caFile", []config.HTTPLinterConfig{{Name: "x", URL: "https://x/", TLS: config.HTTPLinterTLSConfig{CAFile: filepath.Join(dir, "missing.pem")}}}, "tls.caFile"},
		{"caFile not PEM", []config.HTTPLinterConfig{{Name: "x", URL: "https://x/", TLS: config.HTTPLinterTLSConfig{CAFile: notPEM}}}, "no PEM certificates found"},
		{"unloadable client certificate", []config.HTTPLinterConfig{{Name: "x", URL: "https://x/", TLS: config.HTTPLinterTLSConfig{CertFile: notPEM, KeyFile: notPEM}}}, "tls client certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildLinters(tc.cfgs)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("got error %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestHandleRequest_SendsArtifactAndProfile(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		io.WriteString(w, "[]")
	}))
	defer server.Close()
	_, backend := buildOne(t, config.HTTPLinterConfig{Name: "x", URL: server.URL, Artifacts: []string{"crl"}})

	backend.HandleRequest(context.Background(), nil, &linter.LintingRequest{DecodedInput: []byte{0, 1, 2}, ProfileId: linter.RFC5280_CRL})

	if want := `{"b64input":"AAEC","profile":"rfc5280_crl","artifact":"crl"}`; body != want {
		t.Errorf("body:\ngot  %s\nwant %s", body, want)
	}
}
