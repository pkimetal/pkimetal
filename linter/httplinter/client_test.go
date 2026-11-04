package httplinter

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
)

var testRequest = request{B64Input: "AAEC", Profile: "tbr_leaf_tlsserver_ov", Artifact: "certificate"}

// newTestLinter returns a backend for url using deliberately non-default
// severities (error / warning), so that tests can tell they were applied.
func newTestLinter(t *testing.T, url string, timeout time.Duration, headers map[string]string) *HTTPLinter {
	t.Helper()
	client, err := newClient(timeout, 1, "http", config.HTTPLinterTLSConfig{})
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	return &HTTPLinter{
		client:          client,
		url:             url,
		headers:         headers,
		errorSeverity:   linter.SEVERITY_ERROR,
		timeoutSeverity: linter.SEVERITY_WARNING,
	}
}

func respondWith(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

func TestLint_SendsRequest(t *testing.T) {
	var method, path, contentType, accept, userAgent, authorization, body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		contentType, accept = r.Header.Get("Content-Type"), r.Header.Get("Accept")
		userAgent, authorization = r.Header.Get("User-Agent"), r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		io.WriteString(w, "[]")
	}))
	defer server.Close()

	// Header names arrive lowercased from viper; they must still be sent.
	l := newTestLinter(t, server.URL+"/lint", 5*time.Second, map[string]string{"authorization": "Bearer abc123"})
	results := l.lint(context.Background(), testRequest)

	if len(results) != 0 {
		t.Errorf("an empty array should mean no findings, got %+v", results)
	}
	if method != http.MethodPost || path != "/lint" {
		t.Errorf("got %s %s, want POST /lint", method, path)
	}
	if contentType != "application/json" || accept != "application/json" || userAgent != linter.PKIMETAL_NAME {
		t.Errorf("headers: Content-Type %q, Accept %q, User-Agent %q", contentType, accept, userAgent)
	}
	if authorization != "Bearer abc123" {
		t.Errorf("configured header not sent: Authorization %q", authorization)
	}
	if want := `{"b64input":"AAEC","profile":"tbr_leaf_tlsserver_ov","artifact":"certificate"}`; body != want {
		t.Errorf("body:\ngot  %s\nwant %s", body, want)
	}
}

func TestLint_PassesFindingsThrough(t *testing.T) {
	server := httptest.NewServer(respondWith(http.StatusOK,
		`[{"Linter":"ignored","Finding":"f1","Severity":"error","Field":"subject.L","Code":"c1"},{"finding":"f2","severity":"INFO"}]`))
	defer server.Close()

	results := newTestLinter(t, server.URL, 5*time.Second, nil).lint(context.Background(), testRequest)

	want := []linter.LintingResult{
		{Severity: linter.SEVERITY_ERROR, Finding: "f1", Field: "subject.L", Code: "c1"},
		{Severity: linter.SEVERITY_INFO, Finding: "f2"},
	}
	if len(results) != len(want) {
		t.Fatalf("got %+v, want %+v", results, want)
	}
	for i := range want {
		if results[i] != want[i] {
			t.Errorf("result %d: got %+v, want %+v", i, results[i], want[i])
		}
	}
}

func TestLint_Failures(t *testing.T) {
	var redirectTargetHit atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/timeout", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		io.WriteString(w, "[]")
	})
	mux.Handle("/unavailable", respondWith(http.StatusServiceUnavailable, "down"))
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusFound)
	})
	mux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHit.Store(true)
		io.WriteString(w, "[]")
	})
	mux.Handle("/notjson", respondWith(http.StatusOK, "<html>proxy error</html>"))
	mux.Handle("/object", respondWith(http.StatusOK, `{"Finding":"x","Severity":"error"}`))
	mux.Handle("/null", respondWith(http.StatusOK, "null"))
	mux.Handle("/emptyfinding", respondWith(http.StatusOK, `[{"Severity":"error"}]`))
	mux.Handle("/nosev", respondWith(http.StatusOK, `[{"Finding":"x"}]`))
	mux.Handle("/badsev", respondWith(http.StatusOK, `[{"Finding":"x","Severity":"serious"}]`))
	mux.Handle("/metasev", respondWith(http.StatusOK, `[{"Finding":"x","Severity":"meta"}]`))
	mux.HandleFunc("/huge", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "[")
		w.Write([]byte(strings.Repeat(" ", maxResponseSize)))
		io.WriteString(w, "]")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	for _, tc := range []struct {
		path        string
		wantSev     linter.SeverityLevel
		wantFinding string
	}{
		{"/timeout", linter.SEVERITY_WARNING, "API request timed out"},
		{"/unavailable", linter.SEVERITY_ERROR, "API request failed: HTTP 503 Service Unavailable"},
		{"/redirect", linter.SEVERITY_ERROR, "API request failed: HTTP 302 Found"},
		{"/notjson", linter.SEVERITY_ERROR, "invalid API response: "},
		{"/object", linter.SEVERITY_ERROR, "invalid API response: "},
		{"/null", linter.SEVERITY_ERROR, "invalid API response: response is not a JSON array"},
		{"/emptyfinding", linter.SEVERITY_ERROR, "invalid API response: finding 0 has no Finding"},
		{"/nosev", linter.SEVERITY_ERROR, `invalid API response: finding 0 has invalid Severity ""`},
		{"/badsev", linter.SEVERITY_ERROR, `invalid API response: finding 0 has invalid Severity "serious"`},
		{"/metasev", linter.SEVERITY_ERROR, `invalid API response: finding 0 has invalid Severity "meta"`},
		{"/huge", linter.SEVERITY_ERROR, "invalid API response: larger than 16 MiB"},
	} {
		t.Run(strings.TrimPrefix(tc.path, "/"), func(t *testing.T) {
			timeout := 5 * time.Second // Generous, so that a slow test runner is not reported as a timeout.
			if tc.path == "/timeout" {
				timeout = 100 * time.Millisecond
			}
			l := newTestLinter(t, server.URL+tc.path, timeout, map[string]string{"authorization": "Bearer abc123"})
			results := l.lint(context.Background(), testRequest)
			if len(results) != 1 || results[0].Severity != tc.wantSev || !strings.Contains(results[0].Finding, tc.wantFinding) {
				t.Errorf("got %+v, want one finding with severity %v containing %q", results, tc.wantSev, tc.wantFinding)
			}
		})
	}
	if redirectTargetHit.Load() {
		t.Error("the redirect was followed, so configured headers could reach another URL")
	}
}

func TestLint_ConnectionRefused(t *testing.T) {
	server := httptest.NewServer(respondWith(http.StatusOK, "[]"))
	url := server.URL + "/lint?api_key=SECRET"
	server.Close()

	results := newTestLinter(t, url, 5*time.Second, nil).lint(context.Background(), testRequest)

	if len(results) != 1 || results[0].Severity != linter.SEVERITY_ERROR || !strings.Contains(results[0].Finding, "connection refused") {
		t.Errorf("got %+v, want one error finding about the refused connection", results)
	}
	// Findings are returned to pkimetal's clients, so they must not reveal the
	// endpoint URL, which may contain a secret.
	if len(results) == 1 && (strings.Contains(results[0].Finding, "SECRET") || strings.Contains(results[0].Finding, "/lint")) {
		t.Errorf("the finding reveals the endpoint URL: %q", results[0].Finding)
	}
}

func TestLint_StopsWhenCallerGivesUp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) // The server only notices a client disconnect once the body has been read.
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
		io.WriteString(w, "[]")
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	results := newTestLinter(t, server.URL, 5*time.Second, nil).lint(ctx, testRequest)

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("lint took %v after the caller gave up; the worker should be freed promptly", elapsed)
	}
	if len(results) != 1 || results[0].Severity != linter.SEVERITY_WARNING {
		t.Errorf("got %+v, want a single timeoutSeverity (warning) finding", results)
	}
}
