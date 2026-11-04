package httplinter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"

	json "github.com/goccy/go-json"
)

// This is the only test in this package that registers linters or calls
// linter.StartLinters, which use package-global state.  Add further end-to-end
// checks here rather than in a new test.

func testCertDER(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// lintWith sends one request to l and returns its results, up to pkimetal's
// end-of-results marker.
func lintWith(t *testing.T, l *linter.Linter, profile linter.ProfileId, der []byte) []linter.LintingResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	lreq := linter.LintingRequest{
		Ctx:          ctx,
		DecodedInput: der,
		ProfileId:    profile,
		QueuedAt:     time.Now(),
		RespChannel:  make(chan linter.LintingResult),
	}
	l.ReqChannel <- lreq

	var results []linter.LintingResult
	for {
		select {
		case r := <-lreq.RespChannel:
			if r.LinterName == linter.PKIMETAL_NAME && r.Finding == linter.PKIMETAL_ENDOFRESULTS {
				return results
			}
			results = append(results, r)
		case <-ctx.Done():
			t.Errorf("timed out waiting for %s; got %+v", l.Name, results)
			return results
		}
	}
}

func hasResult(results []linter.LintingResult, linterName string, severity linter.SeverityLevel, findingSubstr string) bool {
	for _, r := range results {
		if r.LinterName == linterName && r.Severity == severity && strings.Contains(r.Finding, findingSubstr) {
			return true
		}
	}
	return false
}

// startExample builds and starts the example endpoint, returning its URL, or ""
// if Go is not available to build it.
func startExample(t *testing.T) string {
	t.Helper()
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Log("go is not on PATH, so the example endpoint is not tested")
		return ""
	}
	binary := filepath.Join(t.TempDir(), "subjectcn")
	build := exec.Command(goBinary, "build", "-o", binary, "github.com/pkimetal/pkimetal/examples/httplinter/subjectcn")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the example endpoint: %v\n%s", err, output)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()

	cmd := exec.Command(binary, "-listen", address)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the example endpoint: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if conn, err := net.Dial("tcp", address); err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the example endpoint did not start listening on %s", address)
		}
	}
	return "http://" + address + "/"
}

func TestHTTPLinter_EndToEnd(t *testing.T) {
	inline := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		time.Sleep(20 * time.Millisecond) // Overlap concurrent requests.
		fmt.Fprintf(w, `[{"Finding":"profile %s","Severity":"info"}]`, req.Profile)
	}))
	defer inline.Close()

	cfgs := []config.HTTPLinterConfig{{Name: "e2e-inline", URL: inline.URL, NumGoroutines: intPtr(2)}}
	exampleURL := startExample(t)
	if exampleURL != "" {
		cfgs = append(cfgs, config.HTTPLinterConfig{Name: "e2e-example", URL: exampleURL})
	}
	linters, err := buildLinters(cfgs)
	if err != nil {
		t.Fatalf("buildLinters: %v", err)
	}
	for _, l := range linters {
		l.Register()
	}

	ctx, cancel := context.WithCancel(context.Background())
	linter.StartLinters(ctx)
	t.Cleanup(func() {
		cancel()
		linter.StopLinters(ctx)
		linter.ShutdownWG.Wait()
	})

	// Concurrent requests to the inline endpoint, served by its two Goroutines
	// sharing one HTTP client (run with -race).
	der := testCertDER(t, "pkimetal.test")
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results := lintWith(t, linters[0], linter.TBR_LEAF_TLSSERVER_OV, der)
			if !hasResult(results, "e2e-inline", linter.SEVERITY_INFO, "profile tbr_leaf_tlsserver_ov") {
				t.Errorf("missing the endpoint's finding; got %+v", results)
			}
			if !hasResult(results, "e2e-inline", linter.SEVERITY_META, "Runtime") {
				t.Errorf("missing pkimetal's meta result; got %+v", results)
			}
		}()
	}
	wg.Wait()

	if exampleURL == "" {
		return
	}
	results := lintWith(t, linters[1], linter.TBR_LEAF_TLSSERVER_OV, testCertDER(t, "www.example.com"))
	if !hasResult(results, "e2e-example", linter.SEVERITY_DEBUG, "profile tbr_leaf_tlsserver_ov") {
		t.Errorf("example endpoint: missing the profile finding; got %+v", results)
	}
	if !hasResult(results, "e2e-example", linter.SEVERITY_WARNING, "Subject CN contains 'example'") {
		t.Errorf("example endpoint: missing the warning; got %+v", results)
	}
}
