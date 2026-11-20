package httplinter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
)

// testPKI holds a CA, an unrelated CA, a server certificate for 127.0.0.1 and a
// client certificate, all generated for the test.
type testPKI struct {
	caFile, otherCAFile   string
	clientCert, clientKey string
	serverCert            tls.Certificate
	caPool                *x509.CertPool
}

func newTestCA(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func newTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, name string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if ip := net.ParseIP(name); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	ca, caKey := newTestCA(t, "Test CA")
	otherCA, _ := newTestCA(t, "Other CA")
	client := newTestLeaf(t, ca, caKey, "client", x509.ExtKeyUsageClientAuth)
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(client.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	pki := testPKI{
		caFile:      filepath.Join(dir, "ca.pem"),
		otherCAFile: filepath.Join(dir, "other-ca.pem"),
		clientCert:  filepath.Join(dir, "client.pem"),
		clientKey:   filepath.Join(dir, "client.key"),
		serverCert:  newTestLeaf(t, ca, caKey, "127.0.0.1", x509.ExtKeyUsageServerAuth),
		caPool:      x509.NewCertPool(),
	}
	pki.caPool.AddCert(ca)
	writePEM(t, pki.caFile, "CERTIFICATE", ca.Raw)
	writePEM(t, pki.otherCAFile, "CERTIFICATE", otherCA.Raw)
	writePEM(t, pki.clientCert, "CERTIFICATE", client.Certificate[0])
	writePEM(t, pki.clientKey, "PRIVATE KEY", clientKeyDER)
	return pki
}

// startTLSServer starts an HTTPS server answering "[]" with the test server
// certificate, optionally requiring a client certificate issued by the test CA.
func startTLSServer(t *testing.T, pki testPKI, requireClientCert bool) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "[]")
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pki.serverCert}}
	if requireClientCert {
		server.TLS.ClientAuth = tls.RequireAndVerifyClientCert
		server.TLS.ClientCAs = pki.caPool
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func lintTLS(t *testing.T, url string, tlsCfg config.HTTPLinterTLSConfig) []linter.LintingResult {
	t.Helper()
	_, backend := buildOne(t, config.HTTPLinterConfig{Name: "x", URL: url, TLS: tlsCfg})
	return backend.lint(context.Background(), testRequest)
}

func TestTLS_TrustsConfiguredCA(t *testing.T) {
	pki := newTestPKI(t)
	server := startTLSServer(t, pki, false)

	if results := lintTLS(t, server.URL, config.HTTPLinterTLSConfig{CAFile: pki.caFile}); len(results) != 0 {
		t.Errorf("expected a successful request, got %+v", results)
	}
}

func TestTLS_ConfiguredCAReplacesOtherRoots(t *testing.T) {
	pki := newTestPKI(t)
	server := startTLSServer(t, pki, false)

	results := lintTLS(t, server.URL, config.HTTPLinterTLSConfig{CAFile: pki.otherCAFile})

	if len(results) != 1 || results[0].Severity != linter.SEVERITY_BUG {
		t.Errorf("expected one errorSeverity (bug) finding for an untrusted server, got %+v", results)
	}
}

func TestTLS_MutualTLS(t *testing.T) {
	pki := newTestPKI(t)
	server := startTLSServer(t, pki, true)

	withClientCert := config.HTTPLinterTLSConfig{CAFile: pki.caFile, CertFile: pki.clientCert, KeyFile: pki.clientKey}
	if results := lintTLS(t, server.URL, withClientCert); len(results) != 0 {
		t.Errorf("with a client certificate: expected a successful request, got %+v", results)
	}

	results := lintTLS(t, server.URL, config.HTTPLinterTLSConfig{CAFile: pki.caFile})
	if len(results) != 1 || results[0].Severity != linter.SEVERITY_BUG {
		t.Errorf("without a client certificate: expected one errorSeverity (bug) finding, got %+v", results)
	}
}
