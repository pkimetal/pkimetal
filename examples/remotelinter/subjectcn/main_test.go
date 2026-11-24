package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func certB64(t *testing.T, commonName string) string {
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
	return base64.StdEncoding.EncodeToString(der)
}

func post(method, body string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handleLint(recorder, httptest.NewRequest(method, "/", strings.NewReader(body)))
	return recorder
}

func decodeFindings(t *testing.T, recorder *httptest.ResponseRecorder) []lintFinding {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", recorder.Code, recorder.Body)
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("Content-Type %q, want application/json", contentType)
	}
	var findings []lintFinding
	if err := json.Unmarshal(recorder.Body.Bytes(), &findings); err != nil {
		t.Fatalf("response is not a findings array: %v: %s", err, recorder.Body)
	}
	return findings
}

func TestHandleLint_Certificates(t *testing.T) {
	profileFinding := lintFinding{Severity: "debug", Finding: "profile tbr_leaf_tlsserver_ov"}
	exampleFinding := lintFinding{Severity: "warning", Finding: "Subject CN contains 'example'"}
	for _, tc := range []struct {
		commonName string
		want       []lintFinding
	}{
		{"www.example.com", []lintFinding{profileFinding, exampleFinding}},
		{"EXAMPLE Corp", []lintFinding{profileFinding, exampleFinding}},
		{"pkimetal.test", []lintFinding{profileFinding}},
	} {
		t.Run(tc.commonName, func(t *testing.T) {
			body := `{"b64input":"` + certB64(t, tc.commonName) + `","profile":"tbr_leaf_tlsserver_ov","artifact":"certificate"}`
			if got := decodeFindings(t, post(http.MethodPost, body)); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestHandleLint_UnparseableCertificate(t *testing.T) {
	got := decodeFindings(t, post(http.MethodPost, `{"b64input":"AAEC","profile":"rfc5280_leaf","artifact":"certificate"}`))

	if len(got) != 2 || got[1].Severity != "fatal" || !strings.HasPrefix(got[1].Finding, "could not parse certificate: ") {
		t.Errorf("got %+v, want the profile finding then a fatal parse finding", got)
	}
}

func TestHandleLint_BadRequests(t *testing.T) {
	for _, tc := range []struct {
		name, method, body string
		wantStatus         int
	}{
		{"GET", http.MethodGet, "", http.StatusMethodNotAllowed},
		{"bad JSON", http.MethodPost, "not json", http.StatusBadRequest},
		{"bad base64", http.MethodPost, `{"b64input":"***","profile":"rfc5280_leaf","artifact":"certificate"}`, http.StatusBadRequest},
		{"CRL", http.MethodPost, `{"b64input":"AAEC","profile":"rfc5280_crl","artifact":"crl"}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := post(tc.method, tc.body).Code; got != tc.wantStatus {
				t.Errorf("status %d, want %d", got, tc.wantStatus)
			}
		})
	}
}
