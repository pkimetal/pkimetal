// Command subjectcn is an example pkimetal HTTP linter endpoint; see
// doc/linters/http.md.
//
// It answers POST requests in pkimetal's HTTP linter format and warns when a
// certificate's Subject CN contains "example".  Run it with:
//
//	go run ./examples/httplinter/subjectcn -listen :8000
package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"strings"
)

// lintRequest is the body that pkimetal sends.
type lintRequest struct {
	B64Input string `json:"b64input"`
	Profile  string `json:"profile"`
	Artifact string `json:"artifact"`
}

// lintFinding is one element of the response, as in pkimetal's own API.
type lintFinding struct {
	Severity string
	Finding  string
	Field    string `json:",omitempty"`
	Code     string `json:",omitempty"`
}

func main() {
	listen := flag.String("listen", ":8000", "address to listen on")
	flag.Parse()
	log.Printf("subjectcn: listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, http.HandlerFunc(handleLint)))
}

func handleLint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	var req lintRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Artifact != "certificate" {
		http.Error(w, "only certificates are supported", http.StatusBadRequest)
		return
	}
	der, err := base64.StdEncoding.DecodeString(req.B64Input)
	if err != nil {
		http.Error(w, "invalid b64input: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(lint(req.Profile, der)); err != nil {
		log.Printf("subjectcn: writing response: %v", err)
	}
}

// lint returns the findings for one certificate.
func lint(profile string, der []byte) []lintFinding {
	findings := []lintFinding{{Severity: "debug", Finding: "profile " + profile}}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return append(findings, lintFinding{Severity: "fatal", Finding: "could not parse certificate: " + err.Error()})
	}
	if strings.Contains(strings.ToLower(cert.Subject.CommonName), "example") {
		findings = append(findings, lintFinding{Severity: "warning", Finding: "Subject CN contains 'example'"})
	}
	return findings
}
