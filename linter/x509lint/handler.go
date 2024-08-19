package x509lint

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"unsafe"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
)

/*
#cgo LDFLAGS: -lcrypto
#include <stdlib.h>
#include "messages.h"
#include "checks.h"
*/
import "C"

type X509lint struct{}

var GitDescribeTagsAlways string

func init() {
	// x509lint is run in-process via CGO.  Since it stores linter request state in global variables, multiple backends cannot be supported.
	switch config.Config.Linter.X509lint.NumGoroutines {
	case 0, 1:
	default:
		panic("x509lint: numGoroutines must be 0 or 1")
	}

	// Register x509lint.
	(&linter.Linter{
		Name:         "x509lint",
		Version:      GitDescribeTagsAlways,
		Url:          "https://github.com/kroeckx/x509lint",
		Unsupported:  linter.NonCertificateProfileIDs,
		NumInstances: config.Config.Linter.X509lint.NumGoroutines,
		Interface:    func() linter.LinterInterface { return &X509lint{} },
	}).Register()
}

func (l *X509lint) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	C.check_init()
	return true, "", "", nil // x509lint is run in a Goroutine in the pkimetal process, so there are no "external" instances.
}

func (l *X509lint) StopInstance(lin *linter.LinterInstance) {
	if lin.NumInstances > 0 {
		C.check_finish()
	}
}

func x509lintCertType(profileId linter.ProfileId) int {
	if slices.Contains(linter.RootProfileIDs, profileId) {
		return 2 // Root.
	} else if slices.Contains(linter.SubordinateProfileIDs, profileId) {
		return 1 // Subordinate.
	} else {
		return 0 // Leaf.
	}
}

func (l *X509lint) HandleRequest(lin *linter.LinterInstance, lreq *linter.LintingRequest, ctx context.Context) []linter.LintingResult {
	var lres []linter.LintingResult
	if results := strings.Trim(x509lintCheck(lreq.DecodedInput, x509lintCertType(lreq.ProfileId)), "\n"); results != "" {
		for _, result := range strings.Split(results, "\n") {
			if len(result) < 4 {
				lres = append(lres, linter.LintingResult{
					Severity: linter.SEVERITY_FATAL,
					Finding:  fmt.Sprintf("Result text unexpectedly short: '%s'", result),
				})
				break
			}

			lresult := linter.LintingResult{
				Finding: result[3:],
			}
			switch result[0:3] {
			case "I: ":
				lresult.Severity = linter.SEVERITY_INFO
			case "W: ":
				lresult.Severity = linter.SEVERITY_WARNING
			case "E: ":
				lresult.Severity = linter.SEVERITY_ERROR
			default:
				continue
			}
			lres = append(lres, lresult)
		}
	}

	return lres
}

func x509lintCheck(cert_der []byte, cert_type int) string {
	C.check((*C.uchar)(unsafe.Pointer(&cert_der[0])), (C.ulong)(len(cert_der)), C.DER, (C.CertType)(cert_type))
	messages := C.get_messages()
	defer C.free(unsafe.Pointer(messages))
	return C.GoString(messages)
}

func (l *X509lint) ProcessResult(lresult linter.LintingResult) linter.LintingResult {
	return lresult
}
