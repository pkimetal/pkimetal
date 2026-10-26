package paranoid

import (
	"context"
	"slices"
	"strings"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/linter/pemreader"
)

type Paranoid struct{}

var Version, PythonDir string

func init() {
	if config.Config.Linter.Paranoid.NumProcesses > 0 {
		if PythonDir != "" {
			config.Config.Linter.Paranoid.PythonDir = PythonDir
		} else {
			Version, config.Config.Linter.Paranoid.PythonDir = linter.GetPackageDetailsFromPipx("paranoid-crypto", config.Config.Linter.Paranoid.PythonDir)
		}

		switch config.Config.Linter.Paranoid.PythonDir {
		case "", "autodetect":
			panic("paranoid: PythonDir must be set")
		}
	}

	(&linter.Linter{
		Name:    "paranoid",
		Version: Version,
		Url:     "https://github.com/google/paranoid_crypto",
		Unsupported: unsupportedProfiles(
			config.Config.Linter.Paranoid.EnableCACertificates,
			config.Config.Linter.Paranoid.EnableLeafCertificates,
			config.Config.Linter.Paranoid.EnableCRLs,
			config.Config.Linter.Paranoid.EnableOCSPResponses,
		),
		NumInstances: config.Config.Linter.Paranoid.NumProcesses,
		ReadySignal:  linter.PKIMETAL_READY,
		Interface:    func() linter.LinterInterface { return &Paranoid{} },
	}).Register()
}

func unsupportedProfiles(enableCA, enableLeaf, enableCRL, enableOCSP bool) []linter.ProfileId {
	var unsupported []linter.ProfileId
	for id := range linter.AllProfiles {
		var enabled bool
		switch {
		case id == linter.AUTODETECT:
			enabled = enableCA || enableLeaf || enableCRL || enableOCSP
		case slices.Contains(linter.RootProfileIDs, id), slices.Contains(linter.SubordinateProfileIDs, id):
			enabled = enableCA
		case slices.Contains(linter.CrlProfileIDs, id):
			enabled = enableCRL
		case slices.Contains(linter.OcspProfileIDs, id):
			enabled = enableOCSP
		default:
			enabled = enableLeaf
		}
		if !enabled {
			unsupported = append(unsupported, id)
		}
	}
	return unsupported
}

func (l *Paranoid) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	return false, config.Config.Linter.Paranoid.PythonDir, "python3",
		[]string{"-c", pemreader.Reader + `
import base64
import contextlib
import json
import sys

from absl import logging
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
from cryptography.x509 import ocsp
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import paranoid

logging.set_verbosity(logging.ERROR)

def integer_bytes(value):
	return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")

def ec_info(key):
	numbers = key.public_numbers()
	curve = getattr(paranoid_pb2, "CURVE_" + key.curve.name.upper(), None)
	if curve is None:
		return None
	return paranoid_pb2.ECKeyInfo(
		curve_type=curve, x=integer_bytes(numbers.x), y=integer_bytes(numbers.y)
	)

def finding(field, code, severity):
	return {"node_path": field, "finding_descriptions": [{"code": code, "severity": severity}]}

def check_artifact(artifact, checks, field):
	results = []
	for check in checks.values():
		check.Check([artifact])
	for result in artifact.test_info.test_results:
		if result.result:
			severity = "warning" if result.severity <= paranoid_pb2.SEVERITY_MEDIUM else "error"
			results.append(finding(field, "paranoid." + result.test_name, severity))
	return results

def check_key(key, field):
	if isinstance(key, rsa.RSAPublicKey):
		numbers = key.public_numbers()
		artifact = paranoid_pb2.RSAKey(rsa_info=paranoid_pb2.RSAKeyInfo(
			n=integer_bytes(numbers.n), e=integer_bytes(numbers.e)
		))
		return check_artifact(artifact, paranoid.GetRSAAllChecks(), field)
	if isinstance(key, ec.EllipticCurvePublicKey):
		info = ec_info(key)
		if info is not None:
			artifact = paranoid_pb2.ECKey(ec_info=info)
			return check_artifact(artifact, paranoid.GetECAllChecks(), field)
	return [finding(field, "unsupported_key", "notice")]

def check_signature(document, candidates, signed_bytes, field):
	for certificate in candidates:
		key = certificate.public_key()
		if not isinstance(key, ec.EllipticCurvePublicKey):
			continue
		info = ec_info(key)
		if info is None or not document.signature_algorithm_oid.dotted_string.startswith("1.2.840.10045.4."):
			continue
		algorithm = document.signature_hash_algorithm
		signature_algorithm = getattr(paranoid_pb2, "ECDSA_WITH_" + algorithm.name.upper(), None)
		if signature_algorithm is None:
			continue
		try:
			key.verify(document.signature, signed_bytes, ec.ECDSA(algorithm))
		except InvalidSignature:
			continue
		sig_r, sig_s = utils.decode_dss_signature(document.signature)
		digest = hashes.Hash(algorithm)
		digest.update(signed_bytes)
		artifact = paranoid_pb2.ECDSASignature(
			issuer_key_info=info,
			ecdsa_sig_info=paranoid_pb2.ECDSASignatureInfo(
				r=integer_bytes(sig_r), s=integer_bytes(sig_s),
				algorithm=signature_algorithm, message_hash=digest.finalize()
			),
		)
		return check_artifact(artifact, paranoid.GetECDSAAllChecks(), field)
	return [finding(field, "signature_not_checked", "info")]

def lint(pem_data):
	data = pem_data.encode("ascii")
	if "BEGIN X509 CRL" in pem_data:
		x509.load_pem_x509_crl(data)
		return [finding("", "no_public_key", "notice"), finding("signature", "signature_not_checked", "info")]
	if "BEGIN OCSP RESPONSE" in pem_data:
		der = base64.b64decode("".join(pem_data.splitlines()[1:-1]), validate=True)
		response = ocsp.load_der_ocsp_response(der)
		if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
			return [finding("", "no_public_key", "notice"), finding("signature", "signature_not_checked", "info")]
		results = []
		for index, certificate in enumerate(response.certificates):
			results.extend(check_key(certificate.public_key(), f"certificates[{index}].subjectPublicKeyInfo"))
		if not response.certificates:
			results.append(finding("", "no_public_key", "notice"))
		results.extend(check_signature(response, response.certificates, response.tbs_response_bytes, "signature"))
		return results
	certificate = x509.load_pem_x509_certificate(data)
	results = check_key(certificate.public_key(), "subjectPublicKeyInfo")
	candidates = [certificate] if certificate.subject == certificate.issuer else []
	results.extend(check_signature(certificate, candidates, certificate.tbs_certificate_bytes, "signature"))
	return results

if __name__ == "__main__":
	with contextlib.redirect_stdout(sys.stderr):
		paranoid.GetRSAAllChecks()
		paranoid.GetECAllChecks()
		paranoid.GetECDSAAllChecks()
	print("[Ready]", flush=True)
	try:
		for profile_id, pem_data in read_pem_requests(sys.stdin):
			try:
				with contextlib.redirect_stdout(sys.stderr):
					results = lint(pem_data)
				print(json.dumps({"results": results}))
			except Exception as error:
				print("F: Exception: " + " ".join(str(error).splitlines()))
			print("[EndOfResults]", flush=True)
	except KeyboardInterrupt:
		pass
`}
}

func (l *Paranoid) StopInstance(instance *linter.LinterInstance) {}

func (l *Paranoid) HandleRequest(ctx context.Context, instance *linter.LinterInstance, request *linter.LintingRequest) []linter.LintingResult {
	return nil
}

func (l *Paranoid) ProcessResult(result linter.LintingResult) linter.LintingResult {
	switch result.Code {
	case "":
		return result
	case "unsupported_key":
		result.Finding = "Public key algorithm or curve is not supported by Paranoid"
	case "no_public_key":
		result.Finding = "No public key is present in this artifact; Paranoid key checks were not run"
	case "signature_not_checked":
		result.Finding = "Signature checks require an ECDSA signature and its signer public key; no applicable signature was checked"
	default:
		result.Finding = "Paranoid detected a potential cryptographic weakness: " + strings.TrimPrefix(result.Code, "paranoid.")
	}
	return result
}
