package pkilint

import (
	"context"
	"fmt"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
)

type Pkilint struct{}

var GitDescribeTagsAlways, PythonDir string

func init() {
	// Get pkilint package details, either embedded during the build process or from pipx; if requested in the config, autodetect the site-packages directory.
	var pkilintVersion string
	if GitDescribeTagsAlways != "" {
		pkilintVersion, config.Config.Linter.Pkilint.PythonDir = GitDescribeTagsAlways, PythonDir
	} else {
		pkilintVersion, config.Config.Linter.Pkilint.PythonDir = linter.GetPackageDetailsFromPipx("pkilint", config.Config.Linter.Pkilint.PythonDir)
	}
	switch config.Config.Linter.Pkilint.PythonDir {
	case "", "autodetect":
		panic("pkilint: PythonDir must be set")
	}

	// Register pkilint.
	(&linter.Linter{
		Name:         "pkilint",
		Version:      pkilintVersion,
		Url:          "https://github.com/digicert/pkilint",
		Unsupported:  nil,
		NumInstances: config.Config.Linter.Pkilint.NumProcesses,
		Interface:    func() linter.LinterInterface { return &Pkilint{} },
	}).Register()
}

func (l *Pkilint) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	// Start pkilint server and configure STDIN/STDOUT pipes.
	// To improve performance (up to ~10x!), the validators and finding filters are created once and reused.
	return false, config.Config.Linter.Pkilint.PythonDir, "python3",
		[]string{"-c", `#!/usr/bin/python3
import base64
from sys import stdin
from pkilint import etsi, finding_filter, loader, pkix, validation
from pkilint.cabf import cabf_crl, serverauth, smime
from pkilint.cabf.smime import smime_constants
from pkilint.cabf.serverauth import serverauth_constants
from pkilint.etsi import etsi_constants
from pkilint.pkix import certificate, crl, extension, name, ocsp
from pkilint.report import ReportGeneratorJson


# lint_cabf_smime_cert:
` + smime_profile_dictionary + `
sbr_profile_ids = {` + linter.ProfileIDList(linter.SbrLeafProfileIDs) + `}
smime_decoding_validators = smime.create_decoding_validators()
smime_doc_validators = {}

def init_smime_validators():
	for v in smime_constants.ValidationLevel:
		smime_doc_validators[v] = {}
		for g in smime_constants.Generation:
			smime_doc_validators[v][g] = certificate.create_pkix_certificate_validator_container(smime_decoding_validators, smime.create_subscriber_validators(v, g))

def lint_cabf_smime_cert(profile_id, pem_data):
	try:
		cert = loader.load_pem_certificate(pem_data, "")
		v_g = smime_profile_dictionary.get(profile_id, smime.determine_validation_level_and_generation(cert))
		if v_g is None:
			return "E: Could not determine validation level and generation"
		validation_level, generation = v_g
		return ReportGeneratorJson(smime_doc_validators[validation_level][generation].validate(cert.root), validation.ValidationFindingSeverity.DEBUG).generate()
	except Exception as e:
		return "F: Exception: " + str(e)


# lint_cabf_serverauth_cert:
` + serverauth_profile_dictionary + `
tbr_tevg_profile_ids = {` + linter.ProfileIDList(linter.TbrTevgCertificateProfileIDs) + `}
serverauth_decoding_validators = serverauth.create_decoding_validators()
serverauth_doc_validators = {}
serverauth_finding_filters = {}

def init_serverauth_validators_and_filters():
	for ct in serverauth_constants.CertificateType:
		serverauth_doc_validators[ct] = certificate.create_pkix_certificate_validator_container(serverauth_decoding_validators, serverauth.create_validators(ct))
		serverauth_finding_filters[ct] = serverauth.create_serverauth_finding_filters(ct)

def lint_cabf_serverauth_cert(profile_id, pem_data):
	try:
		cert = loader.load_pem_certificate(pem_data, "")
		certificate_type = serverauth_profile_dictionary.get(profile_id, serverauth.determine_certificate_type(cert))
		results, _ = finding_filter.filter_results(serverauth_finding_filters[certificate_type], serverauth_doc_validators[certificate_type].validate(cert.root))
		return ReportGeneratorJson(results, validation.ValidationFindingSeverity.DEBUG).generate()
	except Exception as e:
		return "F: Exception: " + str(e)


# lint_etsi_cert:
` + etsi_profile_dictionary + `
etsi_profile_ids = {` + linter.ProfileIDList(linter.EtsiCertificateProfileIDs) + `}
etsi_doc_validators = {}
etsi_finding_filters = {}

def init_etsi_validators_and_filters():
	for ct in etsi_constants.CertificateType:
		etsi_doc_validators[ct] = certificate.create_pkix_certificate_validator_container(etsi.create_decoding_validators(ct), etsi.create_validators(ct))
		etsi_finding_filters[ct] = etsi.create_etsi_finding_filters(ct)

def lint_etsi_cert(profile_id, pem_data):
	try:
		cert = loader.load_pem_certificate(pem_data, "")
		certificate_type = etsi_profile_dictionary.get(profile_id, etsi.determine_certificate_type(cert))
		results, _ = finding_filter.filter_results(etsi_finding_filters[certificate_type], etsi_doc_validators[certificate_type].validate(cert.root))
		return ReportGeneratorJson(results, validation.ValidationFindingSeverity.DEBUG).generate()
	except Exception as e:
		return "F: Exception: " + str(e)


# lint_pkix_cert:
pkix_doc_validator = certificate.create_pkix_certificate_validator_container(
	certificate.create_decoding_validators(name.ATTRIBUTE_TYPE_MAPPINGS, extension.EXTENSION_MAPPINGS),
	[
		certificate.create_issuer_validator_container([]),
		certificate.create_validity_validator_container(),
		certificate.create_subject_validator_container([]),
		certificate.create_extensions_validator_container([]),
	]
)

def lint_pkix_cert(pem_data):
	try:
		cert = loader.load_pem_certificate(pem_data, "")
		return ReportGeneratorJson(pkix_doc_validator.validate(cert.root), validation.ValidationFindingSeverity.DEBUG).generate()
	except Exception as e:
		return "F: Exception: " + str(e)


# lint_crl:
crl_profile_ids = {` + linter.ProfileIDList(linter.CrlProfileIDs) + `}
crl_doc_validators = {}
crl_doc_validators[` + fmt.Sprintf("%d", linter.RFC5280_CRL) + `] = crl.create_pkix_crl_validator_container(
	[pkix.create_attribute_decoder(name.ATTRIBUTE_TYPE_MAPPINGS), pkix.create_extension_decoder(extension.EXTENSION_MAPPINGS)],
	[crl.create_issuer_validator_container([]), crl.create_validity_validator_container([]), crl.create_extensions_validator_container([])]
)
crl_doc_validators[` + fmt.Sprintf("%d", linter.TBR_CRL) + `] = crl.create_pkix_crl_validator_container(
	[pkix.create_attribute_decoder(name.ATTRIBUTE_TYPE_MAPPINGS), pkix.create_extension_decoder(extension.EXTENSION_MAPPINGS)],
	[crl.create_issuer_validator_container([]), crl.create_validity_validator_container([cabf_crl.create_validity_period_validator(crl.CertificateRevocationListType.CRL)]), crl.create_extensions_validator_container([]), cabf_crl.create_reason_code_validator(crl.CertificateRevocationListType.CRL)]
)
crl_doc_validators[` + fmt.Sprintf("%d", linter.RFC5280_ARL) + `] = crl.create_pkix_crl_validator_container(
	[pkix.create_attribute_decoder(name.ATTRIBUTE_TYPE_MAPPINGS), pkix.create_extension_decoder(extension.EXTENSION_MAPPINGS)],
	[crl.create_issuer_validator_container([]), crl.create_validity_validator_container([]), crl.create_extensions_validator_container([])]
)
crl_doc_validators[` + fmt.Sprintf("%d", linter.TBR_ARL) + `] = crl.create_pkix_crl_validator_container(
	[pkix.create_attribute_decoder(name.ATTRIBUTE_TYPE_MAPPINGS), pkix.create_extension_decoder(extension.EXTENSION_MAPPINGS)],
	[crl.create_issuer_validator_container([]), crl.create_validity_validator_container([cabf_crl.create_validity_period_validator(crl.CertificateRevocationListType.ARL)]), crl.create_extensions_validator_container([]), cabf_crl.create_reason_code_validator(crl.CertificateRevocationListType.ARL)]
)

def lint_crl(pem_data, crl_profile_id):
	try:
		crl_or_arl = loader.load_pem_crl(pem_data, "")
		return ReportGeneratorJson(crl_doc_validators[crl_profile_id].validate(crl_or_arl.root), validation.ValidationFindingSeverity.DEBUG).generate()
	except Exception as e:
		return "F: Exception: " + str(e)


# lint_ocsp_response:
ocspresponse_profile_ids = {` + linter.ProfileIDList(linter.OcspProfileIDs) + `}
ocsp_doc_validator = ocsp.create_pkix_ocsp_response_validator_container(
	[ocsp.create_response_decoder(), pkix.create_attribute_decoder(name.ATTRIBUTE_TYPE_MAPPINGS), pkix.create_extension_decoder(extension.EXTENSION_MAPPINGS)], []
)

def lint_ocsp_response(pem_data):
	try:
		ocsp_response = loader.load_ocsp_response(pem_data, "")
		return ReportGeneratorJson(ocsp_doc_validator.validate(ocsp_response.root), validation.ValidationFindingSeverity.DEBUG).generate()
	except Exception as e:
		return "F: Exception: " + str(e)


profile_id = -1
pem_data = ""
try:
	init_smime_validators()
	init_serverauth_validators_and_filters()
	for line in stdin:
		if profile_id == -1:
			profile_id = int(line.strip())
		else:
			pem_data = pem_data + line.strip() + "\n"

		if "END CERTIFICATE" in line or "END X509 CRL" in line or "END OCSP RESPONSE" in line:
			if profile_id in sbr_profile_ids:
				print(lint_cabf_smime_cert(profile_id, pem_data))
			elif profile_id in tbr_tevg_profile_ids:
				print(lint_cabf_serverauth_cert(profile_id, pem_data))
			elif profile_id in crl_profile_ids:
				print(lint_crl(pem_data, profile_id))
			elif profile_id in ocspresponse_profile_ids:
				print(lint_ocsp_response(pem_data))
			else:
				print(lint_pkix_cert(pem_data))
			print("` + linter.PKIMETAL_ENDOFRESULTS + `", flush=True)
			profile_id = -1
			pem_data = ""
except KeyboardInterrupt:
	pass
`}
}

func (l *Pkilint) StopInstance(lin *linter.LinterInstance) {
}

func (l *Pkilint) HandleRequest(lin *linter.LinterInstance, lreq *linter.LintingRequest, ctx context.Context) []linter.LintingResult {
	// Not used.
	return nil
}
