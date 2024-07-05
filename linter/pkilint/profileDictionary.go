package pkilint

import (
	"fmt"

	"github.com/pkimetal/pkimetal/linter"
)

var serverauth_profile_dictionary = fmt.Sprintf(`serverauth_profile_dictionary = {
	# CABForum TLS Baseline Requirements.
	%d: serverauth_constants.CertificateType.ROOT_CA,
	%d: serverauth_constants.CertificateType.EXTERNAL_CROSS_CA,
	%d: serverauth_constants.CertificateType.INTERNAL_CROSS_CA,
	%d: serverauth_constants.CertificateType.INTERNAL_UNCONSTRAINED_TLS_CA,
	%d: serverauth_constants.CertificateType.INTERNAL_CONSTRAINED_TLS_CA,
	%d: serverauth_constants.CertificateType.EXTERNAL_UNCONSTRAINED_TLS_CA,
	%d: serverauth_constants.CertificateType.EXTERNAL_CONSTRAINED_TLS_CA,
	%d: serverauth_constants.CertificateType.PRECERT_SIGNING_CA,
	%d: serverauth_constants.CertificateType.DV_FINAL_CERTIFICATE,
	%d: serverauth_constants.CertificateType.DV_PRE_CERTIFICATE,
	%d: serverauth_constants.CertificateType.OV_FINAL_CERTIFICATE,
	%d: serverauth_constants.CertificateType.OV_PRE_CERTIFICATE,
	%d: serverauth_constants.CertificateType.IV_FINAL_CERTIFICATE,
	%d: serverauth_constants.CertificateType.IV_PRE_CERTIFICATE,
	%d: serverauth_constants.CertificateType.OCSP_RESPONDER,
	# CABForum TLS Extended Validation Guidelines.
	%d: serverauth_constants.CertificateType.EV_FINAL_CERTIFICATE,
	%d: serverauth_constants.CertificateType.EV_PRE_CERTIFICATE,
	%d: serverauth_constants.CertificateType.EXTERNAL_UNCONSTRAINED_EV_TLS_CA,
	%d: serverauth_constants.CertificateType.EXTERNAL_CONSTRAINED_EV_TLS_CA
}`,
	linter.TBR_ROOT_TLSSERVER,
	linter.TBR_CROSS_TLSSERVER, linter.TBR_CROSS_UNRESTRICTED,
	linter.TBR_SUBORDINATE_TLSSERVER_INTERNAL_UNCONSTRAINED, linter.TBR_SUBORDINATE_TLSSERVER_INTERNAL_CONSTRAINED,
	linter.TBR_SUBORDINATE_TLSSERVER_EXTERNAL_UNCONSTRAINED, linter.TBR_SUBORDINATE_TLSSERVER_EXTERNAL_CONSTRAINED,
	linter.TBR_SUBORDINATE_PRECERTSIGNING,
	linter.TBR_LEAF_TLSSERVER_DV, linter.TBR_LEAF_TLSSERVER_DV_PRECERTIFICATE,
	linter.TBR_LEAF_TLSSERVER_OV, linter.TBR_LEAF_TLSSERVER_OV_PRECERTIFICATE,
	linter.TBR_LEAF_TLSSERVER_IV, linter.TBR_LEAF_TLSSERVER_IV_PRECERTIFICATE,
	linter.TBR_LEAF_OCSPSIGNING,
	linter.TEVG_LEAF_TLSSERVER_EV, linter.TEVG_LEAF_TLSSERVER_EV_PRECERTIFICATE,
	linter.TEVG_SUBORDINATE_TLSSERVER_EXTERNAL_UNCONSTRAINED, linter.TEVG_SUBORDINATE_TLSSERVER_EXTERNAL_CONSTRAINED,
)

var smime_profile_dictionary = fmt.Sprintf(`smime_profile_dictionary = {
	# CABForum S/MIME Baseline Requirements.
	%d: [smime_constants.ValidationLevel.MAILBOX, smime_constants.Generation.LEGACY],
	%d: [smime_constants.ValidationLevel.MAILBOX, smime_constants.Generation.MULTIPURPOSE],
	%d: [smime_constants.ValidationLevel.MAILBOX, smime_constants.Generation.STRICT],
	%d: [smime_constants.ValidationLevel.ORGANIZATION, smime_constants.Generation.LEGACY],
	%d: [smime_constants.ValidationLevel.ORGANIZATION, smime_constants.Generation.MULTIPURPOSE],
	%d: [smime_constants.ValidationLevel.ORGANIZATION, smime_constants.Generation.STRICT],
	%d: [smime_constants.ValidationLevel.SPONSORED, smime_constants.Generation.LEGACY],
	%d: [smime_constants.ValidationLevel.SPONSORED, smime_constants.Generation.MULTIPURPOSE],
	%d: [smime_constants.ValidationLevel.SPONSORED, smime_constants.Generation.STRICT],
	%d: [smime_constants.ValidationLevel.INDIVIDUAL, smime_constants.Generation.LEGACY],
	%d: [smime_constants.ValidationLevel.INDIVIDUAL, smime_constants.Generation.MULTIPURPOSE],
	%d: [smime_constants.ValidationLevel.INDIVIDUAL, smime_constants.Generation.STRICT]
}`,
	linter.SBR_LEAF_SMIME_MV_LEGACY, linter.SBR_LEAF_SMIME_MV_MULTIPURPOSE, linter.SBR_LEAF_SMIME_MV_STRICT,
	linter.SBR_LEAF_SMIME_OV_LEGACY, linter.SBR_LEAF_SMIME_OV_MULTIPURPOSE, linter.SBR_LEAF_SMIME_OV_STRICT,
	linter.SBR_LEAF_SMIME_SV_LEGACY, linter.SBR_LEAF_SMIME_SV_MULTIPURPOSE, linter.SBR_LEAF_SMIME_SV_STRICT,
	linter.SBR_LEAF_SMIME_IV_LEGACY, linter.SBR_LEAF_SMIME_IV_MULTIPURPOSE, linter.SBR_LEAF_SMIME_IV_STRICT,
)

var etsi_profile_dictionary = fmt.Sprintf(`etsi_profile_dictionary = {
	# ETSI EN 319 412.
	%d: etsi_constants.CertificateType.NCP_W_NATURAL_PERSON_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.NCP_W_NATURAL_PERSON_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.NCP_W_LEGAL_PERSON_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.NCP_W_LEGAL_PERSON_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.DVCP_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.DVCP_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.IVCP_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.IVCP_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.OVCP_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.OVCP_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.EVCP_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.EVCP_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.QEVCP_W_EIDAS_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.QEVCP_W_EIDAS_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.QNCP_W_IV_EIDAS_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.QNCP_W_IV_EIDAS_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.QNCP_W_OV_EIDAS_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.QNCP_W_OV_EIDAS_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.QNCP_W_GEN_NATURAL_PERSON_EIDAS_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.QNCP_W_GEN_NATURAL_PERSON_EIDAS_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.QNCP_W_GEN_LEGAL_PERSON_EIDAS_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.QNCP_W_GEN_LEGAL_PERSON_EIDAS_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.QEVCP_W_NON_EIDAS_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.QEVCP_W_NON_EIDAS_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.QNCP_W_IV_NON_EIDAS_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.QNCP_W_IV_NON_EIDAS_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.QNCP_W_OV_NON_EIDAS_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.QNCP_W_OV_NON_EIDAS_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.QNCP_W_GEN_NATURAL_PERSON_NON_EIDAS_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.QNCP_W_GEN_NATURAL_PERSON_NON_EIDAS_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.QNCP_W_GEN_LEGAL_PERSON_NON_EIDAS_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.QNCP_W_GEN_LEGAL_PERSON_NON_EIDAS_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.QEVCP_W_PSD2_EIDAS_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.QEVCP_W_PSD2_EIDAS_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.QEVCP_W_PSD2_EIDAS_NON_BROWSER_FINAL_CERTIFICATE, %d: etsi_constants.CertificateType.QEVCP_W_PSD2_EIDAS_NON_BROWSER_PRE_CERTIFICATE,
	%d: etsi_constants.CertificateType.NCP_NATURAL_PERSON_CERTIFICATE, %d: etsi_constants.CertificateType.NCP_LEGAL_PERSON_CERTIFICATE,
}`,
	linter.ETSI_LEAF_TLSSERVER_NCPWNATURALPERSON, linter.ETSI_LEAF_TLSSERVER_NCPWNATURALPERSON_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_NCPWLEGALPERSON, linter.ETSI_LEAF_TLSSERVER_NCPWLEGALPERSON_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_DVCP, linter.ETSI_LEAF_TLSSERVER_DVCP_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_IVCP, linter.ETSI_LEAF_TLSSERVER_IVCP_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_OVCP, linter.ETSI_LEAF_TLSSERVER_OVCP_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_EVCP, linter.ETSI_LEAF_TLSSERVER_EVCP_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_QEVCPWEIDAS, linter.ETSI_LEAF_TLSSERVER_QEVCPWEIDAS_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_QNCPWIVEIDAS, linter.ETSI_LEAF_TLSSERVER_QNCPWIVEIDAS_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_QNCPWOVEIDAS, linter.ETSI_LEAF_TLSSERVER_QNCPWOVEIDAS_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONEIDAS, linter.ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONEIDAS_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONEIDAS, linter.ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONEIDAS_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_QEVCPWNONEIDAS, linter.ETSI_LEAF_TLSSERVER_QEVCPWNONEIDAS_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_QNCPWIVNONEIDAS, linter.ETSI_LEAF_TLSSERVER_QNCPWIVNONEIDAS_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_QNCPWOVNONEIDAS, linter.ETSI_LEAF_TLSSERVER_QNCPWOVNONEIDAS_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONNONEIDAS, linter.ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONNONEIDAS_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONNONEIDAS, linter.ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONNONEIDAS_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_QEVCPWPSD2EIDAS, linter.ETSI_LEAF_TLSSERVER_QEVCPWPSD2EIDAS_PRECERTIFICATE,
	linter.ETSI_LEAF_TLSSERVER_QEVCPWPSD2EIDASNONBROWSER, linter.ETSI_LEAF_TLSSERVER_QEVCPWPSD2EIDASNONBROWSER_PRECERTIFICATE,
	linter.ETSI_LEAF_NCPNATURALPERSON, linter.ETSI_LEAF_NCPLEGALPERSON,
)
