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
