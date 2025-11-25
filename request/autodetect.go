package request

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"

	"github.com/pkimetal/pkimetal/linter"

	"github.com/crtsh/ccadb_data"
)

var (
	// Additional Extended Key Usage OIDs.
	oidEKU_DocumentSigning              asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}
	oidEKU_PrecertificateSigning        asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}
	oidEKU_MicrosoftDocumentSigning     asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 12}
	oidEKU_AdobeAuthenticDocumentsTrust asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 5}

	// Additional Extension OIDs.
	oidExtension_AuthorityKeyIdentifier asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtension_PrecertificatePoison   asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	oidExtension_QCStatements           asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}

	// CABForum Certificate Policy OIDs.
	oidPolicy_TLSServer_TBR_DV          asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}
	oidPolicy_TLSServer_TBR_OV          asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 2}
	oidPolicy_TLSServer_TBR_IV          asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 3}
	oidPolicy_TLSServer_TEVG_EV         asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 1}
	oidPolicy_SMIME_SBR_arc             asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 5}
	oidPolicy_SMIME_SBR_MV_LEGACY       asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 5, 1, 1}
	oidPolicy_SMIME_SBR_MV_MULTIPURPOSE asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 5, 1, 2}
	oidPolicy_SMIME_SBR_MV_STRICT       asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 5, 1, 3}
	oidPolicy_SMIME_SBR_OV_LEGACY       asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 5, 2, 1}
	oidPolicy_SMIME_SBR_OV_MULTIPURPOSE asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 5, 2, 2}
	oidPolicy_SMIME_SBR_OV_STRICT       asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 5, 2, 3}
	oidPolicy_SMIME_SBR_SV_LEGACY       asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 5, 3, 1}
	oidPolicy_SMIME_SBR_SV_MULTIPURPOSE asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 5, 3, 2}
	oidPolicy_SMIME_SBR_SV_STRICT       asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 5, 3, 3}
	oidPolicy_SMIME_SBR_IV_LEGACY       asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 5, 4, 1}
	oidPolicy_SMIME_SBR_IV_MULTIPURPOSE asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 5, 4, 2}
	oidPolicy_SMIME_SBR_IV_STRICT       asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 5, 4, 3}
	oidPolicy_CodeSigning_CSBR_OV       asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 4, 1}
	oidPolicy_CodeSigning_CSBR_EV       asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 3}
	oidPolicy_TimeStamping_CSBR         asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 23, 140, 1, 4, 2}

	// Distinguished Name Attribute OIDs.
	oidAttribute_surname                 asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 5, 4, 4}
	oidAttribute_organizationName        asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidAttribute_givenName               asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidAttribute_pseudonym               asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 5, 4, 65}
	oidAttribute_jurisdictionCountryName asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3}

	// QCStatement OIDs.
	oidQCStatement_etsiQcsQcCompliance    asn1.ObjectIdentifier = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}
	oidQCStatement_etsiQcsQcCClegislation asn1.ObjectIdentifier = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 7}
	oidQCStatement_etsiPsd2QcStatement    asn1.ObjectIdentifier = asn1.ObjectIdentifier{0, 4, 0, 19495, 2}
)

type authorityKeyIdentifier struct {
	KeyIdentifier []byte `asn1:"optional,tag:0"`
}

type qcStatement struct {
	StatementId asn1.ObjectIdentifier
}

func getBase64AKI(exts []pkix.Extension) string {
	for _, ext := range exts {
		if ext.Id.Equal(oidExtension_AuthorityKeyIdentifier) {
			var aki authorityKeyIdentifier
			if _, err := asn1.Unmarshal(ext.Value, &aki); err == nil {
				return base64.StdEncoding.EncodeToString(aki.KeyIdentifier)
			}
			break
		}
	}
	return ""
}

func getQualifiedStatementInfo(extensions []pkix.Extension) (bool, bool, bool) {
	var isQualified, isEidasQualified, isPSD2, hasQcCClegislation bool

	for _, e := range extensions {
		if e.Id.Equal(oidExtension_QCStatements) {
			var qcStatements []qcStatement
			if rest, err := asn1.Unmarshal(e.Value, &qcStatements); err == nil && len(rest) == 0 {
				for _, s := range qcStatements {
					if s.StatementId.Equal(oidQCStatement_etsiQcsQcCompliance) {
						isQualified = true
					} else if s.StatementId.Equal(oidQCStatement_etsiQcsQcCClegislation) {
						hasQcCClegislation = true
					} else if s.StatementId.Equal(oidQCStatement_etsiPsd2QcStatement) {
						isPSD2 = true
					}
				}
			}
			if isQualified && !hasQcCClegislation {
				isEidasQualified = true
			}
			break
		}
	}

	return isQualified, isEidasQualified, isPSD2
}

func hasAnyNaturalPersonAttribute(subject pkix.Name) bool {
	for _, name := range subject.Names {
		if name.Type.Equal(oidAttribute_givenName) || name.Type.Equal(oidAttribute_surname) || name.Type.Equal(oidAttribute_pseudonym) {
			return true
		}
	}
	return false
}

func hasOrganizationNameAttribute(subject pkix.Name) bool {
	for _, name := range subject.Names {
		if name.Type.Equal(oidAttribute_organizationName) {
			return true
		}
	}
	return false
}

func hasJurisdictionCountryNameAttribute(subject pkix.Name) bool {
	for _, name := range subject.Names {
		if name.Type.Equal(oidAttribute_jurisdictionCountryName) {
			return true
		}
	}
	return false
}

func isRootCertificate(cert *x509.Certificate) bool {
	if cert.Version >= 3 && (!cert.BasicConstraintsValid || !cert.IsCA) {
		return false
	} else if cert.CheckSignatureFrom(cert) == nil {
		return true
	} else if !hasUnsupportedSignatureAlgorithm(cert) {
		return false
	} else if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	} else if cert.Version >= 3 && len(cert.AuthorityKeyId) > 0 && len(cert.SubjectKeyId) > 0 && !bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId) {
		return false
	} else {
		return true
	}
}

func hasUnsupportedSignatureAlgorithm(cert *x509.Certificate) bool {
	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.DSAWithSHA256, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

func (ri *RequestInfo) GetProfile(profileName string) bool {
	// Determine the Profile ID (default = auto-detect).
	if profileName == "" {
		ri.profileId = linter.AUTODETECT
	} else {
		ri.profileId = -1
		for id, profile := range linter.AllProfiles {
			if profile.Name == profileName {
				ri.profileId = id
				break
			}
		}
		if ri.profileId == -1 {
			return false
		}
	}

	// Perform profile autodetection, if necessary.
	if ri.profileId == linter.AUTODETECT {
		switch ri.endpoint {
		case ENDPOINT_LINTCRL, ENDPOINT_LINTTBSCRL:
			ri.profileId = ri.detectCRLProfile()
		case ENDPOINT_LINTOCSP, ENDPOINT_LINTTBSOCSP:
			ri.profileId = linter.RFC6960_OCSPRESPONSE
		case ENDPOINT_LINTCERT, ENDPOINT_LINTTBSCERT:
			if isRootCertificate(ri.cert) {
				ri.profileId = ri.detectRootCertificateProfile()
			} else if ri.cert.BasicConstraintsValid && ri.cert.IsCA {
				ri.profileId = ri.detectSubordinateCertificateProfile()
			} else {
				ri.profileId = ri.detectLeafCertificateProfile()
			}
		}
	}

	return true
}

func (ri *RequestInfo) detectCRLProfile() linter.ProfileId {
	// Use the Key Identifier from the CRL's AKI extension to lookup the issuer's capabilities in the CCADB data.
	if rl, err := x509.ParseRevocationList(ri.decodedInput); err == nil {
		if keyIdentifier := getBase64AKI(rl.Extensions); keyIdentifier != "" {
			if ic := ccadb_data.GetIssuerCapabilitiesByKeyIdentifier(keyIdentifier); ic != nil {
				// Infer the CRL profile based on the issuer's capabilities and CCADB record type.
				if ic.CertificateRecordType == ccadb_data.CCADB_RECORD_ROOT {
					if ic.TlsCapable {
						return linter.TBR_ARL
					} else {
						return linter.RFC5280_ARL
					}
				} else {
					if ic.TlsCapable {
						return linter.TBR_CRL
					} else {
						return linter.RFC5280_CRL
					}
				}
			}
		}
	}

	return linter.RFC5280_CRL
}

func (ri *RequestInfo) detectRootCertificateProfile() linter.ProfileId {
	// Look for this root certificate's capabilities in the CCADB CSV data.
	if ic := ccadb_data.GetCACertCapabilitiesBySHA256(sha256.Sum256(ri.decodedInput)); ic != nil {
		if ic.TlsEvCapable {
			return linter.TEVG_ROOT_TLSSERVER
		} else if ic.TlsCapable {
			return linter.TBR_ROOT_TLSSERVER
		} else if ic.SmimeCapable {
			return linter.SBR_ROOT_SMIME
		} else if ic.CodeSigningCapable {
			return linter.CSBR_ROOT_CODESIGNING
		}
	}

	// Root certificates typically don't contain EKUs or Certificate Policies, so assume the RFC5280 profile.
	return linter.RFC5280_ROOT
}

func (ri *RequestInfo) detectSubordinateCertificateProfile() linter.ProfileId {
	// CT is intended for the WebPKI, so the Precertificate Signing EKU implies TLS BR scope.
	for _, eku := range ri.cert.UnknownExtKeyUsage {
		if eku.Equal(oidEKU_PrecertificateSigning) {
			return linter.TBR_SUBORDINATE_PRECERTSIGNING
		}
	}

	// Determine the subordinate certificate profile based on CABForum certificate policy OIDs.
	for _, p := range ri.cert.PolicyIdentifiers {
		if p.Equal(oidPolicy_TLSServer_TBR_DV) || p.Equal(oidPolicy_TLSServer_TBR_OV) || p.Equal(oidPolicy_TLSServer_TBR_IV) {
			return linter.TBR_SUBORDINATE_TLSSERVER
		} else if p.Equal(oidPolicy_TLSServer_TEVG_EV) {
			return linter.TEVG_SUBORDINATE_TLSSERVER
		} else if len(p) >= 5 && p[0:5].Equal(oidPolicy_SMIME_SBR_arc) {
			return linter.SBR_SUBORDINATE_SMIME
		} else if p.Equal(oidPolicy_CodeSigning_CSBR_OV) || p.Equal(oidPolicy_CodeSigning_CSBR_EV) {
			return linter.CSBR_SUBORDINATE_CODESIGNING
		} else if p.Equal(oidPolicy_TimeStamping_CSBR) {
			return linter.CSBR_SUBORDINATE_TIMESTAMPING
		}
	}

	// Look for common EKUs in the certificate.
	var hasAnyOrNoEKU, hasServerAuthEKU, hasEmailProtectionEKU, hasCodeSigningEKU, hasTimeStampingEKU bool
	if len(ri.cert.ExtKeyUsage) == 0 {
		if len(ri.cert.UnknownExtKeyUsage) == 0 {
			hasAnyOrNoEKU = true
		}
	} else {
		for _, eku := range ri.cert.ExtKeyUsage {
			switch eku {
			case x509.ExtKeyUsageAny:
				hasAnyOrNoEKU = true
			case x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageMicrosoftServerGatedCrypto, x509.ExtKeyUsageNetscapeServerGatedCrypto:
				hasServerAuthEKU = true
			case x509.ExtKeyUsageEmailProtection:
				hasEmailProtectionEKU = true
			case x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageMicrosoftCommercialCodeSigning, x509.ExtKeyUsageMicrosoftKernelCodeSigning:
				hasCodeSigningEKU = true
			case x509.ExtKeyUsageTimeStamping:
				hasTimeStampingEKU = true
			}
		}
	}

	// Use the Key Identifier from the certificate's AKI extension to lookup the issuer's capabilities in the CCADB data.
	if keyIdentifier := getBase64AKI(ri.cert.Extensions); keyIdentifier != "" {
		if ic := ccadb_data.GetIssuerCapabilitiesByKeyIdentifier(keyIdentifier); ic != nil {
			// Determine the subordinate certificate profile based on the issuer's capabilities and the certificate's EKUs.
			if hasServerAuthEKU || hasAnyOrNoEKU {
				if ic.TlsEvCapable {
					return linter.TEVG_SUBORDINATE_TLSSERVER
				} else if ic.TlsCapable {
					return linter.TBR_SUBORDINATE_TLSSERVER
				}
			}
			if (hasEmailProtectionEKU || hasAnyOrNoEKU) && ic.SmimeCapable {
				return linter.SBR_SUBORDINATE_SMIME
			}
			if (hasCodeSigningEKU || hasAnyOrNoEKU) && ic.CodeSigningCapable {
				return linter.CSBR_SUBORDINATE_CODESIGNING
			}
			if hasTimeStampingEKU { // The CCADB CSV data doesn't reveal timestamping capability, but the Timestamping EKU OID combined with presence in the CCADB is a strong indicator of CSBR scope.
				return linter.CSBR_SUBORDINATE_TIMESTAMPING
			}
		}
	}

	return linter.RFC5280_SUBORDINATE
}

func (ri *RequestInfo) detectLeafCertificateProfile() linter.ProfileId {
	// Determine if the certificate is a Precertificate.
	isPrecertificate := false
	for _, e := range ri.cert.Extensions {
		if e.Id.Equal(oidExtension_PrecertificatePoison) {
			isPrecertificate = true
			break
		}
	}

	// Determine if the certificate has ETSI profile characteristics.
	isQualified, isEidasQualified, isPSD2 := getQualifiedStatementInfo(ri.cert.Extensions)

	// Detect leaf profiles based on CABForum certificate policy OIDs.
	for _, p := range ri.cert.PolicyIdentifiers {
		// Handle TLS BR and related ETSI TLS leaf profiles.
		if isPrecertificate {
			if p.Equal(oidPolicy_TLSServer_TBR_DV) {
				return linter.TBR_LEAF_TLSSERVER_DV_PRECERTIFICATE
			} else if p.Equal(oidPolicy_TLSServer_TBR_OV) {
				if isEidasQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWOVEIDAS_PRECERTIFICATE
				} else if isQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWOVNONEIDAS_PRECERTIFICATE
				} else {
					return linter.TBR_LEAF_TLSSERVER_OV_PRECERTIFICATE
				}
			} else if p.Equal(oidPolicy_TLSServer_TBR_IV) {
				if isEidasQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWIVEIDAS_PRECERTIFICATE
				} else if isQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWIVNONEIDAS_PRECERTIFICATE
				} else {
					return linter.TBR_LEAF_TLSSERVER_IV_PRECERTIFICATE
				}
			} else if p.Equal(oidPolicy_TLSServer_TEVG_EV) {
				if isPSD2 {
					return linter.ETSI_LEAF_TLSSERVER_QEVCPWPSD2EIDAS_PRECERTIFICATE
				} else if isEidasQualified {
					return linter.ETSI_LEAF_TLSSERVER_QEVCPWEIDAS_PRECERTIFICATE
				} else if isQualified {
					return linter.ETSI_LEAF_TLSSERVER_QEVCPWNONEIDAS_PRECERTIFICATE
				} else {
					return linter.TEVG_LEAF_TLSSERVER_EV_PRECERTIFICATE
				}
			}
		} else {
			if p.Equal(oidPolicy_TLSServer_TBR_DV) {
				return linter.TBR_LEAF_TLSSERVER_DV
			} else if p.Equal(oidPolicy_TLSServer_TBR_OV) {
				if isEidasQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWOVEIDAS
				} else if isQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWOVNONEIDAS
				} else {
					return linter.TBR_LEAF_TLSSERVER_OV
				}
			} else if p.Equal(oidPolicy_TLSServer_TBR_IV) {
				if isEidasQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWIVEIDAS
				} else if isQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWIVNONEIDAS
				} else {
					return linter.TBR_LEAF_TLSSERVER_IV
				}
			} else if p.Equal(oidPolicy_TLSServer_TEVG_EV) {
				if isPSD2 {
					return linter.ETSI_LEAF_TLSSERVER_QEVCPWPSD2EIDAS
				} else if isEidasQualified {
					return linter.ETSI_LEAF_TLSSERVER_QEVCPWEIDAS
				} else if isQualified {
					return linter.ETSI_LEAF_TLSSERVER_QEVCPWNONEIDAS
				} else {
					return linter.TEVG_LEAF_TLSSERVER_EV
				}
			}
		}

		// Handle S/MIME BR leaf profiles.
		if len(p) >= 5 && p[0:5].Equal(oidPolicy_SMIME_SBR_arc) {
			if p.Equal(oidPolicy_SMIME_SBR_MV_LEGACY) { // Mailbox Validated.
				return linter.SBR_LEAF_SMIME_MV_LEGACY
			} else if p.Equal(oidPolicy_SMIME_SBR_MV_MULTIPURPOSE) {
				return linter.SBR_LEAF_SMIME_MV_MULTIPURPOSE
			} else if p.Equal(oidPolicy_SMIME_SBR_MV_STRICT) {
				return linter.SBR_LEAF_SMIME_MV_STRICT
			} else if p.Equal(oidPolicy_SMIME_SBR_OV_LEGACY) { // Organization Validated.
				return linter.SBR_LEAF_SMIME_OV_LEGACY
			} else if p.Equal(oidPolicy_SMIME_SBR_OV_MULTIPURPOSE) {
				return linter.SBR_LEAF_SMIME_OV_MULTIPURPOSE
			} else if p.Equal(oidPolicy_SMIME_SBR_OV_STRICT) {
				return linter.SBR_LEAF_SMIME_OV_STRICT
			} else if p.Equal(oidPolicy_SMIME_SBR_SV_LEGACY) { // Sponsor Validated.
				return linter.SBR_LEAF_SMIME_SV_LEGACY
			} else if p.Equal(oidPolicy_SMIME_SBR_SV_MULTIPURPOSE) {
				return linter.SBR_LEAF_SMIME_SV_MULTIPURPOSE
			} else if p.Equal(oidPolicy_SMIME_SBR_SV_STRICT) {
				return linter.SBR_LEAF_SMIME_SV_STRICT
			} else if p.Equal(oidPolicy_SMIME_SBR_IV_LEGACY) { // Individual Validated.
				return linter.SBR_LEAF_SMIME_IV_LEGACY
			} else if p.Equal(oidPolicy_SMIME_SBR_IV_MULTIPURPOSE) {
				return linter.SBR_LEAF_SMIME_IV_MULTIPURPOSE
			} else if p.Equal(oidPolicy_SMIME_SBR_IV_STRICT) {
				return linter.SBR_LEAF_SMIME_IV_STRICT
			}
		}

		// Handle Code Signing BR leaf profiles.
		if p.Equal(oidPolicy_CodeSigning_CSBR_OV) {
			return linter.CSBR_LEAF_CODESIGNING_OV
		} else if p.Equal(oidPolicy_CodeSigning_CSBR_EV) {
			return linter.CSBR_LEAF_CODESIGNING_EV
		} else if p.Equal(oidPolicy_TimeStamping_CSBR) {
			return linter.CSBR_LEAF_TIMESTAMPING
		}
	}

	// Look for common EKUs in the certificate.
	var hasAnyOrNoEKU, hasServerAuthEKU, hasClientAuthEKU, hasEmailProtectionEKU, hasCodeSigningEKU, hasTimeStampingEKU, hasOCSPSigningEKU bool
	if len(ri.cert.ExtKeyUsage) == 0 {
		if len(ri.cert.UnknownExtKeyUsage) == 0 {
			hasAnyOrNoEKU = true
		}
	} else {
		for _, eku := range ri.cert.ExtKeyUsage {
			switch eku {
			case x509.ExtKeyUsageAny:
				hasAnyOrNoEKU = true
			case x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageMicrosoftServerGatedCrypto, x509.ExtKeyUsageNetscapeServerGatedCrypto:
				hasServerAuthEKU = true
			case x509.ExtKeyUsageClientAuth:
				hasClientAuthEKU = true
			case x509.ExtKeyUsageEmailProtection:
				hasEmailProtectionEKU = true
			case x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageMicrosoftCommercialCodeSigning, x509.ExtKeyUsageMicrosoftKernelCodeSigning:
				hasCodeSigningEKU = true
			case x509.ExtKeyUsageTimeStamping:
				hasTimeStampingEKU = true
			case x509.ExtKeyUsageOCSPSigning:
				hasOCSPSigningEKU = true
			}
		}
	}

	// Handle non-CABForum ETSI TLS leaf profiles.
	isNaturalPerson := hasAnyNaturalPersonAttribute(ri.cert.Subject)
	if hasServerAuthEKU {
		if isNaturalPerson {
			if isPrecertificate {
				if isEidasQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONEIDAS_PRECERTIFICATE
				} else if isQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONNONEIDAS_PRECERTIFICATE
				}
			} else {
				if isEidasQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONEIDAS
				} else if isQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONNONEIDAS
				}
			}
		} else {
			if isPrecertificate {
				if isEidasQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONEIDAS_PRECERTIFICATE
				} else if isQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONNONEIDAS_PRECERTIFICATE
				}
			} else {
				if isEidasQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONEIDAS
				} else if isQualified {
					return linter.ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONNONEIDAS
				}
			}
		}
	}

	// Use the Key Identifier in the certificate's AKI extension to lookup the issuer's capabilities in the CCADB data.
	// This is useful to determine TLS BR and EVCS scope, since older versions of those documents did not require CABForum policy OIDs.
	if keyIdentifier := getBase64AKI(ri.cert.Extensions); keyIdentifier != "" {
		if ic := ccadb_data.GetIssuerCapabilitiesByKeyIdentifier(keyIdentifier); ic != nil {
			// Determine the leaf certificate profile based on the issuer's capabilities and the certificate's EKUs.
			if hasServerAuthEKU || hasAnyOrNoEKU {
				if ic.TlsEvCapable {
					if isPrecertificate {
						return linter.TEVG_LEAF_TLSSERVER_EV_PRECERTIFICATE
					} else {
						return linter.TEVG_LEAF_TLSSERVER_EV
					}
				} else if ic.TlsCapable {
					if isNaturalPerson {
						if isPrecertificate {
							return linter.TBR_LEAF_TLSSERVER_IV_PRECERTIFICATE
						} else {
							return linter.TBR_LEAF_TLSSERVER_IV
						}
					} else if hasOrganizationNameAttribute(ri.cert.Subject) {
						if isPrecertificate {
							return linter.TBR_LEAF_TLSSERVER_OV_PRECERTIFICATE
						} else {
							return linter.TBR_LEAF_TLSSERVER_OV
						}
					} else {
						if isPrecertificate {
							return linter.TBR_LEAF_TLSSERVER_DV_PRECERTIFICATE
						} else {
							return linter.TBR_LEAF_TLSSERVER_DV
						}
					}
				}
			}
			if hasOCSPSigningEKU && ic.TlsCapable {
				return linter.TBR_LEAF_OCSPSIGNING
			}
			if (hasCodeSigningEKU || hasAnyOrNoEKU) && ic.CodeSigningCapable {
				if hasJurisdictionCountryNameAttribute(ri.cert.Subject) {
					return linter.CSBR_LEAF_CODESIGNING_EV
				} else if hasOrganizationNameAttribute(ri.cert.Subject) {
					return linter.CSBR_LEAF_CODESIGNING_OV
				}
			}
			if hasTimeStampingEKU { // The CCADB CSV data doesn't reveal timestamping capability, but the Timestamping EKU OID combined with the issuer's presence in the CCADB is a strong indicator of CSBR scope.
				return linter.CSBR_LEAF_TIMESTAMPING
			}
		}
	}

	// Use the certificate's EKUs to determine RFC5280 leaf profiles.
	if hasServerAuthEKU {
		return linter.RFC5280_LEAF_TLSSERVER
	} else if hasEmailProtectionEKU {
		return linter.RFC5280_LEAF_SMIME
	} else if hasCodeSigningEKU {
		return linter.RFC5280_LEAF_CODESIGNING
	} else if hasTimeStampingEKU {
		return linter.RFC5280_LEAF_TIMESTAMPING
	} else if hasOCSPSigningEKU {
		return linter.RFC5280_LEAF_OCSPSIGNING
	}

	// Detect Document Signing leaf profiles.
	for _, eku2 := range ri.cert.UnknownExtKeyUsage {
		if eku2.Equal(oidEKU_DocumentSigning) || eku2.Equal(oidEKU_MicrosoftDocumentSigning) || eku2.Equal(oidEKU_AdobeAuthenticDocumentsTrust) {
			return linter.RFC5280_LEAF_DOCUMENTSIGNING
		}
	}

	// Detect "Client Authentication only" last, since this EKU is often combined with other EKUs.
	if hasClientAuthEKU {
		return linter.RFC5280_LEAF_TLSCLIENT
	}

	return linter.RFC5280_LEAF
}
