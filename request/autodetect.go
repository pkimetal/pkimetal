package request

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/pkimetal/pkimetal/linter"
)

var (
	// Additional Extended Key Usage OIDs.
	oidEKU_DocumentSigning              asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}
	oidEKU_PrecertificateSigning        asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}
	oidEKU_MicrosoftDocumentSigning     asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 12}
	oidEKU_AdobeAuthenticDocumentsTrust asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 5}

	// Additional Extension OIDs.
	oidExtension_PrecertificatePoison asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	oidExtension_QCStatements         asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}

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
	oidAttribute_givenName asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidAttribute_surname   asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 5, 4, 4}
	oidAttribute_pseudonym asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 5, 4, 65}

	// QCStatement OIDs.
	oidQCStatement_etsiQcsQcCompliance    asn1.ObjectIdentifier = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}
	oidQCStatement_etsiQcsQcCClegislation asn1.ObjectIdentifier = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 7}
	oidQCStatement_etsiPsd2QcStatement    asn1.ObjectIdentifier = asn1.ObjectIdentifier{0, 4, 0, 19495, 2}
)

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
			ri.profileId = linter.RFC5280_CRL
		case ENDPOINT_LINTOCSP, ENDPOINT_LINTTBSOCSP:
			ri.profileId = linter.RFC6960_OCSPRESPONSE
		case ENDPOINT_LINTCERT, ENDPOINT_LINTTBSCERT:
			if ri.cert.BasicConstraintsValid && ri.cert.IsCA {
				if ri.cert.CheckSignatureFrom(ri.cert) == nil {
					ri.profileId = linter.RFC5280_ROOT
				} else {
					ri.profileId = linter.RFC5280_SUBORDINATE
					for _, eku := range ri.cert.ExtKeyUsage {
						switch eku {
						case x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageMicrosoftServerGatedCrypto, x509.ExtKeyUsageNetscapeServerGatedCrypto:
							ri.profileId = ri.detectSubordinateTLSServerProfile()
						case x509.ExtKeyUsageEmailProtection:
							ri.profileId = ri.detectSubordinateSMIMEProfile()
						case x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageMicrosoftCommercialCodeSigning, x509.ExtKeyUsageMicrosoftKernelCodeSigning:
							ri.profileId = ri.detectSubordinateCodeSigningProfile()
						case x509.ExtKeyUsageTimeStamping:
							ri.profileId = ri.detectSubordinateTimeStampingProfile()
						default:
							continue
						}
						break
					}

					// If "ExtKeyUsage" didn't detect the type, use "UnknownExtKeyUsage" to detect Precertificate Signing.
					if ri.profileId == linter.RFC5280_SUBORDINATE {
						for _, eku2 := range ri.cert.UnknownExtKeyUsage {
							if eku2.Equal(oidEKU_PrecertificateSigning) {
								ri.profileId = linter.TBR_SUBORDINATE_PRECERTSIGNING
								break
							}
						}
					}
				}
			} else {
				// It's a generic leaf certificate until/unless we determine otherwise.
				ri.profileId = linter.RFC5280_LEAF

				// Most profiles can be autodetected from the parsed "ExtKeyUsage" list.
				hasClientAuth := false
				for _, eku := range ri.cert.ExtKeyUsage {
					switch eku {
					// x509.ExtKeyUsageAny is treated as "other leaf", unless more-specific EKU(s) is/are present.
					case x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageMicrosoftServerGatedCrypto, x509.ExtKeyUsageNetscapeServerGatedCrypto:
						ri.profileId = ri.detectLeafTLSServerProfile()
					case x509.ExtKeyUsageEmailProtection:
						ri.profileId = ri.detectLeafSMIMEProfile()
					case x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageMicrosoftCommercialCodeSigning, x509.ExtKeyUsageMicrosoftKernelCodeSigning:
						ri.profileId = ri.detectLeafCodeSigningProfile()
					case x509.ExtKeyUsageTimeStamping:
						ri.profileId = ri.detectLeafTimeStampingProfile()
					case x509.ExtKeyUsageClientAuth:
						hasClientAuth = true
						continue
					case x509.ExtKeyUsageOCSPSigning:
						ri.profileId = linter.RFC5280_LEAF_OCSPSIGNING
					default:
						continue
					}
					break
				}

				// If "ExtKeyUsage" didn't detect the type, use "UnknownExtKeyUsage" to detect Document Signing.
				if ri.profileId == linter.RFC5280_LEAF {
					for _, eku2 := range ri.cert.UnknownExtKeyUsage {
						if eku2.Equal(oidEKU_DocumentSigning) || eku2.Equal(oidEKU_MicrosoftDocumentSigning) || eku2.Equal(oidEKU_AdobeAuthenticDocumentsTrust) {
							ri.profileId = linter.RFC5280_LEAF_DOCUMENTSIGNING
							break
						}
					}
				}

				// Detect "Client Authentication only" last, since this EKU is often combined with other EKUs.
				if (ri.profileId == linter.RFC5280_LEAF) && hasClientAuth {
					ri.profileId = linter.RFC5280_LEAF_TLSCLIENT
				}
			}
		}
	}

	return true
}

func (ri *RequestInfo) detectLeafTLSServerProfile() linter.ProfileId {
	isPrecertificate := false
	for _, e := range ri.cert.Extensions {
		if e.Id.Equal(oidExtension_PrecertificatePoison) {
			isPrecertificate = true
			break
		}
	}

	isQualified, isEidasQualified, isPSD2 := getQualifiedStatementInfo(ri.cert.Extensions)
	for _, p := range ri.cert.PolicyIdentifiers {
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
					return linter.TEVG_LEAF_TLSSERVER_EV_PRECERTIFICATE
				}
			}
		}
	}

	isNaturalPerson := hasAnyNaturalPersonAttribute(ri.cert.Subject)
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

	return linter.RFC5280_LEAF_TLSSERVER
}

func (ri *RequestInfo) detectSubordinateTLSServerProfile() linter.ProfileId {
	for _, p := range ri.cert.PolicyIdentifiers {
		if p.Equal(oidPolicy_TLSServer_TBR_DV) || p.Equal(oidPolicy_TLSServer_TBR_OV) || p.Equal(oidPolicy_TLSServer_TBR_IV) {
			return linter.TBR_SUBORDINATE_TLSSERVER
		} else if p.Equal(oidPolicy_TLSServer_TEVG_EV) {
			return linter.TEVG_SUBORDINATE_TLSSERVER
		}
	}
	return linter.RFC5280_SUBORDINATE
}

func (ri *RequestInfo) detectLeafSMIMEProfile() linter.ProfileId {
	for _, p := range ri.cert.PolicyIdentifiers {
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
	return linter.RFC5280_LEAF_SMIME
}

func (ri *RequestInfo) detectSubordinateSMIMEProfile() linter.ProfileId {
	for _, p := range ri.cert.PolicyIdentifiers {
		if len(p) >= 5 && p[0:5].Equal(oidPolicy_SMIME_SBR_arc) {
			return linter.SBR_SUBORDINATE_SMIME
		}
	}
	return linter.RFC5280_SUBORDINATE
}

func (ri *RequestInfo) detectLeafCodeSigningProfile() linter.ProfileId {
	for _, p := range ri.cert.PolicyIdentifiers {
		if p.Equal(oidPolicy_CodeSigning_CSBR_OV) {
			return linter.CSBR_LEAF_CODESIGNING_OV
		} else if p.Equal(oidPolicy_CodeSigning_CSBR_EV) {
			return linter.CSBR_LEAF_CODESIGNING_EV
		}
	}
	return linter.RFC5280_LEAF_CODESIGNING
}

func (ri *RequestInfo) detectSubordinateCodeSigningProfile() linter.ProfileId {
	for _, p := range ri.cert.PolicyIdentifiers {
		if p.Equal(oidPolicy_CodeSigning_CSBR_OV) || p.Equal(oidPolicy_CodeSigning_CSBR_EV) {
			return linter.CSBR_SUBORDINATE_CODESIGNING
		}
	}
	return linter.RFC5280_SUBORDINATE
}

func (ri *RequestInfo) detectLeafTimeStampingProfile() linter.ProfileId {
	for _, p := range ri.cert.PolicyIdentifiers {
		if p.Equal(oidPolicy_TimeStamping_CSBR) {
			return linter.CSBR_LEAF_TIMESTAMPING
		}
	}
	return linter.RFC5280_LEAF_TIMESTAMPING
}

func (ri *RequestInfo) detectSubordinateTimeStampingProfile() linter.ProfileId {
	for _, p := range ri.cert.PolicyIdentifiers {
		if p.Equal(oidPolicy_TimeStamping_CSBR) {
			return linter.CSBR_SUBORDINATE_TIMESTAMPING
		}
	}
	return linter.RFC5280_SUBORDINATE
}

type qcStatement struct {
	StatementId asn1.ObjectIdentifier
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
