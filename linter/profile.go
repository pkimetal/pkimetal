package linter

import (
	"fmt"
	"slices"
	"strings"
)

type ProfileId int

type Profile struct {
	Name           string
	Source         string
	Description    string
	Autodetectable bool
}

const (
	AUTODETECT ProfileId = iota
	// RFC5280.
	RFC5280_ROOT
	RFC5280_SUBORDINATE
	RFC5280_LEAF
	RFC5280_LEAF_TLSCLIENT
	RFC5280_LEAF_TLSSERVER
	RFC5280_LEAF_SMIME
	RFC5280_LEAF_CODESIGNING
	RFC5280_LEAF_TIMESTAMPING
	RFC5280_LEAF_DOCUMENTSIGNING
	RFC5280_LEAF_OCSPSIGNING
	RFC5280_CRL
	RFC5280_ARL
	// RFC6960.
	RFC6960_OCSPRESPONSE
	// CABForum TLS Baseline Requirements.
	TBR_ROOT_TLSSERVER
	TBR_CROSS_TLSSERVER
	TBR_CROSS_UNRESTRICTED
	TBR_SUBORDINATE_TLSSERVER
	TBR_SUBORDINATE_TLSSERVER_INTERNAL_UNCONSTRAINED
	TBR_SUBORDINATE_TLSSERVER_INTERNAL_CONSTRAINED
	TBR_SUBORDINATE_TLSSERVER_EXTERNAL_UNCONSTRAINED
	TBR_SUBORDINATE_TLSSERVER_EXTERNAL_CONSTRAINED
	TBR_SUBORDINATE_PRECERTSIGNING
	TBR_LEAF_TLSSERVER_DV
	TBR_LEAF_TLSSERVER_DV_PRECERTIFICATE
	TBR_LEAF_TLSSERVER_OV
	TBR_LEAF_TLSSERVER_OV_PRECERTIFICATE
	TBR_LEAF_TLSSERVER_IV
	TBR_LEAF_TLSSERVER_IV_PRECERTIFICATE
	TBR_LEAF_OCSPSIGNING
	TBR_CRL
	TBR_ARL
	// CABForum TLS Extended Validation Guidelines.
	TEVG_ROOT_TLSSERVER
	TEVG_SUBORDINATE_TLSSERVER
	TEVG_SUBORDINATE_TLSSERVER_EXTERNAL_UNCONSTRAINED
	TEVG_SUBORDINATE_TLSSERVER_EXTERNAL_CONSTRAINED
	TEVG_LEAF_TLSSERVER_EV
	TEVG_LEAF_TLSSERVER_EV_PRECERTIFICATE
	// CABForum S/MIME Baseline Requirements.
	SBR_ROOT_SMIME
	SBR_SUBORDINATE_SMIME
	SBR_LEAF_SMIME_MV_LEGACY
	SBR_LEAF_SMIME_MV_MULTIPURPOSE
	SBR_LEAF_SMIME_MV_STRICT
	SBR_LEAF_SMIME_OV_LEGACY
	SBR_LEAF_SMIME_OV_MULTIPURPOSE
	SBR_LEAF_SMIME_OV_STRICT
	SBR_LEAF_SMIME_SV_LEGACY
	SBR_LEAF_SMIME_SV_MULTIPURPOSE
	SBR_LEAF_SMIME_SV_STRICT
	SBR_LEAF_SMIME_IV_LEGACY
	SBR_LEAF_SMIME_IV_MULTIPURPOSE
	SBR_LEAF_SMIME_IV_STRICT
	// CABForum Code Signing Baseline Requirements.
	CSBR_ROOT_CODESIGNING
	CSBR_ROOT_TIMESTAMPING
	CSBR_SUBORDINATE_CODESIGNING
	CSBR_SUBORDINATE_TIMESTAMPING
	CSBR_LEAF_CODESIGNING_OV
	CSBR_LEAF_CODESIGNING_EV
	CSBR_LEAF_TIMESTAMPING
	// ETSI.
	ETSI_LEAF_TLSSERVER_NCPWNATURALPERSON
	ETSI_LEAF_TLSSERVER_NCPWNATURALPERSON_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_NCPWLEGALPERSON
	ETSI_LEAF_TLSSERVER_NCPWLEGALPERSON_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_DVCP
	ETSI_LEAF_TLSSERVER_DVCP_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_IVCP
	ETSI_LEAF_TLSSERVER_IVCP_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_OVCP
	ETSI_LEAF_TLSSERVER_OVCP_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_EVCP
	ETSI_LEAF_TLSSERVER_EVCP_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_QEVCPWEIDAS
	ETSI_LEAF_TLSSERVER_QEVCPWEIDAS_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_QNCPWIVEIDAS
	ETSI_LEAF_TLSSERVER_QNCPWIVEIDAS_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_QNCPWOVEIDAS
	ETSI_LEAF_TLSSERVER_QNCPWOVEIDAS_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONEIDAS
	ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONEIDAS_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONEIDAS
	ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONEIDAS_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_QEVCPWNONEIDAS
	ETSI_LEAF_TLSSERVER_QEVCPWNONEIDAS_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_QNCPWIVNONEIDAS
	ETSI_LEAF_TLSSERVER_QNCPWIVNONEIDAS_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_QNCPWOVNONEIDAS
	ETSI_LEAF_TLSSERVER_QNCPWOVNONEIDAS_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONNONEIDAS
	ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONNONEIDAS_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONNONEIDAS
	ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONNONEIDAS_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_QEVCPWPSD2EIDAS
	ETSI_LEAF_TLSSERVER_QEVCPWPSD2EIDAS_PRECERTIFICATE
	ETSI_LEAF_TLSSERVER_QEVCPWPSD2EIDASNONBROWSER
	ETSI_LEAF_TLSSERVER_QEVCPWPSD2EIDASNONBROWSER_PRECERTIFICATE
	ETSI_LEAF_NCPNATURALPERSON
	ETSI_LEAF_NCPLEGALPERSON
)

var (
	AllProfiles = map[ProfileId]Profile{
		AUTODETECT: {Name: "autodetect", Description: "AUTO-DETECT", Autodetectable: false},
		// RFC5280.
		RFC5280_ROOT:                 {Name: "rfc5280_root", Source: "RFC5280", Description: "Root CA Certificate", Autodetectable: true},
		RFC5280_SUBORDINATE:          {Name: "rfc5280_subordinate", Source: "RFC5280", Description: "Subordinate CA Certificate", Autodetectable: true},
		RFC5280_LEAF:                 {Name: "rfc5280_leaf", Source: "RFC5280", Description: "Leaf Certificate", Autodetectable: true},
		RFC5280_LEAF_TLSCLIENT:       {Name: "rfc5280_leaf_tlsclient", Source: "RFC5280", Description: "TLS Client Certificate", Autodetectable: true},
		RFC5280_LEAF_TLSSERVER:       {Name: "rfc5280_leaf_tlsserver", Source: "RFC5280", Description: "TLS Server Certificate", Autodetectable: true},
		RFC5280_LEAF_SMIME:           {Name: "rfc5280_leaf_smime", Source: "RFC5280", Description: "S/MIME Certificate", Autodetectable: true},
		RFC5280_LEAF_CODESIGNING:     {Name: "rfc5280_leaf_codesigning", Source: "RFC5280", Description: "Code Signing Certificate", Autodetectable: true},
		RFC5280_LEAF_TIMESTAMPING:    {Name: "rfc5280_leaf_timestamping", Source: "RFC5280", Description: "Time Stamping Certificate", Autodetectable: true},
		RFC5280_LEAF_DOCUMENTSIGNING: {Name: "rfc5280_leaf_documentsigning", Source: "RFC5280", Description: "Document Signing Certificate", Autodetectable: true},
		RFC5280_LEAF_OCSPSIGNING:     {Name: "rfc5280_leaf_ocspsigning", Source: "RFC5280", Description: "OCSP Signing Certificate", Autodetectable: true},
		RFC5280_CRL:                  {Name: "rfc5280_crl", Source: "RFC5280", Description: "Certificate Revocation List", Autodetectable: true},
		RFC5280_ARL:                  {Name: "rfc5280_arl", Source: "RFC5280", Description: "Authority Revocation List", Autodetectable: false},
		// RFC6960.
		RFC6960_OCSPRESPONSE: {Name: "rfc6960_ocspresponse", Source: "RFC6960", Description: "OCSP Response", Autodetectable: true},
		// CABForum TLS Baseline Requirements.
		TBR_ROOT_TLSSERVER:                               {Name: "tbr_root_tlsserver", Source: "TLS BRs", Description: "TLS Server Root CA Certificate", Autodetectable: false},
		TBR_CROSS_TLSSERVER:                              {Name: "tbr_cross_tlsserver", Source: "TLS BRs", Description: "TLS Server Cross-Certified Subordinate CA Certificate", Autodetectable: false},
		TBR_CROSS_UNRESTRICTED:                           {Name: "tbr_cross_unrestricted", Source: "TLS BRs", Description: "Unrestricted TLS Server Cross-Certified Subordinate CA Certificate", Autodetectable: false},
		TBR_SUBORDINATE_TLSSERVER:                        {Name: "tbr_subordinate_tlsserver", Source: "TLS BRs", Description: "TLS Server Subordinate CA Certificate", Autodetectable: true},
		TBR_SUBORDINATE_TLSSERVER_INTERNAL_UNCONSTRAINED: {Name: "tbr_subordinate_tlsserver_internal_unconstrained", Source: "TLS BRs", Description: "Unconstrained Internal TLS Server Subordinate CA Certificate", Autodetectable: false},
		TBR_SUBORDINATE_TLSSERVER_INTERNAL_CONSTRAINED:   {Name: "tbr_subordinate_tlsserver_internal_constrained", Source: "TLS BRs", Description: "Constrained Internal TLS Server Subordinate CA Certificate", Autodetectable: false},
		TBR_SUBORDINATE_TLSSERVER_EXTERNAL_UNCONSTRAINED: {Name: "tbr_subordinate_tlsserver_external_unconstrained", Source: "TLS BRs", Description: "Unconstrained External TLS Server Subordinate CA Certificate", Autodetectable: false},
		TBR_SUBORDINATE_TLSSERVER_EXTERNAL_CONSTRAINED:   {Name: "tbr_subordinate_tlsserver_external_constrained", Source: "TLS BRs", Description: "Constrained External TLS Server Subordinate CA Certificate", Autodetectable: false},
		TBR_SUBORDINATE_PRECERTSIGNING:                   {Name: "tbr_subordinate_precertsigning", Source: "TLS BRs", Description: "Precertificate Signing Subordinate CA Certificate", Autodetectable: true},
		TBR_LEAF_TLSSERVER_DV:                            {Name: "tbr_leaf_tlsserver_dv", Source: "TLS BRs", Description: "TLS Server Certificate: Domain Validated", Autodetectable: true},
		TBR_LEAF_TLSSERVER_DV_PRECERTIFICATE:             {Name: "tbr_leaf_tlsserver_dv_precertificate", Source: "TLS BRs", Description: "TLS Server Precertificate: Domain Validated", Autodetectable: true},
		TBR_LEAF_TLSSERVER_OV:                            {Name: "tbr_leaf_tlsserver_ov", Source: "TLS BRs", Description: "TLS Server Certificate: Organization Validated", Autodetectable: true},
		TBR_LEAF_TLSSERVER_OV_PRECERTIFICATE:             {Name: "tbr_leaf_tlsserver_ov_precertificate", Source: "TLS BRs", Description: "TLS Server Precertificate: Organization Validated", Autodetectable: true},
		TBR_LEAF_TLSSERVER_IV:                            {Name: "tbr_leaf_tlsserver_iv", Source: "TLS BRs", Description: "TLS Server Certificate: Individual Validated", Autodetectable: true},
		TBR_LEAF_TLSSERVER_IV_PRECERTIFICATE:             {Name: "tbr_leaf_tlsserver_iv_precertificate", Source: "TLS BRs", Description: "TLS Server Precertificate: Individual Validated", Autodetectable: true},
		TBR_LEAF_OCSPSIGNING:                             {Name: "tbs_leaf_ocspsigning", Source: "TLS BRs", Description: "OCSP Signing Certificate", Autodetectable: false},
		TBR_CRL:                                          {Name: "tbr_crl", Source: "TLS BRs", Description: "Certificate Revocation List", Autodetectable: false},
		TBR_ARL:                                          {Name: "tbr_arl", Source: "TLS BRs", Description: "Authority Revocation List", Autodetectable: false},
		// CABForum TLS Extended Validation Guidelines.
		TEVG_LEAF_TLSSERVER_EV:                            {Name: "tevg_leaf_tlsserver_ev", Source: "TLS EVGs", Description: "TLS Server Certificate: Extended Validation", Autodetectable: true},
		TEVG_LEAF_TLSSERVER_EV_PRECERTIFICATE:             {Name: "tevg_leaf_tlsserver_ev_precertificate", Source: "TLS EVGs", Description: "TLS Server Precertificate: Extended Validation", Autodetectable: true},
		TEVG_ROOT_TLSSERVER:                               {Name: "tevg_root_tlsserver", Source: "TLS EVGs", Description: "EV TLS Server Root CA Certificate", Autodetectable: false},
		TEVG_SUBORDINATE_TLSSERVER:                        {Name: "tevg_subordinate_tlsserver", Source: "TLS EVGs", Description: "EV TLS Subordinate CA Certificate", Autodetectable: true},
		TEVG_SUBORDINATE_TLSSERVER_EXTERNAL_UNCONSTRAINED: {Name: "tevg_subordinate_tlsserver_external_unconstrained", Source: "TLS EVGs", Description: "Unconstrained External EV TLS Server Subordinate CA Certificate", Autodetectable: false},
		TEVG_SUBORDINATE_TLSSERVER_EXTERNAL_CONSTRAINED:   {Name: "tevg_subordinate_tlsserver_external_constrained", Source: "TLS EVGs", Description: "Constrained External EV TLS Server Subordinate CA Certificate", Autodetectable: false},
		// CABForum S/MIME Baseline Requirements.
		SBR_ROOT_SMIME:                 {Name: "sbr_root_smime", Source: "S/MIME BRs", Description: "S/MIME Root CA Certificate", Autodetectable: false},
		SBR_SUBORDINATE_SMIME:          {Name: "sbr_subordinate_smime", Source: "S/MIME BRs", Description: "S/MIME Subordinate CA Certificate", Autodetectable: true},
		SBR_LEAF_SMIME_MV_LEGACY:       {Name: "sbr_leaf_smime_mv_legacy", Source: "S/MIME BRs", Description: "S/MIME Certificate: Mailbox Validated, Legacy", Autodetectable: true},
		SBR_LEAF_SMIME_MV_MULTIPURPOSE: {Name: "sbr_leaf_smime_mv_multipurpose", Source: "S/MIME BRs", Description: "S/MIME Certificate: Mailbox Validated, Multipurpose", Autodetectable: true},
		SBR_LEAF_SMIME_MV_STRICT:       {Name: "sbr_leaf_smime_mv_strict", Source: "S/MIME BRs", Description: "S/MIME Certificate: Mailbox Validated, Strict", Autodetectable: true},
		SBR_LEAF_SMIME_OV_LEGACY:       {Name: "sbr_leaf_smime_ov_legacy", Source: "S/MIME BRs", Description: "S/MIME Certificate: Organization Validated, Legacy", Autodetectable: true},
		SBR_LEAF_SMIME_OV_MULTIPURPOSE: {Name: "sbr_leaf_smime_ov_multipurpose", Source: "S/MIME BRs", Description: "S/MIME Certificate: Organization Validated, Multipurpose", Autodetectable: true},
		SBR_LEAF_SMIME_OV_STRICT:       {Name: "sbr_leaf_smime_ov_strict", Source: "S/MIME BRs", Description: "S/MIME Certificate: Organization Validated, Strict", Autodetectable: true},
		SBR_LEAF_SMIME_SV_LEGACY:       {Name: "sbr_leaf_smime_sv_legacy", Source: "S/MIME BRs", Description: "S/MIME Certificate: Sponsor Validated, Legacy", Autodetectable: true},
		SBR_LEAF_SMIME_SV_MULTIPURPOSE: {Name: "sbr_leaf_smime_sv_multipurpose", Source: "S/MIME BRs", Description: "S/MIME Certificate: Sponsor Validated, Multipurpose", Autodetectable: true},
		SBR_LEAF_SMIME_SV_STRICT:       {Name: "sbr_leaf_smime_sv_strict", Source: "S/MIME BRs", Description: "S/MIME Certificate: Sponsor Validated, Strict", Autodetectable: true},
		SBR_LEAF_SMIME_IV_LEGACY:       {Name: "sbr_leaf_smime_iv_legacy", Source: "S/MIME BRs", Description: "S/MIME Certificate: Individual Validated, Legacy", Autodetectable: true},
		SBR_LEAF_SMIME_IV_MULTIPURPOSE: {Name: "sbr_leaf_smime_iv_multipurpose", Source: "S/MIME BRs", Description: "S/MIME Certificate: Individual Validated, Multipurpose", Autodetectable: true},
		SBR_LEAF_SMIME_IV_STRICT:       {Name: "sbr_leaf_smime_iv_strict", Source: "S/MIME BRs", Description: "S/MIME Certificate: Individual Validated, Strict", Autodetectable: true},
		// CABForum Code Signing Baseline Requirements.
		CSBR_ROOT_CODESIGNING:         {Name: "csbr_root_codesigning", Source: "Code Signing BRs", Description: "Code Signing Root CA Certificate", Autodetectable: false},
		CSBR_ROOT_TIMESTAMPING:        {Name: "csbr_root_timestamping", Source: "Code Signing BRs", Description: "Time Stamping Root CA Certificate", Autodetectable: false},
		CSBR_SUBORDINATE_CODESIGNING:  {Name: "csbr_subordinate_codesigning", Source: "Code Signing BRs", Description: "Code Signing Subordinate CA Certificate", Autodetectable: true},
		CSBR_SUBORDINATE_TIMESTAMPING: {Name: "csbr_subordinate_timestamping", Source: "Code Signing BRs", Description: "Time Stamping Subordinate CA Certificate", Autodetectable: true},
		CSBR_LEAF_CODESIGNING_OV:      {Name: "csbr_leaf_codesigning_ov", Source: "Code Signing BRs", Description: "Code Signing Certificate: Organization Validated", Autodetectable: true},
		CSBR_LEAF_CODESIGNING_EV:      {Name: "csbr_leaf_codesigning_ev", Source: "Code Signing BRs", Description: "Code Signing Certificate: Extended Validation", Autodetectable: true},
		CSBR_LEAF_TIMESTAMPING:        {Name: "csbr_leaf_timestamping", Source: "Code Signing BRs", Description: "Time Stamping Certificate", Autodetectable: true},
		// ETSI.
		ETSI_LEAF_TLSSERVER_NCPWNATURALPERSON:                            {Name: "etsi_leaf_tlsserver_ncpwnaturalperson", Source: "EN 319 412", Description: "ETSI Website Authentication Certificate: Natural Person", Autodetectable: false},
		ETSI_LEAF_TLSSERVER_NCPWNATURALPERSON_PRECERTIFICATE:             {Name: "etsi_leaf_tlsserver_ncpwnaturalperson_precertificate", Source: "EN 319 412", Description: "ETSI Website Authentication Precertificate: Natural Person", Autodetectable: false},
		ETSI_LEAF_TLSSERVER_NCPWLEGALPERSON:                              {Name: "etsi_leaf_tlsserver_ncpwlegalperson", Source: "EN 319 412", Description: "ETSI Website Authentication Certificate: Legal Person", Autodetectable: false},
		ETSI_LEAF_TLSSERVER_NCPWLEGALPERSON_PRECERTIFICATE:               {Name: "etsi_leaf_tlsserver_ncpwlegalperson_precertificate", Source: "EN 319 412", Description: "ETSI Website Authentication Precertificate: Legal Person", Autodetectable: false},
		ETSI_LEAF_TLSSERVER_DVCP:                                         {Name: "etsi_leaf_tlsserver_dvcp", Source: "EN 319 412", Description: "ETSI Server Certificate: Domain Validated", Autodetectable: false},
		ETSI_LEAF_TLSSERVER_DVCP_PRECERTIFICATE:                          {Name: "etsi_leaf_tlsserver_dvcp_precertificate", Source: "EN 319 412", Description: "ETSI Server Precertificate: Domain Validated", Autodetectable: false},
		ETSI_LEAF_TLSSERVER_IVCP:                                         {Name: "etsi_leaf_tlsserver_ivcp", Source: "EN 319 412", Description: "ETSI Server Certificate: Individual Validated", Autodetectable: false},
		ETSI_LEAF_TLSSERVER_IVCP_PRECERTIFICATE:                          {Name: "etsi_leaf_tlsserver_ivcp_precertificate", Source: "EN 319 412", Description: "ETSI Server Precertificate: Individual Validated", Autodetectable: false},
		ETSI_LEAF_TLSSERVER_OVCP:                                         {Name: "etsi_leaf_tlsserver_ovcp", Source: "EN 319 412", Description: "ETSI Server Certificate: Organization Validated", Autodetectable: false},
		ETSI_LEAF_TLSSERVER_OVCP_PRECERTIFICATE:                          {Name: "etsi_leaf_tlsserver_ovcp_precertificate", Source: "EN 319 412", Description: "ETSI Server Precertificate: Organization Validated", Autodetectable: false},
		ETSI_LEAF_TLSSERVER_EVCP:                                         {Name: "etsi_leaf_tlsserver_evcp", Source: "EN 319 412", Description: "ETSI Server Certificate: Extended Validation", Autodetectable: false},
		ETSI_LEAF_TLSSERVER_EVCP_PRECERTIFICATE:                          {Name: "etsi_leaf_tlsserver_evcp_precertificate", Source: "EN 319 412", Description: "ETSI Server Precertificate: Extended Validation", Autodetectable: false},
		ETSI_LEAF_TLSSERVER_QEVCPWEIDAS:                                  {Name: "etsi_leaf_tlsserver_qevcpweidas", Source: "EN 319 412", Description: "ETSI Website Authentication Certificate: Extended Validation (Qualified, eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QEVCPWEIDAS_PRECERTIFICATE:                   {Name: "etsi_leaf_tlsserver_qevcpweidas_precertificate", Source: "EN 319 412", Description: "ETSI Website Authentication Precertificate: Extended Validation (Qualified, eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWIVEIDAS:                                 {Name: "etsi_leaf_tlsserver_qncpwiveidas", Source: "EN 319 412", Description: "ETSI Website Authentication Certificate: Individual Validated (Qualified, eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWIVEIDAS_PRECERTIFICATE:                  {Name: "etsi_leaf_tlsserver_qncpwiveidas_precertificate", Source: "EN 319 412", Description: "ETSI Website Authentication Precertificate: Individual Validated (Qualified, eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWOVEIDAS:                                 {Name: "etsi_leaf_tlsserver_qncpwoveidas", Source: "EN 319 412", Description: "ETSI Website Authentication Certificate: Organization Validated (Qualified, eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWOVEIDAS_PRECERTIFICATE:                  {Name: "etsi_leaf_tlsserver_qncpwoveidas_precertificate", Source: "EN 319 412", Description: "ETSI Website Authentication Precertificate: Organization Validated (Qualified, eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONEIDAS:                   {Name: "etsi_leaf_tlsserver_qncpwgennaturalpersoneidas", Source: "EN 319 412", Description: "ETSI Website Authentication Certificate: Natural Person (Qualified, eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONEIDAS_PRECERTIFICATE:    {Name: "etsi_leaf_tlsserver_qncpwgennaturalpersoneidas_precertificate", Source: "EN 319 412", Description: "ETSI Website Authentication Precertificate: Natural Person (Qualified, eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONEIDAS:                     {Name: "etsi_leaf_tlsserver_qncpwgenlegalpersoneidas", Source: "EN 319 412", Description: "ETSI Website Authentication Certificate: Legal Person (Qualified, eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONEIDAS_PRECERTIFICATE:      {Name: "etsi_leaf_tlsserver_qncpwgenlegalpersoneidas_precertificate", Source: "EN 319 412", Description: "ETSI Website Authentication Precertificate: Legal Person (Qualified, eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QEVCPWNONEIDAS:                               {Name: "etsi_leaf_tlsserver_qevcpwnoneidas", Source: "EN 319 412", Description: "ETSI Website Authentication Certificate: Extended Validation (Qualified, non-eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QEVCPWNONEIDAS_PRECERTIFICATE:                {Name: "etsi_leaf_tlsserver_qevcpwnoneidas_precertificate", Source: "EN 319 412", Description: "ETSI Website Authentication Precertificate: Extended Validation (Qualified, non-eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWIVNONEIDAS:                              {Name: "etsi_leaf_tlsserver_qncpwivnoneidas", Source: "EN 319 412", Description: "ETSI Website Authentication Certificate: Individual Validated (Qualified, non-eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWIVNONEIDAS_PRECERTIFICATE:               {Name: "etsi_leaf_tlsserver_qncpwivnoneidas_precertificate", Source: "EN 319 412", Description: "ETSI Website Authentication Precertificate: Individual Validated (Qualified, non-eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWOVNONEIDAS:                              {Name: "etsi_leaf_tlsserver_qncpwovnoneidas", Source: "EN 319 412", Description: "ETSI Website Authentication Certificate: Organization Validated (Qualified, non-eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWOVNONEIDAS_PRECERTIFICATE:               {Name: "etsi_leaf_tlsserver_qncpwovnoneidas_precertificate", Source: "EN 319 412", Description: "ETSI Website Authentication Precertificate: Organization Validated (Qualified, non-eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONNONEIDAS:                {Name: "etsi_leaf_tlsserver_qncpwgennaturalpersonnoneidas", Source: "EN 319 412", Description: "ETSI Website Authentication Certificate: Natural Person (Qualified, non-EIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWGENNATURALPERSONNONEIDAS_PRECERTIFICATE: {Name: "etsi_leaf_tlsserver_qncpwgennaturalpersonnoneidas_precertificate", Source: "EN 319 412", Description: "ETSI Website Authentication Precertificate: Natural Person (Qualified, non-eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONNONEIDAS:                  {Name: "etsi_leaf_tlsserver_qncpwgenlegalpersonnoneidas", Source: "EN 319 412", Description: "ETSI Website Authentication Certificate: Legal Person (Qualified, non-eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QNCPWGENLEGALPERSONNONEIDAS_PRECERTIFICATE:   {Name: "etsi_leaf_tlsserver_qncpwgenlegalpersonnoneidas_precertificate", Source: "EN 319 412", Description: "ETSI Website Authentication Certificate: Legal Person (Qualified, non-eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QEVCPWPSD2EIDAS:                              {Name: "etsi_leaf_tlsserver_qevcpwpsd2eidas", Source: "EN 319 412", Description: "ETSI Website Authentication Certificate: Extended Validation, PSD2 (Qualified, eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QEVCPWPSD2EIDAS_PRECERTIFICATE:               {Name: "etsi_leaf_tlsserver_qevcpwpsd2eidas_precertificate", Source: "EN 319 412", Description: "ETSI Website Authentication Precertificate: Extended Validation, PSD2 (Qualified, eIDAS)", Autodetectable: true},
		ETSI_LEAF_TLSSERVER_QEVCPWPSD2EIDASNONBROWSER:                    {Name: "etsi_leaf_tlsserver_qevcpwpsd2eidasnonbrowser", Source: "EN 319 412", Description: "ETSI Website Authentication Certificate: Extended Validation, PSD2 (Qualified, eIDAS, non-Browser)", Autodetectable: false},
		ETSI_LEAF_TLSSERVER_QEVCPWPSD2EIDASNONBROWSER_PRECERTIFICATE:     {Name: "etsi_leaf_tlsserver_qevcpwpsd2eidasnonbrowser_precertificate", Source: "EN 319 412", Description: "ETSI Website Authentication Precertificate: Extended Validation, PSD2 (Qualified, eIDAS, non-Browser)", Autodetectable: false},
		ETSI_LEAF_NCPNATURALPERSON:                                       {Name: "etsi_leaf_ncpnaturalperson", Source: "EN 319 412", Description: "ETSI Electronic Seal Certificate: Natural Person", Autodetectable: false},
		ETSI_LEAF_NCPLEGALPERSON:                                         {Name: "etsi_leaf_ncplegalperson", Source: "EN 319 412", Description: "ETSI Electronic Seal Certificate: Legal Person ", Autodetectable: false},
	}

	AllProfilesOrdered                                                                                                                                                                                                       []Profile
	CrlProfileIDs, OcspProfileIDs, RootProfileIDs, SubordinateProfileIDs, SbrLeafProfileIDs, TbrTevgLeafProfileIDs, TbrTevgCertificateProfileIDs, NonCabforumProfileIDs, NonCertificateProfileIDs, EtsiCertificateProfileIDs []ProfileId
)

func init() {
	AllProfilesOrdered = make([]Profile, len(AllProfiles))
	for i := 0; i < len(AllProfiles); i++ {
		AllProfilesOrdered[i] = AllProfiles[ProfileId(i)]
	}

	// First pass.  Populate lists that don't intersect with other lists.
	for k, v := range AllProfiles {
		if strings.HasSuffix(v.Name, "_crl") || strings.HasSuffix(v.Name, "_arl") {
			CrlProfileIDs = append(CrlProfileIDs, k)
		} else if strings.HasSuffix(v.Name, "_ocspresponse") {
			OcspProfileIDs = append(OcspProfileIDs, k)
		} else if strings.Contains(v.Name, "_root_") || strings.HasSuffix(v.Name, "_root") {
			RootProfileIDs = append(RootProfileIDs, k)
		} else if strings.Contains(v.Name, "_subordinate_") || strings.HasSuffix(v.Name, "_subordinate") || strings.Contains(v.Name, "_cross_") {
			SubordinateProfileIDs = append(SubordinateProfileIDs, k)
		} else if strings.HasPrefix(v.Name, "sbr_leaf_") {
			SbrLeafProfileIDs = append(SbrLeafProfileIDs, k)
		} else if strings.HasPrefix(v.Name, "tbr_leaf_") || strings.HasPrefix(v.Name, "tevg_leaf_") || (strings.HasPrefix(v.Name, "etsi_leaf_tlsserver_") && !strings.Contains(v.Name, "person")) {
			TbrTevgLeafProfileIDs = append(TbrTevgLeafProfileIDs, k)
		}
	}

	// Second pass.  NonCabforumProfileIDs intersects with other lists, and TbrTevgCertificateProfileIDs requires CrlProfileIDs to be populated first.
	for k, v := range AllProfiles {
		if !strings.HasPrefix(v.Name, "tbr_") && !strings.HasPrefix(v.Name, "tevg_") && !strings.HasPrefix(v.Name, "sbr_") && !strings.HasPrefix(v.Name, "csbr_") {
			NonCabforumProfileIDs = append(NonCabforumProfileIDs, k)
		} else if (strings.HasPrefix(v.Name, "tbr_") || strings.HasPrefix(v.Name, "tevg_") || (strings.HasPrefix(v.Name, "etsi_leaf_tlsserver_") && !strings.Contains(v.Name, "person"))) && !slices.Contains(CrlProfileIDs, k) && !slices.Contains(OcspProfileIDs, k) {
			TbrTevgCertificateProfileIDs = append(TbrTevgCertificateProfileIDs, k)
		}

		if strings.HasPrefix(v.Name, "etsi_") {
			EtsiCertificateProfileIDs = append(EtsiCertificateProfileIDs, k)
		}
	}

	// Third pass.  NonCertificateProfileIDs requires CrlProfileIDs and OcspProfileIDs to be populated first, and intersects with other lists.
	NonCertificateProfileIDs = append(CrlProfileIDs, OcspProfileIDs...)
}

func ProfileIDList(list []ProfileId) string {
	var s strings.Builder
	for _, id := range list {
		s.WriteString(fmt.Sprintf(",%d", id))
	}
	return s.String()[1:]
}
