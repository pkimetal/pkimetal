// Package pemreader holds the Python source for pkilint's PEM request reader.
// It is kept in its own package so it can be unit-tested without triggering the
// pkilint package's init(), which requires a configured pkilint install.
package pemreader

// Reader is the Python generator that reads the profile/PEM request protocol
// from a stream.  It collects normalized PEM lines and joins them once per
// request, avoiding quadratic string assembly for large inputs (e.g. big CRLs).
const Reader = `def read_pem_requests(stream):
	profile_id = None
	pem_lines = []
	for line in stream:
		if profile_id is None:
			profile_id = int(line.strip())
		else:
			pem_lines.append(line.strip() + "\n")

		if "END CERTIFICATE" in line or "END X509 CRL" in line or "END OCSP RESPONSE" in line:
			yield profile_id, "".join(pem_lines)
			profile_id = None
			pem_lines.clear()
`
