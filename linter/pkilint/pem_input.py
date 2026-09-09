def read_pem_requests(stream):
    """Read the profile/PEM protocol without repeatedly copying the input."""
    profile_id = None
    pem_lines = []
    for line in stream:
        if profile_id is None:
            profile_id = int(line.strip())
        else:
            pem_lines.append(line.strip() + "\n")

        if (
            "END CERTIFICATE" in line
            or "END X509 CRL" in line
            or "END OCSP RESPONSE" in line
        ):
            yield profile_id, "".join(pem_lines)
            profile_id = None
            pem_lines.clear()
