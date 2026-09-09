import io
import unittest

from pem_input import read_pem_requests


class ReadPemRequestsTest(unittest.TestCase):
    def test_multiple_requests_and_all_supported_types(self):
        expected = [
            (3, "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n"),
            (32, "-----BEGIN X509 CRL-----\nZGVm\n-----END X509 CRL-----\n"),
            (13, "-----BEGIN OCSP RESPONSE-----\nZ2hp\n-----END OCSP RESPONSE-----\n"),
        ]
        wire = "".join(f"{profile}\n{pem}" for profile, pem in expected)
        self.assertEqual(list(read_pem_requests(io.StringIO(wire))), expected)

    def test_whitespace_and_crlf_are_normalized(self):
        wire = (
            " 32 \r\n  -----BEGIN X509 CRL----- \r\n"
            "\tYWJj \r\n -----END X509 CRL----- \r\n"
        )
        expected = "-----BEGIN X509 CRL-----\nYWJj\n-----END X509 CRL-----\n"
        self.assertEqual(list(read_pem_requests(io.StringIO(wire))), [(32, expected)])

    def test_large_request_followed_by_small_request(self):
        # Roughly 6 MiB of PEM, followed by another request on the same worker.
        large = (
            "-----BEGIN X509 CRL-----\n"
            + ("A" * 64 + "\n") * 100000
            + "-----END X509 CRL-----\n"
        )
        small = "-----BEGIN X509 CRL-----\nYWJj\n-----END X509 CRL-----\n"
        wire = f"32\n{large}11\n{small}"
        self.assertEqual(
            list(read_pem_requests(io.StringIO(wire))), [(32, large), (11, small)]
        )

    def test_incomplete_input_is_not_dispatched(self):
        for wire in ["", "32\n", "32\n-----BEGIN X509 CRL-----\nYWJj\n"]:
            with self.subTest(wire=wire):
                self.assertEqual(list(read_pem_requests(io.StringIO(wire))), [])

    def test_invalid_profile_is_rejected(self):
        with self.assertRaises(ValueError):
            list(read_pem_requests(io.StringIO("invalid\n")))


if __name__ == "__main__":
    unittest.main()
