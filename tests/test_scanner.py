import unittest
from fahs.scanner import _normalise, _resolve_public, _has_sensitive_query

class ScannerUnitTests(unittest.TestCase):
    def test_adds_https_scheme(self):
        self.assertEqual(_normalise("example.com"), "https://example.com/")

    def test_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            _normalise("ftp://example.com/file")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            _normalise("https://user:pass@example.com")

    def test_detects_sensitive_query_parameter(self):
        self.assertTrue(_has_sensitive_query("https://example.com/?access_token=secret"))

    def test_detects_api_key_parameter(self):
        self.assertTrue(_has_sensitive_query("https://example.com/?api_key=secret"))

    def test_normalises_ipv6_authority(self):
        self.assertEqual(_normalise("https://[2606:4700:4700::1111]"),
                         "https://[2606:4700:4700::1111]/")

    def test_rejects_loopback_address(self):
        with self.assertRaises(ValueError):
            _resolve_public("127.0.0.1")

    def test_rejects_localhost_name(self):
        with self.assertRaises(ValueError):
            _resolve_public("localhost")

    def test_ipv6_loopback_is_rejected(self):
        with self.assertRaises(ValueError):
            _resolve_public("::1")

if __name__ == "__main__":
    unittest.main()
