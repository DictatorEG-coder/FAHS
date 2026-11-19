import unittest
import socket
from unittest.mock import patch
from fahs.scanner import _normalise, _resolve_public, _has_sensitive_query, _brand_lookalike, _parse_urlhaus_entries, _scan_url

class ScannerUnitTests(unittest.TestCase):
    def test_adds_https_scheme(self):
        self.assertEqual(_normalise("example.com"), "https://example.com/")

    def test_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            _normalise("ftp://example.com/file")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            _normalise("https://user:pass@example.com")

    def test_rejects_control_characters(self):
        with self.assertRaises(ValueError):
            _normalise("https://example.com/\r\nHost: localhost")

    def test_rejects_unusual_ports(self):
        with self.assertRaises(ValueError):
            _normalise("https://example.com:8080/")

    def test_rejects_zero_port(self):
        with self.assertRaises(ValueError):
            _normalise("https://example.com:0/")

    def test_rejects_scheme_port_mismatch(self):
        with self.assertRaises(ValueError):
            _normalise("https://example.com:80/")

    def test_rejects_invalid_dns_label(self):
        with self.assertRaises(ValueError):
            _normalise("https://bad..example.com/")

    def test_detects_sensitive_query_parameter(self):
        self.assertTrue(_has_sensitive_query("https://example.com/?access_token=secret"))

    def test_detects_api_key_parameter(self):
        self.assertTrue(_has_sensitive_query("https://example.com/?api_key=secret"))

    def test_detects_camel_case_access_token(self):
        self.assertTrue(_has_sensitive_query("https://example.com/?accessToken=secret"))

    def test_detects_camel_case_api_key(self):
        self.assertTrue(_has_sensitive_query("https://example.com/?apiKey=secret"))

    def test_detects_verification_code(self):
        self.assertTrue(_has_sensitive_query("https://example.com/?verificationCode=123456"))

    def test_detects_jwt_query_parameter(self):
        self.assertTrue(_has_sensitive_query("https://example.com/?jwt=eyJhbGciOiJIUzI1NiJ9"))

    def test_detects_cookie_query_parameter(self):
        self.assertTrue(_has_sensitive_query("https://example.com/?sessionCookie=secret"))

    def test_removes_default_https_port(self):
        self.assertEqual(_normalise("https://example.com:443/path#section"),
                         "https://example.com/path")

    def test_removes_default_http_port(self):
        self.assertEqual(_normalise("http://example.com:80/"), "http://example.com/")

    def test_normalises_ipv6_authority(self):
        self.assertEqual(_normalise("https://[2606:4700:4700::1111]"),
                         "https://[2606:4700:4700::1111]/")

    def test_detects_brand_typo(self):
        self.assertEqual(_brand_lookalike("paypa1.com"), "paypal")

    def test_detects_brand_name_on_unofficial_domain(self):
        self.assertEqual(_brand_lookalike("paypal.net"), "paypal")

    def test_detects_brand_domain_nested_under_attacker_domain(self):
        self.assertEqual(_brand_lookalike("paypal.com.evil.example"), "paypal")

    def test_allows_official_brand_subdomain(self):
        self.assertIsNone(_brand_lookalike("login.paypal.com"))

    def test_parses_urlhaus_malware_feed_without_non_malware_entries(self):
        payload = {
            "query_status": "ok",
            "urls": [
                {"url": "https://bad.example/payload", "url_status": "online", "threat": "malware_download"},
                {"url": "https://phish.example/login", "url_status": "online", "threat": "phishing"}
            ]
        }
        self.assertEqual(_parse_urlhaus_entries(payload),
                         {"https://bad.example/payload": "online"})

    def test_rejects_dns_answers_mixing_public_and_private_ips(self):
        answers = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
        ]
        with patch("fahs.scanner.socket.getaddrinfo", return_value=answers):
            with self.assertRaises(ValueError):
                _resolve_public("mixed.example")

    def test_accepts_only_public_dns_answers(self):
        answers = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
        ]
        with patch("fahs.scanner.socket.getaddrinfo", return_value=answers):
            self.assertEqual(_resolve_public("public.example"), ["1.1.1.1", "8.8.8.8"])

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


class SensitiveURLShortCircuitTests(unittest.IsolatedAsyncioTestCase):
    async def test_sensitive_query_stops_before_feed_or_dns_calls(self):
        from unittest.mock import AsyncMock
        with patch("fahs.scanner._openphish_entries", new=AsyncMock(side_effect=AssertionError("feed should not run"))), \
             patch("fahs.scanner._urlhaus_entries", new=AsyncMock(side_effect=AssertionError("feed should not run"))), \
             patch("fahs.scanner._resolve_public", side_effect=AssertionError("DNS should not run")):
            result = await _scan_url("https://example.com/login?access_token=secret")
        self.assertEqual(result["level"], "تعذر إكمال الفحص")
        self.assertEqual(result["host"], "example.com")
        self.assertEqual(result["chain"], [])
        self.assertIn("قبل استعلام DNS", result["reasons"][0])


