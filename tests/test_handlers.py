import unittest
from fahs.handlers import URL_RE


class URLExtractionTests(unittest.TestCase):
    def test_does_not_treat_email_address_as_a_url(self):
        self.assertEqual(URL_RE.findall("راسلني على user@example.com"), [])

    def test_extracts_bare_domain_and_explicit_url(self):
        found = URL_RE.findall("example.com ثم https://safe.example/path")
        self.assertEqual(found, ["example.com", "https://safe.example/path"])

    def test_extracts_ipv4_link(self):
        self.assertEqual(URL_RE.findall("127.0.0.1"), ["127.0.0.1"])


if __name__ == "__main__":
    unittest.main()
