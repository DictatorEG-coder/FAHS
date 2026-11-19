import unittest
from types import SimpleNamespace
from fahs.handlers import URL_RE, _allow_scan, SCAN_EVENTS, GLOBAL_SCAN_EVENTS, _extract_message_urls


class URLExtractionTests(unittest.TestCase):
    def test_does_not_treat_email_address_as_a_url(self):
        self.assertEqual(URL_RE.findall("راسلني على user@example.com"), [])

    def test_extracts_bare_domain_and_explicit_url(self):
        found = URL_RE.findall("example.com ثم https://safe.example/path")
        self.assertEqual(found, ["example.com", "https://safe.example/path"])

    def test_extracts_ipv4_link(self):
        self.assertEqual(URL_RE.findall("127.0.0.1"), ["127.0.0.1"])

    def test_deduplicates_visible_and_embedded_text_links(self):
        message = SimpleNamespace(
            text="افتح example.com", caption=None,
            entities=[SimpleNamespace(type="text_link", url="https://example.com/")],
            caption_entities=None,
        )
        self.assertEqual(_extract_message_urls(message), ["example.com"])

    def test_extracts_at_most_three_unique_links(self):
        message = SimpleNamespace(
            text="a.example b.example c.example d.example", caption=None,
            entities=[], caption_entities=[],
        )
        self.assertEqual(len(_extract_message_urls(message)), 3)



class ScanRateLimitTests(unittest.TestCase):
    def setUp(self):
        SCAN_EVENTS.clear()
        GLOBAL_SCAN_EVENTS.clear()

    def tearDown(self):
        SCAN_EVENTS.clear()
        GLOBAL_SCAN_EVENTS.clear()

    def test_per_sender_limit_is_eight_per_minute(self):
        self.assertTrue(all(_allow_scan(1001, now=10 + i * 0.01) for i in range(8)))
        self.assertFalse(_allow_scan(1001, now=11))
        self.assertTrue(_allow_scan(1001, now=71))

    def test_global_limit_caps_total_scan_volume(self):
        for actor in range(120):
            self.assertTrue(_allow_scan(actor, now=100))
        self.assertFalse(_allow_scan(9999, now=100))

    def test_rate_limit_buckets_remain_bounded(self):
        import fahs.handlers as handlers
        old_limit = handlers.MAX_RATE_BUCKETS
        handlers.MAX_RATE_BUCKETS = 3
        try:
            for actor in range(10):
                _allow_scan(actor, now=200)
            self.assertLessEqual(len(SCAN_EVENTS), 3)
        finally:
            handlers.MAX_RATE_BUCKETS = old_limit





class SecurityContentTests(unittest.TestCase):
    def test_quiz_answers_are_valid(self):
        from fahs.content import QUIZ
        self.assertGreaterEqual(len(QUIZ), 20)
        for question, options, correct, explanation in QUIZ:
            self.assertTrue(question.strip())
            self.assertGreaterEqual(len(options), 2)
            self.assertGreaterEqual(correct, 0)
            self.assertLess(correct, len(options))
            self.assertTrue(explanation.strip())

    def test_every_emergency_playbook_has_actionable_content(self):
        from fahs.content import EMERGENCY
        self.assertGreaterEqual(len(EMERGENCY), 12)
        for title, instructions in EMERGENCY.items():
            self.assertTrue(title.strip())
            self.assertGreater(len(instructions), 80)

    def test_protection_center_has_ten_guides(self):
        from fahs.handlers import PROTECTION_GUIDES
        self.assertEqual(len(PROTECTION_GUIDES), 10)
        for key, (title, body) in PROTECTION_GUIDES.items():
            self.assertTrue(key.isidentifier())
            self.assertTrue(title.strip())
            self.assertGreater(len(body), 150)

    def test_glossary_is_large_enough_for_multiple_pages(self):
        from fahs.content import GLOSSARY
        self.assertGreaterEqual(len(GLOSSARY), 10)


if __name__ == "__main__":
    unittest.main()


class EditableContentTests(unittest.TestCase):
    def test_admin_categories_cover_educational_content_not_link_scanner(self):
        from fahs.handlers import CONTENT_CATEGORIES
        self.assertEqual(
            set(CONTENT_CATEGORIES),
            {"scams", "ai_scams", "data", "protection", "emergency", "glossary", "tips"},
        )
        self.assertNotIn("scanner", CONTENT_CATEGORIES)

    def test_catalog_applies_edits_additions_and_deletions(self):
        from unittest.mock import patch
        from fahs.handlers import _catalog_items
        with patch("fahs.handlers.db.get_content_overrides", return_value={
            "تصيد عبر الرسائل": {
                "title": "تصيد برسالة مزيفة (محدّث)",
                "body": "شرح جديد قابل للتعديل.",
                "deleted": False,
            },
            "hidden-item": {
                "title": "محتوى محذوف",
                "body": "لن يظهر",
                "deleted": True,
            },
            "custom-item": {
                "title": "احتيال جديد",
                "body": "شرح طريقة الاحتيال الجديدة.",
                "deleted": False,
            },
        }):
            items = _catalog_items("scams")
        titles = [title for _, title, _ in items]
        self.assertIn("تصيد برسالة مزيفة (محدّث)", titles)
        self.assertIn("احتيال جديد", titles)
        self.assertNotIn("محتوى محذوف", titles)

    def test_emergency_and_glossary_use_editable_catalogs(self):
        from unittest.mock import patch
        from fahs.handlers import _catalog_items
        with patch("fahs.handlers.db.get_content_overrides", return_value={}):
            self.assertGreaterEqual(len(_catalog_items("emergency")), 12)
            self.assertGreaterEqual(len(_catalog_items("glossary")), 10)
            self.assertGreaterEqual(len(_catalog_items("tips")), 1)


