import os
import tempfile
import unittest

from fahs import db
from fahs.config import settings


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_path = settings.database_path
        object.__setattr__(settings, "database_path", os.path.join(self.temp.name, "fahs.sqlite3"))
        db.init_db()

    def tearDown(self):
        object.__setattr__(settings, "database_path", self.old_path)
        self.temp.cleanup()

    def test_group_allowlist_matches_subdomains(self):
        self.assertTrue(db.add_group_domain(-100, "example.com"))
        self.assertTrue(db.group_domain_allowed(-100, "example.com"))
        self.assertTrue(db.group_domain_allowed(-100, "login.example.com"))
        self.assertFalse(db.group_domain_allowed(-100, "example.net"))
        self.assertTrue(db.remove_group_domain(-100, "example.com"))
        self.assertFalse(db.group_domain_allowed(-100, "login.example.com"))

    def test_user_can_delete_stored_settings(self):
        db.touch_user(123)
        db.set_reminders(123, True)
        self.assertTrue(db.get_reminders(123))
        db.delete_user(123)
        self.assertFalse(db.get_reminders(123))
        self.assertFalse(db.reminder_due(123, "2026-11-19"))

    def test_scan_statistics_are_aggregated_without_url_or_user_fields(self):
        db.record_scan("مرتفع")
        db.record_scan("مرتفع")
        db.record_scan("لم تظهر مؤشرات اشتباه أولية")
        users, reminders, groups, scans, levels = db.stats()
        self.assertEqual(scans, 3)
        self.assertEqual(levels["مرتفع"], 2)
        self.assertEqual(levels["لم تظهر مؤشرات اشتباه أولية"], 1)

    def test_reminder_interval_is_limited_to_one_or_two_days(self):
        db.touch_user(456)
        db.set_reminder_interval(456, 2)
        self.assertEqual(db.get_reminder_interval(456), 2)
        with self.assertRaises(ValueError):
            db.set_reminder_interval(456, 3)


if __name__ == "__main__":
    unittest.main()
