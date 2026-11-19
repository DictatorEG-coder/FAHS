import unittest
from unittest.mock import AsyncMock, patch

from fahs.reminders import RETRY_DELAY_SECONDS, _deliver_user


class ReminderDeliveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_successful_delivery_is_recorded(self):
        bot = AsyncMock()
        retry_after = {}
        with (
            patch("fahs.reminders.db.get_reminders", return_value=True),
            patch("fahs.reminders.db.reminder_due", return_value=True),
            patch("fahs.reminders.db.mark_reminder_sent") as mark_sent,
        ):
            await _deliver_user(bot, 123, "2026-11-19", retry_after, 100.0)

        bot.send_message.assert_awaited_once()
        mark_sent.assert_called_once_with(123, "2026-11-19")
        self.assertNotIn(123, retry_after)

    async def test_transient_failure_is_retried_after_cooldown(self):
        bot = AsyncMock()
        bot.send_message.side_effect = [RuntimeError("temporary Telegram outage"), None]
        retry_after = {}
        with (
            patch("fahs.reminders.db.get_reminders", return_value=True),
            patch("fahs.reminders.db.reminder_due", return_value=True),
            patch("fahs.reminders.db.mark_reminder_sent") as mark_sent,
        ):
            await _deliver_user(bot, 456, "2026-11-19", retry_after, 100.0)
            self.assertEqual(retry_after[456], 100.0 + RETRY_DELAY_SECONDS)
            mark_sent.assert_not_called()

            await _deliver_user(bot, 456, "2026-11-19", retry_after, 200.0)
            bot.send_message.assert_awaited_once()
            mark_sent.assert_not_called()

            await _deliver_user(bot, 456, "2026-11-19", retry_after, 100.0 + RETRY_DELAY_SECONDS)
            bot.send_message.assert_awaited_twice()
            mark_sent.assert_called_once_with(456, "2026-11-19")
            self.assertNotIn(456, retry_after)


if __name__ == "__main__":
    unittest.main()
