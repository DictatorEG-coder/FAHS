import unittest
from unittest.mock import AsyncMock, patch

from fahs.scanner import _redirect_chain


class FakeReader:
    def __init__(self, lines):
        self.lines = iter(lines)

    async def readline(self):
        return next(self.lines, b"")


class FakeWriter:
    def __init__(self):
        self.data = b""
        self.closed = False

    def write(self, data):
        self.data += data

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


class RedirectSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def test_connects_to_validated_ip_and_keeps_hostname_for_tls(self):
        reader = FakeReader([b"HTTP/1.1 200 OK\\r\\n", b"\\r\\n"])
        writer = FakeWriter()
        with patch("fahs.scanner._resolve_public", return_value=["93.184.216.34"]), \\
             patch("fahs.scanner.asyncio.open_connection", new_callable=AsyncMock) as connect:
            connect.return_value = (reader, writer)
            chain, note = await _redirect_chain("https://example.com/")

        self.assertEqual(chain, ["https://example.com/"])
        self.assertIsNone(note)
        self.assertEqual(connect.await_args.kwargs["host"], "93.184.216.34")
        self.assertEqual(connect.await_args.kwargs["server_hostname"], "example.com")
        self.assertTrue(writer.closed)

    async def test_revalidates_redirect_destination_before_connecting(self):
        reader = FakeReader([
            b"HTTP/1.1 302 Found\\r\\n",
            b"Location: http://127.0.0.1/\\r\\n",
            b"\\r\\n",
        ])
        writer = FakeWriter()
        with patch("fahs.scanner._resolve_public", side_effect=[
            ["93.184.216.34"],
            ValueError("العنوان يشير إلى شبكة خاصة أو محلية"),
        ]), patch("fahs.scanner.asyncio.open_connection", new_callable=AsyncMock) as connect:
            connect.return_value = (reader, writer)
            chain, note = await _redirect_chain("https://example.com/")

        self.assertEqual(chain, ["https://example.com/"])
        self.assertIn("شبكة خاصة", note)
        connect.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
