"""Conservative URL inspection. This is indicator-based, never a safety guarantee."""
import ipaddress
import asyncio
import re
import socket
import ssl
import time
from difflib import SequenceMatcher
from urllib.parse import urlsplit, urlunsplit, parse_qsl, quote
import httpx
from fahs.config import settings

_FEED_CACHE = {"expires": 0.0, "entries": set()}
_SCAN_SEMAPHORE = asyncio.Semaphore(8)

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account", "update", "wallet",
    "password", "bonus", "gift", "prize", "free", "claim", "bank", "support",
    "تسجيل", "تحقق", "حساب", "جائزة", "هدية", "بنك", "محفظة"
}
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly"}
BRANDS = {
    "paypal": "paypal.com", "telegram": "telegram.org", "google": "google.com",
    "facebook": "facebook.com", "microsoft": "microsoft.com", "apple": "apple.com",
    "amazon": "amazon.com", "instagram": "instagram.com", "whatsapp": "whatsapp.com",
    "tiktok": "tiktok.com", "netflix": "netflix.com", "binance": "binance.com"
}
SENSITIVE_KEY_RE = re.compile(r"(^|[_-])(token|auth|key|session|code|password|otp|secret|sid|ticket)([_-]|$)", re.I)

def _is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return ip.is_global

def _resolve_public(host: str) -> list[str]:
    try:
        literal = ipaddress.ip_address(host)
        if not literal.is_global:
            raise ValueError("العنوان يشير إلى شبكة خاصة أو محلية")
        return [str(literal)]
    except ValueError as exc:
        if "شبكة خاصة" in str(exc):
            raise
    addresses = set()
    try:
        for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            addr = item[4][0].split("%")[0]
            if not _is_public_ip(addr):
                raise ValueError("النطاق يحلّ إلى عنوان غير عام؛ أُوقف الاتصال للحماية")
            addresses.add(addr)
    except socket.gaierror:
        raise ValueError("تعذر العثور على عنوان DNS للنطاق")
    if not addresses:
        raise ValueError("لم يُعثر على سجلات DNS صالحة")
    return sorted(addresses)

def _normalise(raw: str) -> str:
    raw = raw.strip()
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise ValueError("يحتوي الرابط على محارف تحكم غير مسموحة")
    if len(raw) > settings.max_url_length:
        raise ValueError("الرابط أطول من الحد المسموح")
    if "://" in raw and not re.match(r"^https?://", raw, re.I):
        raise ValueError("يُسمح بروابط HTTP وHTTPS فقط")
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme.lower() not in {"http", "https"}:
        raise ValueError("يُسمح بروابط HTTP وHTTPS فقط")
    if not parts.hostname:
        raise ValueError("صيغة الرابط غير مكتملة")
    if parts.username or parts.password:
        raise ValueError("يحتوي الرابط على بيانات دخول؛ لن نفحصه حفاظًا على الخصوصية")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("رقم المنفذ غير صالح")
    if port and port not in {80, 443}:
        raise ValueError("منفذ غير معتاد؛ أُوقف الفحص الوقائي")
    host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    authority = f"[{host}]" if ":" in host else host
    authority += f":{port}" if port else ""
    return urlunsplit((parts.scheme.lower(), authority, parts.path or "/", parts.query, ""))

def _brand_lookalike(host: str) -> str | None:
    root = host.split(".")[0]
    compact = re.sub(r"[^a-z0-9]", "", root)
    for brand, official_domain in BRANDS.items():
        if host == official_domain or host.endswith("." + official_domain):
            continue
        if official_domain + "." in host:
            return brand
        similarity = SequenceMatcher(None, compact, brand).ratio()
        if compact != brand and similarity >= 0.80:
            return brand
    return None

def _has_sensitive_query(url: str) -> bool:
    return any(SENSITIVE_KEY_RE.search(k) for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True))

async def _redirect_chain(start: str) -> tuple[list[str], str | None]:
    """Follow only HEAD redirects, connecting to the exact IP that passed validation."""
    from urllib.parse import urljoin

    chain, current = [], start
    for _ in range(settings.max_redirects + 1):
        parts = urlsplit(current)
        host = parts.hostname or ""
        try:
            addresses = await asyncio.to_thread(_resolve_public, host)
        except ValueError as exc:
            return chain, str(exc)
        chain.append(current)
        if _has_sensitive_query(current):
            return chain, "توقفنا لأن الرابط يحتوي على معاملات قد تكون رموز وصول أو بيانات حساسة"

        port = parts.port or (443 if parts.scheme == "https" else 80)
        target_ip = addresses[0]
        tls = ssl.create_default_context() if parts.scheme == "https" else None
        path = quote(parts.path or "/", safe="/%:@!        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query'()*+,;=-._~")
        if parts.query:
            path += "?" + quote(parts.query, safe="=&?/%:@!
        authority = parts.netloc
        request = (
            f"HEAD {path} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "User-Agent: FAHS-Security-Link-Inspector/0.1\r\n"
            "Connection: close\r\n\r\n"
        )
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=target_ip,
                    port=port,
                    ssl=tls,
                    server_hostname=host if tls else None,
                ),
                timeout=settings.request_timeout,
            )
            writer.write(request.encode("ascii"))
            await asyncio.wait_for(writer.drain(), timeout=settings.request_timeout)
            status_line = await asyncio.wait_for(reader.readline(), timeout=settings.request_timeout)
            if len(status_line) > 4096 or not status_line.startswith(b"HTTP/"):
                return chain, "استجابة HTTP غير مفهومة من الموقع"
            try:
                status_code = int(status_line.split(b" ", 2)[1])
            except (IndexError, ValueError):
                return chain, "تعذر قراءة رمز استجابة HTTP"

            location = None
            total_header_bytes = len(status_line)
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=settings.request_timeout)
                total_header_bytes += len(line)
                if total_header_bytes > 16384:
                    return chain, "ترويسات استجابة الموقع أكبر من الحد المسموح"
                if line in (b"\r\n", b"\n", b""):
                    break
                if b":" not in line:
                    continue
                name, value = line.split(b":", 1)
                if name.strip().lower() == b"location":
                    location = value.decode("latin-1").strip()
        except (OSError, asyncio.TimeoutError, ssl.SSLError, UnicodeError):
            return chain, "تعذر تأكيد سلسلة التحويلات؛ قد يمنع الموقع طلبات الفحص"
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

        if status_code in {405, 501}:
            return chain, "الموقع لا يدعم طلب HEAD؛ تعذر تأكيد سلسلة التحويلات دون تنزيل محتوى الصفحة"
        if status_code not in {301, 302, 303, 307, 308}:
            return chain, None
        if not location:
            return chain, "استجابة تحويل بلا وجهة واضحة"
        try:
            current = _normalise(urljoin(current, location))
        except (ValueError, UnicodeError) as exc:
            return chain, f"وجهة التحويل غير صالحة: {exc}"
    return chain, "تجاوز الرابط الحد الأقصى للتحويلات"

async def _openphish_entries() -> set[str]:
    feed_url = settings.openphish_feed_url
    try:
        feed_parts = urlsplit(feed_url)
        if (feed_parts.scheme != "https" or feed_parts.hostname != "openphish.com"
                or feed_parts.port not in (None, 443) or feed_parts.username or feed_parts.password):
            return set()
    except ValueError:
        return set()

    now = time.monotonic()
    if now < _FEED_CACHE["expires"]:
        return _FEED_CACHE["entries"]
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
            async with client.stream("GET", feed_url) as response:
                response.raise_for_status()
                chunks = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > 5 * 1024 * 1024:
                        raise ValueError("OpenPhish feed exceeds the 5 MiB limit")
                    chunks.append(chunk)
                body = b"".join(chunks).decode("utf-8", errors="replace")
            entries = set()
            for line in body.splitlines():
                candidate = line.strip()
                if candidate.startswith(("https://", "http://")):
                    try:
                        entries.add(_normalise(candidate))
                    except (ValueError, UnicodeError):
                        continue
            _FEED_CACHE["entries"] = entries
            _FEED_CACHE["expires"] = now + 900
            return entries
    except (httpx.HTTPError, ValueError, UnicodeError):
        _FEED_CACHE["entries"] = set()
        _FEED_CACHE["expires"] = now + 300
        return set()

async def _scan_url(raw: str) -> dict:
    try:
        url = _normalise(raw)
        parts = urlsplit(url)
        host = parts.hostname or ""
    except (ValueError, UnicodeError) as exc:
        return {"level": "تعذر إكمال الفحص", "score": 0, "reasons": [str(exc)], "url": "", "host": "", "chain": []}

    feed_entries = await _openphish_entries()
    if url in feed_entries:
        return {"level": "خطر حرج", "score": 10,
                "reasons": ["تطابق الرابط حرفيًا مع مؤشر وارد في مصدر OpenPhish المفعّل."],
                "url": url, "host": host, "ips": [], "chain": [], "source": "OpenPhish"}
    try:
        addresses = await asyncio.to_thread(_resolve_public, host)
    except (ValueError, UnicodeError) as exc:
        return {"level": "تعذر إكمال الفحص", "score": 0, "reasons": [str(exc)], "url": url, "host": host, "chain": []}

    reasons = []
    score = 0
    labels = [x for x in re.split(r"[./_-]", host) if x]
    try:
        ipaddress.ip_address(host)
        score += 1
        reasons.append("الرابط يستخدم عنوان IP مباشرًا بدل اسم نطاق معروف")
    except ValueError:
        pass
    if host in SHORTENERS:
        score += 1
        reasons.append("الرابط يستخدم خدمة اختصار؛ الوجهة النهائية تحتاج تحققًا")
    lookalike = _brand_lookalike(host)
    if lookalike:
        score += 2
        reasons.append(f"اسم النطاق يشبه علامة معروفة ({lookalike}) دون أن يطابق نطاقها الرسمي")
    if len(host) > 45 or host.count("-") >= 3:
        score += 1
        reasons.append("تركيب النطاق طويل أو غير معتاد")
    if re.search(r"xn--", host):
        score += 2
        reasons.append("النطاق يستخدم ترميز IDN؛ تحقّق من تشابه الحروف")
    if sum(1 for word in SUSPICIOUS_WORDS if word in url.lower()) >= 1:
        score += 1
        reasons.append("يحتوي الرابط على كلمات شائعة في صفحات الاستدراج")
    if parts.scheme == "http":
        score += 1
        reasons.append("الاتصال لا يستخدم HTTPS")
    if len(labels) > 5:
        score += 1
        reasons.append("عدد مستويات النطاق الفرعية مرتفع")
    try:
        chain, redirect_note = await _redirect_chain(url)
    except (ValueError, UnicodeError) as exc:
        chain, redirect_note = [url], str(exc)
    if redirect_note:
        reasons.append(redirect_note)
        if any(term in redirect_note for term in ("غير عام", "خاصة", "محلية", "تجاوز")):
            score = max(score, 4)
    if any(step in feed_entries for step in chain):
        return {"level": "خطر حرج", "score": 10,
                "reasons": ["تطابقت إحدى وجهات التحويل مع مؤشر وارد في مصدر OpenPhish المفعّل."],
                "url": url, "host": host, "ips": addresses, "chain": chain, "source": "OpenPhish"}
    if len(chain) > 1:
        score += 1
        reasons.append(f"رُصدت {len(chain)-1} عملية تحويل")
    if redirect_note and "تجاوز" in redirect_note:
        score += 2

    if redirect_note and not any(term in redirect_note for term in ("غير عام", "خاصة", "محلية", "تجاوز")):
        level = "تعذر إكمال الفحص"
    elif score >= 4:
        level = "مرتفع"
    elif score >= 2:
        level = "متوسط"
    elif score == 1:
        level = "مؤشرات اشتباه"
    else:
        level = "لم تظهر مؤشرات اشتباه أولية"

    return {"level": level, "score": score, "reasons": reasons or ["لم تظهر مؤشرات تركيبية واضحة."],
            "url": url, "host": host, "ips": addresses, "chain": chain}


async def scan_url(raw: str) -> dict:
    async with _SCAN_SEMAPHORE:
        return await _scan_url(raw)
()*+,;~-._")
        authority = parts.netloc
        request = (
            f"HEAD {path} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "User-Agent: FAHS-Security-Link-Inspector/0.1\r\n"
            "Connection: close\r\n\r\n"
        )
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=target_ip,
                    port=port,
                    ssl=tls,
                    server_hostname=host if tls else None,
                ),
                timeout=settings.request_timeout,
            )
            writer.write(request.encode("ascii"))
            await asyncio.wait_for(writer.drain(), timeout=settings.request_timeout)
            status_line = await asyncio.wait_for(reader.readline(), timeout=settings.request_timeout)
            if len(status_line) > 4096 or not status_line.startswith(b"HTTP/"):
                return chain, "استجابة HTTP غير مفهومة من الموقع"
            try:
                status_code = int(status_line.split(b" ", 2)[1])
            except (IndexError, ValueError):
                return chain, "تعذر قراءة رمز استجابة HTTP"

            location = None
            total_header_bytes = len(status_line)
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=settings.request_timeout)
                total_header_bytes += len(line)
                if total_header_bytes > 16384:
                    return chain, "ترويسات استجابة الموقع أكبر من الحد المسموح"
                if line in (b"\r\n", b"\n", b""):
                    break
                if b":" not in line:
                    continue
                name, value = line.split(b":", 1)
                if name.strip().lower() == b"location":
                    location = value.decode("latin-1").strip()
        except (OSError, asyncio.TimeoutError, ssl.SSLError, UnicodeError):
            return chain, "تعذر تأكيد سلسلة التحويلات؛ قد يمنع الموقع طلبات الفحص"
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

        if status_code in {405, 501}:
            return chain, "الموقع لا يدعم طلب HEAD؛ تعذر تأكيد سلسلة التحويلات دون تنزيل محتوى الصفحة"
        if status_code not in {301, 302, 303, 307, 308}:
            return chain, None
        if not location:
            return chain, "استجابة تحويل بلا وجهة واضحة"
        try:
            current = _normalise(urljoin(current, location))
        except (ValueError, UnicodeError) as exc:
            return chain, f"وجهة التحويل غير صالحة: {exc}"
    return chain, "تجاوز الرابط الحد الأقصى للتحويلات"

async def _openphish_entries() -> set[str]:
    feed_url = settings.openphish_feed_url
    if not feed_url.startswith("https://"):
        return set()
    now = time.monotonic()
    if now < _FEED_CACHE["expires"]:
        return _FEED_CACHE["entries"]
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
            response = await client.get(feed_url)
            response.raise_for_status()
            entries = set()
            for line in response.text.splitlines():
                candidate = line.strip()
                if candidate.startswith("https://") or candidate.startswith("http://"):
                    try:
                        normal = _normalise(candidate)
                        entries.add(normal)
                    except ValueError:
                        continue
            _FEED_CACHE["entries"] = entries
            _FEED_CACHE["expires"] = now + 900
            return entries
    except (httpx.HTTPError, ValueError):
        _FEED_CACHE["entries"] = set()
        _FEED_CACHE["expires"] = now + 300
        return set()

async def _scan_url(raw: str) -> dict:
    try:
        url = _normalise(raw)
        parts = urlsplit(url)
        host = parts.hostname or ""
    except (ValueError, UnicodeError) as exc:
        return {"level": "تعذر إكمال الفحص", "score": 0, "reasons": [str(exc)], "url": "", "host": "", "chain": []}

    feed_entries = await _openphish_entries()
    if url in feed_entries:
        return {"level": "خطر حرج", "score": 10,
                "reasons": ["تطابق الرابط حرفيًا مع مؤشر وارد في مصدر OpenPhish المفعّل."],
                "url": url, "host": host, "ips": [], "chain": [], "source": "OpenPhish"}
    try:
        addresses = await asyncio.to_thread(_resolve_public, host)
    except (ValueError, UnicodeError) as exc:
        return {"level": "تعذر إكمال الفحص", "score": 0, "reasons": [str(exc)], "url": url, "host": host, "chain": []}

    reasons = []
    score = 0
    labels = [x for x in re.split(r"[./_-]", host) if x]
    try:
        ipaddress.ip_address(host)
        score += 1
        reasons.append("الرابط يستخدم عنوان IP مباشرًا بدل اسم نطاق معروف")
    except ValueError:
        pass
    if host in SHORTENERS:
        score += 1
        reasons.append("الرابط يستخدم خدمة اختصار؛ الوجهة النهائية تحتاج تحققًا")
    lookalike = _brand_lookalike(host)
    if lookalike:
        score += 2
        reasons.append(f"اسم النطاق يشبه علامة معروفة ({lookalike}) دون أن يطابق نطاقها الرسمي")
    if len(host) > 45 or host.count("-") >= 3:
        score += 1
        reasons.append("تركيب النطاق طويل أو غير معتاد")
    if re.search(r"xn--", host):
        score += 2
        reasons.append("النطاق يستخدم ترميز IDN؛ تحقّق من تشابه الحروف")
    if sum(1 for word in SUSPICIOUS_WORDS if word in url.lower()) >= 1:
        score += 1
        reasons.append("يحتوي الرابط على كلمات شائعة في صفحات الاستدراج")
    if parts.scheme == "http":
        score += 1
        reasons.append("الاتصال لا يستخدم HTTPS")
    if len(labels) > 5:
        score += 1
        reasons.append("عدد مستويات النطاق الفرعية مرتفع")
    try:
        chain, redirect_note = await _redirect_chain(url)
    except (ValueError, UnicodeError) as exc:
        chain, redirect_note = [url], str(exc)
    if redirect_note:
        reasons.append(redirect_note)
        if any(term in redirect_note for term in ("غير عام", "خاصة", "محلية", "تجاوز")):
            score = max(score, 4)
    if any(step in feed_entries for step in chain):
        return {"level": "خطر حرج", "score": 10,
                "reasons": ["تطابقت إحدى وجهات التحويل مع مؤشر وارد في مصدر OpenPhish المفعّل."],
                "url": url, "host": host, "ips": addresses, "chain": chain, "source": "OpenPhish"}
    if len(chain) > 1:
        score += 1
        reasons.append(f"رُصدت {len(chain)-1} عملية تحويل")
    if redirect_note and "تجاوز" in redirect_note:
        score += 2

    if redirect_note and not any(term in redirect_note for term in ("غير عام", "خاصة", "محلية", "تجاوز")):
        level = "تعذر إكمال الفحص"
    elif score >= 4:
        level = "مرتفع"
    elif score >= 2:
        level = "متوسط"
    elif score == 1:
        level = "مؤشرات اشتباه"
    else:
        level = "لم تظهر مؤشرات اشتباه أولية"

    return {"level": level, "score": score, "reasons": reasons or ["لم تظهر مؤشرات تركيبية واضحة."],
            "url": url, "host": host, "ips": addresses, "chain": chain}


async def scan_url(raw: str) -> dict:
    async with _SCAN_SEMAPHORE:
        return await _scan_url(raw)
