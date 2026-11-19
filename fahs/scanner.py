"""Conservative URL inspection. This is indicator-based, never a safety guarantee."""
import ipaddress
import re
import socket
from urllib.parse import urlsplit, urlunsplit, parse_qsl
import httpx
from fahs.config import settings

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account", "update", "wallet",
    "password", "bonus", "gift", "prize", "free", "claim", "bank", "support",
    "تسجيل", "تحقق", "حساب", "جائزة", "هدية", "بنك", "محفظة"
}
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly"}
SENSITIVE_KEYS = {"token", "access_token", "auth", "key", "session", "code", "password", "otp", "secret", "sid"}

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
    if len(raw) > settings.max_url_length:
        raise ValueError("الرابط أطول من الحد المسموح")
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
    if port and port not in {80, 443, 8080, 8443}:
        raise ValueError("منفذ غير معتاد؛ أُوقف الفحص الوقائي")
    host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    return urlunsplit((parts.scheme.lower(), host + (f":{port}" if port else ""), parts.path or "/", parts.query, ""))

def _has_sensitive_query(url: str) -> bool:
    return any(k.lower() in SENSITIVE_KEYS for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True))

async def _redirect_chain(start: str) -> tuple[list[str], str | None]:
    chain, current = [], start
    headers = {"User-Agent": "FAHS-Security-Link-Inspector/0.1"}
    async with httpx.AsyncClient(timeout=settings.request_timeout, follow_redirects=False, trust_env=False, headers=headers) as client:
        for _ in range(settings.max_redirects + 1):
            parts = urlsplit(current)
            try:
                _resolve_public(parts.hostname or "")
            except ValueError as exc:
                return chain, str(exc)
            chain.append(current)
            if _has_sensitive_query(current):
                return chain, "توقفنا لأن الرابط يحتوي على معاملات قد تكون رموز وصول أو بيانات حساسة"
            try:
                async with client.stream("GET", current, headers={"Range": "bytes=0-0"}) as response:
                    status_code = response.status_code
                    location = response.headers.get("location")
                    response_url = response.url
            except httpx.HTTPError:
                return chain, "تعذر تأكيد سلسلة التحويلات؛ قد يمنع الموقع طلبات الفحص"
            if status_code not in {301, 302, 303, 307, 308}:
                return chain, None
            if not location:
                return chain, "استجابة تحويل بلا وجهة واضحة"
            current = _normalise(str(response_url.join(location)))
        return chain, "تجاوز الرابط الحد الأقصى للتحويلات"

async def scan_url(raw: str) -> dict:
    try:
        url = _normalise(raw)
        parts = urlsplit(url)
        host = parts.hostname or ""
        addresses = _resolve_public(host)
    except (ValueError, UnicodeError) as exc:
        return {"level": "تعذر إكمال الفحص", "score": 0, "reasons": [str(exc)], "url": "", "host": "", "chain": []}

    reasons = []
    score = 0
    labels = [x for x in re.split(r"[./_-]", host) if x]
    if host in SHORTENERS:
        score += 1
        reasons.append("الرابط يستخدم خدمة اختصار؛ الوجهة النهائية تحتاج تحققًا")
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
    chain, redirect_note = await _redirect_chain(url)
    if redirect_note:
        reasons.append(redirect_note)
    if len(chain) > 1:
        score += 1
        reasons.append(f"رُصدت {len(chain)-1} عملية تحويل")
    if redirect_note and "تجاوز" in redirect_note:
        score += 2

    if score >= 4:
        level = "مرتفع"
    elif score >= 2:
        level = "متوسط"
    elif score == 1:
        level = "مؤشرات اشتباه"
    else:
        level = "لم تظهر مؤشرات اشتباه أولية"

    return {"level": level, "score": score, "reasons": reasons or ["لم تظهر مؤشرات تركيبية واضحة."],
            "url": url, "host": host, "ips": addresses, "chain": chain}
