"""
security.py - central security layer for Digital Mall.

Everything security-related that is not business logic lives here so it can be
reviewed in one place:

  * CSRF protection (session token + Origin check)
  * Security headers + Content-Security-Policy (per-request nonce)
  * In-memory rate limiter
  * Upload validation / image re-encoding
  * Safe redirect + safe external URL helpers
"""
import hmac
import io
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from functools import wraps
from urllib.parse import urlparse

from flask import abort, g, jsonify, request, session
from flask_login import current_user
from PIL import Image, ImageOps

# Refuse decompression bombs (default Pillow limit only warns).
Image.MAX_IMAGE_PIXELS = 100_000_000

# Endpoints that cannot carry a CSRF token (server-to-server callbacks).
CSRF_EXEMPT_ENDPOINTS = {"paystack_webhook"}


# ------------------------------------------------------------------
# CSRF
# ------------------------------------------------------------------
def csrf_token() -> str:
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def _wants_json() -> bool:
    return request.is_json or request.headers.get("X-CSRFToken") is not None \
        or request.accept_mimetypes.best == "application/json"


def csrf_protect():
    """before_request hook: reject unsafe requests without a valid token."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    if request.endpoint in CSRF_EXEMPT_ENDPOINTS:
        return None

    # Layer 1: if the browser sent an Origin header, it must be us.
    origin = request.headers.get("Origin")
    if origin and origin != "null":
        if urlparse(origin).netloc != request.host:
            return _csrf_fail()

    # Layer 2: synchroniser token (form field or header for fetch()).
    sent = request.headers.get("X-CSRFToken") or request.form.get("csrf_token", "")
    expected = session.get("_csrf", "")
    if not expected or not sent or not hmac.compare_digest(str(sent), str(expected)):
        return _csrf_fail()
    return None


def _csrf_fail():
    if _wants_json():
        return jsonify({"error": "Security check failed. Please refresh the page."}), 400
    abort(400, description="Security check failed. Please go back, refresh the page and try again.")


# ------------------------------------------------------------------
# Security headers + CSP
# ------------------------------------------------------------------
def new_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


def build_csp(nonce: str, host: str, is_prod: bool) -> str:
    directives = [
        "default-src 'self'",
        f"script-src 'self' 'nonce-{nonce}' https://cdn.tailwindcss.com https://cdn.socket.io",
        # Tailwind's CDN build injects <style>; remove 'unsafe-inline' once Tailwind is built locally.
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "img-src 'self' data: https://res.cloudinary.com",
        "media-src 'self' https://res.cloudinary.com",
        "font-src 'self' data: https://fonts.gstatic.com",
        f"connect-src 'self' wss://{host} ws://{host}" if not is_prod else f"connect-src 'self' wss://{host}",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
        # Paystack is reached through redirects after form POSTs, so it must be allowed here.
        "form-action 'self' https://checkout.paystack.com https://*.paystack.co",
    ]
    if is_prod:
        directives.append("upgrade-insecure-requests")
    return "; ".join(directives)


def apply_security_headers(response, is_prod: bool, csp_mode: str):
    h = response.headers
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "strict-origin-when-cross-origin"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["X-Permitted-Cross-Domain-Policies"] = "none"
    if is_prod:
        h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

    if request.endpoint != "static":
        nonce = getattr(g, "csp_nonce", None)
        if nonce:
            header = "Content-Security-Policy" if csp_mode == "enforce" else "Content-Security-Policy-Report-Only"
            h[header] = build_csp(nonce, request.host, is_prod)
        # Never let browsers/proxies cache pages that can contain personal data.
        if current_user.is_authenticated:
            h["Cache-Control"] = "no-store"
            h["Pragma"] = "no-cache"
    return response


# ------------------------------------------------------------------
# Rate limiting (in-memory; fine for one process, use Redis for many)
# ------------------------------------------------------------------
class RateLimiter:
    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def allow(self, key: str, limit: int, window: int) -> bool:
        now = time.monotonic()
        with self._lock:
            if now - self._last_sweep > 300:
                self._sweep(now)
            dq = self._hits[key]
            while dq and dq[0] <= now - window:
                dq.popleft()
            if len(dq) >= limit:
                return False
            dq.append(now)
            return True

    def _sweep(self, now):
        # Drop keys that have been idle for over an hour so memory stays bounded.
        for k in [k for k, dq in self._hits.items() if not dq or dq[-1] < now - 3600]:
            del self._hits[k]
        self._last_sweep = now


limiter = RateLimiter()


def client_ip() -> str:
    return request.remote_addr or "unknown"


def rate_limit(limit: int, window: int, scope: str, per_user: bool = False):
    """Decorator. 429 when the caller exceeds `limit` hits per `window` seconds."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            ident = f"u{current_user.get_id()}" if per_user and current_user.is_authenticated else client_ip()
            if not limiter.allow(f"{scope}:{ident}", limit, window):
                if _wants_json():
                    return jsonify({"error": "Too many requests. Please slow down."}), 429
                abort(429)
            return fn(*a, **kw)
        return wrapper
    return deco


# ------------------------------------------------------------------
# Redirect + URL safety
# ------------------------------------------------------------------
def safe_next_url(target: str) -> bool:
    """True only for same-site relative paths. Blocks //evil.com, /\\evil.com, javascript:, etc."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return False
    parsed = urlparse(target)
    return not parsed.scheme and not parsed.netloc and not any(ord(c) < 32 for c in target)


def safe_http_url(url: str, max_len: int = 200):
    """Return url if it is a plain http(s) URL, else None (blocks javascript:, data:, etc.)."""
    url = (url or "").strip()
    if not url or len(url) > max_len or any(ord(c) < 32 or c in '<>"\' ' for c in url):
        return None
    p = urlparse(url)
    if p.scheme in ("http", "https") and p.netloc:
        return url
    return None


# ------------------------------------------------------------------
# Upload validation
# ------------------------------------------------------------------
IMAGE_EXT = {"png", "jpg", "jpeg", "webp", "gif"}
VIDEO_EXT = {"mp4", "webm", "mov"}
MAX_IMAGE_BYTES = 15 * 1024 * 1024   # raw upload; big phone photos are shrunk below, not rejected
MAX_GIF_BYTES = 5 * 1024 * 1024
MAX_VIDEO_BYTES = 50 * 1024 * 1024   # must stay under MAX_CONTENT_LENGTH in app.py
MAX_IMAGE_SIDE = 2000                # longest edge after shrinking (plenty for a shop page)
_PIL_TO_EXT = {"JPEG": "jpg", "PNG": "png", "WEBP": "webp", "GIF": "gif"}


def _stream_size(stream) -> int:
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(0)
    return size


def sanitize_upload(f, kind: str):
    """
    Validate an uploaded FileStorage. kind: "image" or "video".
    Returns a file-like object that is safe to hand to Cloudinary, or None if rejected.
    Images are fully decoded and RE-ENCODED, which strips EXIF/GPS data and
    destroys polyglot payloads hidden in the file.
    """
    if not f or not f.filename:
        return None
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    size = _stream_size(f.stream)
    if size == 0:
        return None

    if kind == "image":
        if ext not in IMAGE_EXT or size > MAX_IMAGE_BYTES:
            return None
        try:
            img = Image.open(f.stream)
            fmt = img.format
            if fmt not in _PIL_TO_EXT:
                return None
            img.verify()                      # structural check
            f.stream.seek(0)
            img = Image.open(f.stream)        # verify() invalidates the object
            if fmt == "GIF":
                if size > MAX_GIF_BYTES:
                    return None
                f.stream.seek(0)              # keep animation; already structurally verified
                return f.stream
            if fmt == "JPEG":
                img.draft("RGB", (MAX_IMAGE_SIDE * 2, MAX_IMAGE_SIDE * 2))  # decode big JPEGs at lower res: saves RAM
            img = ImageOps.exif_transpose(img)
            if fmt == "JPEG" and img.mode not in ("RGB", "L"):
                img = img.convert("RGB")
            img.thumbnail((MAX_IMAGE_SIDE, MAX_IMAGE_SIDE))   # shrink only if larger; keeps aspect ratio
            out = io.BytesIO()
            save_kwargs = {"quality": 85, "optimize": True} if fmt in ("JPEG", "WEBP") else {}
            img.save(out, format=fmt, **save_kwargs)   # no exif= argument -> metadata dropped
            out.seek(0)
            out.name = f"upload.{_PIL_TO_EXT[fmt]}"
            return out
        except Exception:
            return None

    if kind == "video":
        if ext not in VIDEO_EXT or size > MAX_VIDEO_BYTES:
            return None
        head = f.stream.read(12)
        f.stream.seek(0)
        is_mp4_mov = len(head) >= 8 and head[4:8] == b"ftyp"
        is_webm = head[:4] == b"\x1a\x45\xdf\xa3"
        if ext in ("mp4", "mov") and is_mp4_mov:
            return f.stream
        if ext == "webm" and is_webm:
            return f.stream
        return None

    return None
