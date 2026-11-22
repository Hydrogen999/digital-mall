import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import tempfile
import time
import uuid
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from urllib.parse import quote

from itsdangerous import URLSafeTimedSerializer

import click
import cloudinary
import cloudinary.uploader
import cloudinary.utils
import requests
from flask import (
    Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for,
)
from flask_login import (
    LoginManager, current_user, login_required, login_user, logout_user,
)
from flask_mail import Mail, Message as MailMessage
from markupsafe import escape
from sqlalchemy.pool import NullPool
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from models import (
    Conversation, Order, OrderItem, Product, Reel, ReelLike, Review,
    Shop, User, Wishlist, Withdrawal, db,
)
from security import (
    apply_security_headers, client_ip, csrf_protect, csrf_token, limiter,
    new_csp_nonce, rate_limit, safe_http_url, safe_next_url, sanitize_upload,
)
from sockets import socketio

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("mall")
audit_log = logging.getLogger("mall.audit")

# ==================================================================
# CONFIG
# ==================================================================
APP_ENV = os.environ.get("APP_ENV", "production").lower()
IS_PROD = APP_ENV != "development"
CSP_MODE = os.environ.get("CSP_MODE", "report-only").lower()

ACTIVATION_FEE_NGN = 10000
MAX_PRODUCTS_PER_SHOP = 10_000     # live (non-deleted) products one shop may have
DASHBOARD_PRODUCTS_PER_PAGE = 24
PLATFORM_COMMISSION = 0.05
REEL_PROMO_FEE_NGN = 10000
PENDING_ORDER_TTL = timedelta(hours=2)


def _secret(name: str, min_len: int, dev_default: str, banned=()) -> str:
    val = os.environ.get(name, "")
    if IS_PROD:
        if len(val) < min_len or val in banned:
            raise RuntimeError(
                f"{name} is missing or too weak. Set a strong value in your environment "
                f"(at least {min_len} characters). Refusing to start in production."
            )
        return val
    return val or dev_default


SECRET_KEY = _secret("SECRET_KEY", 32, secrets.token_hex(32), banned=("dev-change-me-please",))
PAYSTACK_SECRET_KEY = _secret("PAYSTACK_SECRET_KEY", 10, "sk_test_dev_only", banned=("sk_test_xxxx",))

cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET"),
    secure=True,
)

def cloudinary_ready() -> bool:
    c = cloudinary.config()
    return bool(c.cloud_name and c.api_key and c.api_secret)


if not cloudinary_ready():
    log.warning("CLOUDINARY IS NOT CONFIGURED: image/video uploads will fail. "
                "Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET in your .env file.")

db_url = os.environ.get("DATABASE_URL", "sqlite:///mall.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# ==================================================================
# APP SETUP
# ==================================================================
app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SQLALCHEMY_DATABASE_URI=db_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={"poolclass": NullPool, "pool_pre_ping": True},
    MAX_CONTENT_LENGTH=64 * 1024 * 1024,   # videos up to 50MB + form fields
    MAX_FORM_MEMORY_SIZE=1024 * 1024,
    MAX_FORM_PARTS=200,
    SESSION_COOKIE_NAME="__Host-mall" if IS_PROD else "mall",
    SESSION_COOKIE_SECURE=IS_PROD,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    REMEMBER_COOKIE_SECURE=IS_PROD,
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get("MAIL_USERNAME"),
    MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD"),
    MAIL_DEFAULT_SENDER=os.environ.get("MAIL_USERNAME"),
)

db.init_app(app)
socketio.init_app(app)

# --- FIXED: Mail & Serializer are now OUTSIDE the config dictionary ---
mail = Mail(app)
serializer = URLSafeTimedSerializer(SECRET_KEY)

_hops = int(os.environ.get("TRUST_PROXY_HOPS", "1" if IS_PROD else "0"))
if _hops:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_hops, x_proto=_hops, x_host=_hops)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "error"
login_manager.session_protection = "basic"


@login_manager.user_loader
def load_user(uid):
    try:
        return db.session.get(User, int(uid))
    except (TypeError, ValueError):
        return None


# ==================================================================
# GENERIC HELPERS
# ==================================================================
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clip(value, n: int) -> str:
    return _CTRL.sub("", (value or "")).strip()[:n]


def clip_text(value, n: int) -> str:
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", (value or "")).strip()
    return s[:n]


def parse_int(raw, lo, hi):
    try:
        v = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return v if lo <= v <= hi else None


def parse_money(raw, lo: float, hi: float):
    try:
        d = Decimal(str(raw).strip().replace(",", ""))
    except (InvalidOperation, AttributeError):
        return None
    if not d.is_finite():
        return None
    d = d.quantize(Decimal("0.01"))
    if d < Decimal(str(lo)) or d > Decimal(str(hi)):
        return None
    return float(d)


def slugify(text: str) -> str:
    text = re.sub(r"[^\w\s-]", "", (text or "").lower())
    return re.sub(r"[-\s]+", "-", text).strip("-") or "shop"


def unique_slug(name: str) -> str:
    base = slugify(name)[:100]
    slug, i = base, 1
    while Shop.query.filter_by(slug=slug).first():
        i += 1
        slug = f"{base}-{i}"
    return slug


def normalize_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw or "")
    if digits.startswith("234"):
        return "+" + digits
    if digits.startswith("0") and len(digits) == 11:
        return "+234" + digits[1:]
    return digits


def is_valid_ng_phone(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw or "")
    return bool(re.match(r"^(234|0)[789][01]\d{8}$", digits))


EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
USERNAME_RE = re.compile(r"^[\w .'\-]{2,50}$")
DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


def audit(action: str, **details):
    audit_log.info("user=%s ip=%s action=%s %s", current_user.get_id(), client_ip(), action,
                   " ".join(f"{k}={v}" for k, v in details.items()))


def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if current_user.role != "admin":
            abort(404)
        return fn(*a, **kw)
    return wrapper


# ==================================================================
# EMAIL & UPLOADS
# ==================================================================
def send_email(to_email, subject, html_body):
    if not app.config["MAIL_USERNAME"]:
        return
    try:
        msg = MailMessage(clip(subject, 200), recipients=[to_email])
        msg.html = html_body
        mail.send(msg)
    except Exception:
        log.exception("Email failed to send")


def _send_to_cloudinary(stream, kind: str, **options):
    """
    Copy the (already validated) upload to a temp file and send that to Cloudinary.
    Videos use chunked upload, which is far more reliable for large files than one big request.
    On failure returns None and stores a short reason in g.upload_error (also written to the log).
    """
    g.upload_error = None
    suffix = os.path.splitext(getattr(stream, "name", "") or "")[1] or (".mp4" if kind == "video" else "")
    path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            shutil.copyfileobj(stream, tmp)
            path = tmp.name
        if kind == "video":
            return cloudinary.uploader.upload_large(path, resource_type="video", chunk_size=6_000_000, **options)
        return cloudinary.uploader.upload(path, resource_type="image", **options)
    except Exception as exc:
        g.upload_error = (str(exc) or exc.__class__.__name__)[:200]
        log.exception("Cloudinary upload failed (%s): %s", kind, g.upload_error)
        return None
    finally:
        if path and os.path.exists(path):
            os.unlink(path)


def upload_public(stream, kind: str):
    """Upload an already-validated stream to Cloudinary. Returns secure_url or None."""
    if stream is None:
        return None
    res = _send_to_cloudinary(stream, kind, folder="mall", unique_filename=True, overwrite=False)
    return res.get("secure_url") if res else None


def upload_private_id(stream):
    """KYC documents are stored as 'authenticated' assets - not reachable by a plain URL."""
    if stream is None:
        return None
    res = _send_to_cloudinary(stream, "image", type="authenticated", folder="mall_kyc",
                              unique_filename=True, overwrite=False)
    return ("private:" + res["public_id"]) if res else None


def delete_cloudinary_asset(url, resource_type="image"):
    """Best-effort removal of an asset we uploaded (used for abandoned, unpaid reel uploads)."""
    m = re.search(r"/upload/(?:v\d+/)?(.+?)(?:\.[A-Za-z0-9]+)?$", url or "")
    if not m or not cloudinary_ready():
        return
    try:
        cloudinary.uploader.destroy(m.group(1), resource_type=resource_type, invalidate=True)
    except Exception:
        log.exception("Could not delete Cloudinary asset %s", m.group(1))


@app.template_filter("kyc_url")
def kyc_url_filter(value):
    if not value:
        return ""
    if value.startswith("private:"):
        url, _ = cloudinary.utils.cloudinary_url(
            value[len("private:"):], type="authenticated", sign_url=True,
            secure=True, resource_type="image",
        )
        return url
    return value


@app.template_filter("from_json")
def from_json_filter(value):
    try:
        return json.loads(value or "[]")
    except Exception:
        return []


@app.template_filter("safe_url")
def safe_url_filter(value):
    return safe_http_url(value) or ""


# ==================================================================
# PAYSTACK
# ==================================================================
PAYSTACK_BASE = "https://api.paystack.co"


def _paystack(method, path, **kw):
    try:
        return requests.request(
            method, PAYSTACK_BASE + path, timeout=15,
            headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"},
            **kw,
        )
    except requests.RequestException:
        log.exception("Paystack request failed")
        return None


def initialize_paystack(email, amount_ngn, callback_url, reference, metadata=None):
    r = _paystack("POST", "/transaction/initialize", json={
        "email": email,
        "amount": int(round(amount_ngn * 100)),
        "currency": "NGN",
        "reference": reference,
        "callback_url": callback_url,
        "metadata": metadata or {},
    })
    if r is not None and r.status_code == 200:
        try:
            return r.json()["data"]["authorization_url"]
        except (ValueError, KeyError, TypeError):
            pass
    return None


def verify_paystack(reference):
    r = _paystack("GET", f"/transaction/verify/{quote(reference, safe='')}")
    if r is None or r.status_code != 200:
        return "error", None
    try:
        body = r.json()
        data = body.get("data") or {}
    except ValueError:
        return "error", None
    if body.get("status") and data.get("status") == "success":
        return "success", data
    return "failed", data


def activate_shop(shop):
    now = datetime.utcnow()
    shop.activation_paid = True
    shop.verification_status = "ACTIVE"
    shop.subscription_status = "ACTIVE"
    shop.is_approved = True
    if shop.subscription_expires_at and shop.subscription_expires_at > now:
        shop.subscription_expires_at += timedelta(days=30)
    else:
        shop.subscription_expires_at = now + timedelta(days=30)


def restock_order(order, new_status="CANCELLED"):
    for it in order.items:
        p = db.session.get(Product, it.product_id)
        if p:
            p.stock += it.qty
        it.status = new_status
    order.status = new_status


def apply_successful_payment(data) -> bool:
    reference = str(data.get("reference") or "")
    paid_kobo = data.get("amount")
    if not reference or data.get("currency", "NGN") != "NGN" or not isinstance(paid_kobo, int):
        return False
    metadata = data.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    kind = metadata.get("type")

    if kind == "activation":
        shop_id = parse_int(metadata.get("shop_id"), 1, 2**31 - 1)
        shop = Shop.query.filter_by(id=shop_id).with_for_update().first() if shop_id else None
        if not shop or shop.activation_ref != reference:
            return False
        if paid_kobo != ACTIVATION_FEE_NGN * 100:
            log.warning("Activation amount mismatch ref=%s paid=%s", reference, paid_kobo)
            return False
        activate_shop(shop)
        shop.activation_ref = None
        db.session.commit()
        log.info("Shop %s activated (ref %s)", shop.id, reference)
        return True

    if kind == "reel_promotion":
        reel_id = parse_int(metadata.get("reel_id"), 1, 2**31 - 1)
        reel = db.session.get(Reel, reel_id) if reel_id else None
        if not reel or paid_kobo != REEL_PROMO_FEE_NGN * 100:
            return False
        if not reel.is_sponsored:
            reel.is_sponsored = True
            db.session.commit()
        return True

    order = Order.query.filter_by(reference=reference).with_for_update().first()
    if not order:
        return False
    if order.status in ("PAID", "SHIPPED", "DELIVERED"):
        return True
    if paid_kobo != int(round(order.total * 100)):
        log.warning("Order amount mismatch ref=%s paid=%s expected=%s", reference, paid_kobo, order.total)
        return False

    if order.status == "CANCELLED":
        locked = {}
        for it in order.items:
            locked[it.product_id] = Product.query.filter_by(id=it.product_id).with_for_update().first()
        if any(locked[it.product_id] is None or locked[it.product_id].stock < it.qty for it in order.items):
            order.status = "REFUND_REQUIRED"
            db.session.commit()
            log.error("PAID AFTER EXPIRY and stock gone - refund needed: %s", reference)
            return False
        for it in order.items:
            locked[it.product_id].stock -= it.qty

    order.status = "PAID"
    for it in order.items:
        it.status = "PAID"
    db.session.commit()

    dash = url_for("dashboard", _external=True)
    for shop in {it.shop for it in order.items}:
        send_email(
            shop.owner.email,
            f"New Order #{order.reference} - {shop.name}",
            f"<h2>You have a new order!</h2><p>Hi {escape(shop.name)},</p>"
            f"<p>Order <b>#{escape(order.reference)}</b> has been paid for by {escape(order.customer.username)}.</p>"
            f"<p><b>Delivery Address:</b> {escape(order.address)}</p><p><b>Phone:</b> {escape(order.phone)}</p>"
            f"<p><a href=\"{escape(dash)}\">Log in and mark it as shipped.</a></p>",
        )
    log.info("Order %s paid", reference)
    return True


# ==================================================================
# REQUEST HOOKS
# ==================================================================
app.before_request(new_csp_nonce)


@app.before_request
def force_https():
    if IS_PROD and not request.is_secure and request.endpoint not in ("paystack_webhook", "static"):
        return redirect(request.url.replace("http://", "https://", 1), code=301)


app.before_request(csrf_protect)

_last_maintenance = 0.0


# --- FIXED: Removed the stray 's' before the decorator ---
@app.before_request
def maintenance():
    """Expire subscriptions, release stock, and auto-release escrow (runs once a minute)."""
    global _last_maintenance
    if request.endpoint in ("static", "paystack_webhook"):
        return
    now_m = time.monotonic()
    if now_m - _last_maintenance < 60:
        return
    _last_maintenance = now_m
    
    try:
        now = datetime.utcnow()
        
        # 1. Expire Subscriptions
        for shop in Shop.query.filter(Shop.subscription_status == "ACTIVE", Shop.subscription_expires_at < now).all():
            shop.subscription_status = "EXPIRED"
            shop.is_approved = False
            
        # 2. Restock abandoned checkouts (2 hours)
        stale = Order.query.filter(Order.status == "PENDING", Order.created_at < now - PENDING_ORDER_TTL) \
            .with_for_update(skip_locked=True).all()
        for order in stale:
            restock_order(order)
            
        # 3. Auto-release escrow. There is no "shipped at" column, so measure from when the order was
        #    placed and use a generous 14 days. The JOIN is essential: without it this query matches
        #    EVERY shipped item as soon as ANY order in the database is old, paying vendors early.
        escrow_cutoff = now - timedelta(days=14)
        old_shipped_items = (
            OrderItem.query.join(Order, OrderItem.order_id == Order.id)
            .filter(OrderItem.status == "SHIPPED", Order.created_at < escrow_cutoff)
            .with_for_update(skip_locked=True, of=OrderItem)
            .all()
        )

        for item in old_shipped_items:
            item.status = "DELIVERED"
            payout = round(item.price * item.qty * (1 - PLATFORM_COMMISSION), 2)
            Shop.query.filter_by(id=item.shop_id).update(
                {Shop.wallet_balance: Shop.wallet_balance + payout}, synchronize_session=False
            )
            log.info(f"Auto-released escrow for item {item.id} (Order {item.order.reference})")
            
        # 4. Abandoned reel uploads. The video is uploaded BEFORE the Paystack payment, so remove
        #    reels that were never paid for or approved after 24h (otherwise vendors could fill
        #    your Cloudinary storage for free). At most 5 per run to keep requests fast.
        abandoned = (Reel.query.filter(Reel.is_sponsored.is_(False), Reel.is_approved.is_(False),
                                       Reel.created_at < now - timedelta(hours=24)).limit(5).all())
        for reel in abandoned:
            delete_cloudinary_asset(reel.video_url, "video")
            delete_cloudinary_asset(reel.poster_url, "image")
            ReelLike.query.filter_by(reel_id=reel.id).delete()
            db.session.delete(reel)

        db.session.commit()
        
    except Exception:
        db.session.rollback()
        log.exception("Maintenance failed")


@app.context_processor
def inject_security():
    return {"csrf_token": csrf_token, "csp_nonce": getattr(g, "csp_nonce", "")}


@app.after_request
def security_headers(response):
    return apply_security_headers(response, IS_PROD, CSP_MODE)


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
@app.errorhandler(429)
def http_error(e):
    code = getattr(e, "code", 500)
    messages = {
        400: getattr(e, "description", None) or "Bad request.",
        403: "You don't have permission to do that.",
        404: "We couldn't find that page.",
        413: "That upload is too large.",
        429: "Too many requests. Please wait a moment and try again.",
    }
    msg = messages.get(code, "Something went wrong.")
    if request.is_json or request.headers.get("X-CSRFToken") is not None:
        return jsonify({"error": msg}), code
    return render_template("error.html", code=code, message=msg), code


@app.errorhandler(500)
def server_error(e):
    db.session.rollback()
    log.exception("Unhandled error")
    if request.is_json or request.headers.get("X-CSRFToken") is not None:
        return jsonify({"error": "A server error occurred."}), 500
    return render_template("error.html", code=500, message="Something went wrong on our side."), 500


# ==================================================================
# AUTH
# ==================================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        email = clip(request.form.get("email"), 120).lower()
        password = (request.form.get("password") or "")[:256]

        ip_ok = limiter.allow(f"login-ip:{client_ip()}", 20, 900)
        acct_ok = limiter.allow(f"login-acct:{client_ip()}:{email}", 5, 900)
        if not (ip_ok and acct_ok):
            flash("Too many sign-in attempts. Please wait 15 minutes and try again.", "error")
            return render_template("login.html"), 429

        user = User.query.filter_by(email=email).first()
        ok = check_password_hash(user.password_hash if user else DUMMY_HASH, password)
        if user and ok:
            session.clear()
            login_user(user)
            nxt = request.args.get("next", "")
            return redirect(nxt if safe_next_url(nxt) else url_for("home"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        if not limiter.allow(f"register:{client_ip()}", 10, 3600):
            flash("Too many sign-ups from this network. Please try again later.", "error")
            return render_template("login.html"), 429
        username = clip(request.form.get("username"), 50)
        email = clip(request.form.get("email"), 120).lower()
        password = request.form.get("password") or ""
        role = request.form.get("role", "customer")
        if role not in ("customer", "vendor"):
            role = "customer"

        if not USERNAME_RE.match(username):
            flash("Name must be 2-50 characters (letters, numbers, spaces, . ' - _).", "error")
            return render_template("login.html")
        if not EMAIL_RE.match(email):
            flash("Please enter a valid email address.", "error")
            return render_template("login.html")
        if not (10 <= len(password) <= 128):
            flash("Password must be between 10 and 128 characters.", "error")
            return render_template("login.html")
        if password.lower() in (email, username.lower()) or len(set(password)) < 4:
            flash("Please choose a less predictable password.", "error")
            return render_template("login.html")
        if User.query.filter((User.email == email) | (db.func.lower(User.username) == username.lower())).first():
            flash("That email or username is already taken.", "error")
            return render_template("login.html")

        user = User(username=username, email=email, password_hash=generate_password_hash(password), role=role)
        db.session.add(user)
        db.session.commit()
        session.clear()
        login_user(user)
        return redirect(url_for("vendor_apply") if role == "vendor" else url_for("home"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("home"))


# ==================================================================
# PASSWORD RESET
# ==================================================================
def _pw_fingerprint(user) -> str:
    """Changes whenever the password changes, so a reset link dies the moment it is used."""
    return hashlib.sha256(user.password_hash.encode()).hexdigest()[:16]


def external_url(endpoint, **values) -> str:
    """Build an absolute link. Set PUBLIC_BASE_URL in production so emailed links can't be poisoned via the Host header."""
    base = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    return base + url_for(endpoint, **values) if base else url_for(endpoint, _external=True, **values)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
        
    if request.method == "POST":
        email = clip(request.form.get("email"), 120).lower()
        if not (limiter.allow(f"reset-ip:{client_ip()}", 5, 3600) and limiter.allow(f"reset-mail:{email}", 3, 3600)):
            flash("Too many reset requests. Please try again later.", "error")
            return render_template("reset_request.html"), 429
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = serializer.dumps({"e": user.email, "f": _pw_fingerprint(user)}, salt="password-reset")
            reset_url = external_url("reset_token", token=token)
            
            send_email(
                user.email,
                "Reset Your Mall Password",
                f"""
                <h2>Password Reset Request</h2>
                <p>Hi {escape(user.username)},</p>
                <p>We received a request to reset your password. Click the link below to choose a new one. This link expires in 1 hour.</p>
                <p><a href="{escape(reset_url)}" style="padding: 10px 20px; background: #f59e0b; color: white; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a></p>
                <p>If you didn't request this, you can safely ignore this email.</p>
                """
            )
            
        flash("If that email is registered, a reset link has been sent.", "success")
        return redirect(url_for("login"))
        
    return render_template("reset_request.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for("home"))
        
    try:
        payload = serializer.loads(token, salt="password-reset", max_age=3600)
        email, fp = payload["e"], payload["f"]
    except Exception:
        flash("The password reset link is invalid or has expired.", "error")
        return redirect(url_for("reset_request"))

    user = User.query.filter_by(email=email).first()
    if not user or not hmac.compare_digest(fp, _pw_fingerprint(user)):
        flash("This reset link has already been used or is no longer valid.", "error")
        return redirect(url_for("reset_request"))

    if request.method == "POST":
        password = request.form.get("password") or ""
        
        if not (10 <= len(password) <= 128):
            flash("Password must be between 10 and 128 characters.", "error")
            return render_template("reset_password.html", token=token)
            
        user.password_hash = generate_password_hash(password)
        db.session.commit()
        
        flash("Your password has been updated! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


# ==================================================================
# PUBLIC ROUTES
# ==================================================================
def _count_view(model, obj_id):
    if limiter.allow(f"view:{model.__name__}:{obj_id}:{client_ip()}", 1, 3600):
        model.query.filter_by(id=obj_id).update({model.views: model.views + 1}, synchronize_session=False)
        db.session.commit()


@app.route("/")
def home():
    shops = Shop.query.filter_by(is_approved=True).order_by(Shop.created_at.desc()).limit(12).all()
    products = (Product.query.filter_by(is_active=True).join(Shop).filter(Shop.is_approved.is_(True))
                .order_by(Product.created_at.desc()).limit(16).all())
    return render_template("home.html", shops=shops, products=products)


@app.route("/search")
def search():
    q = clip(request.args.get("q"), 100)
    category = clip(request.args.get("category"), 60)
    page = request.args.get("page", 1, type=int)
    
    # NEW: Price and Sort filters
    min_price = request.args.get("min_price", type=float)
    max_price = request.args.get("max_price", type=float)
    sort_by = request.args.get("sort", "newest")

    query = Product.query.filter_by(is_active=True).join(Shop).filter(Shop.is_approved.is_(True))
    
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        query = query.filter(Product.name.ilike(like, escape="\\") | Product.description.ilike(like, escape="\\"))
    if category:
        query = query.filter(Product.shop.has(Shop.category == category))
    if min_price is not None:
        query = query.filter(Product.price >= min_price)
    if max_price is not None:
        query = query.filter(Product.price <= max_price)

    # Sorting Logic
    if sort_by == "price_asc":
        query = query.order_by(Product.price.asc())
    elif sort_by == "price_desc":
        query = query.order_by(Product.price.desc())
    else:
        query = query.order_by(Product.created_at.desc()) # Default

    pagination = query.paginate(page=page, per_page=12, error_out=False)
    
    return render_template("search.html", products=pagination.items, pagination=pagination, q=q, category=category, 
                           min_price=min_price, max_price=max_price, sort_by=sort_by)


@app.route("/shop/<slug>")
def shop_page(slug):
    shop = Shop.query.filter_by(slug=slug[:140], is_approved=True).first_or_404()
    _count_view(Shop, shop.id)
    page = request.args.get("page", 1, type=int)
    sort_by = request.args.get("sort", "newest")

    reviews = Review.query.filter_by(shop_id=shop.id).order_by(Review.created_at.desc()).limit(100).all()
    avg_rating = sum(r.rating for r in reviews) / len(reviews) if reviews else 0.0
    
    query = Product.query.filter_by(shop_id=shop.id, is_active=True)
    
    # Sorting Logic for Shop
    if sort_by == "price_asc":
        query = query.order_by(Product.price.asc())
    elif sort_by == "price_desc":
        query = query.order_by(Product.price.desc())
    else:
        query = query.order_by(Product.created_at.desc())

    pagination = query.paginate(page=page, per_page=12, error_out=False)
    
    return render_template("shop.html", shop=shop, reviews=reviews, avg_rating=avg_rating, 
                           products=pagination.items, pagination=pagination, sort_by=sort_by)

@app.route("/shop/<slug>")
def shop_page(slug):
    shop = Shop.query.filter_by(slug=slug[:140], is_approved=True).first_or_404()
    _count_view(Shop, shop.id)
    page = request.args.get("page", 1, type=int)
    
    reviews = Review.query.filter_by(shop_id=shop.id).order_by(Review.created_at.desc()).limit(100).all()
    avg_rating = sum(r.rating for r in reviews) / len(reviews) if reviews else 0.0
    
    pagination = Product.query.filter_by(shop_id=shop.id, is_active=True).order_by(Product.created_at.desc()).paginate(page=page, per_page=12, error_out=False)
    
    return render_template("shop.html", shop=shop, reviews=reviews, avg_rating=avg_rating, products=pagination.items, pagination=pagination)


@app.route("/shop/<slug>/review", methods=["POST"])
@login_required
@rate_limit(10, 3600, "review", per_user=True)
def add_review(slug):
    shop = Shop.query.filter_by(slug=slug[:140], is_approved=True).first_or_404()
    if shop.owner_id == current_user.id:
        flash("You can't review your own shop.", "error")
        return redirect(url_for("shop_page", slug=shop.slug))
    rating = parse_int(request.form.get("rating"), 1, 5)
    comment = clip_text(request.form.get("comment"), 1000)
    if rating is None:
        flash("Please choose a rating from 1 to 5.", "error")
        return redirect(url_for("shop_page", slug=shop.slug))
    bought = (OrderItem.query.join(Order)
              .filter(Order.customer_id == current_user.id, OrderItem.shop_id == shop.id,
                      OrderItem.status.in_(["PAID", "SHIPPED", "DELIVERED"])).first())
    if not bought:
        flash("You can only review shops you have purchased from.", "error")
        return redirect(url_for("shop_page", slug=shop.slug))
    if Review.query.filter_by(shop_id=shop.id, customer_id=current_user.id).first():
        flash("You have already reviewed this shop.", "error")
        return redirect(url_for("shop_page", slug=shop.slug))
    db.session.add(Review(shop_id=shop.id, customer_id=current_user.id, rating=rating, comment=comment))
    db.session.commit()
    flash("Review submitted!", "success")
    return redirect(url_for("shop_page", slug=shop.slug))


def _visible_product_or_404(pid):
    p = db.session.get(Product, pid)
    if not p:
        abort(404)
    owner = current_user.is_authenticated and p.shop.owner_id == current_user.id
    if not owner and not (p.is_active and p.shop.is_approved):
        abort(404)
    return p


@app.route("/product/<int:pid>")
def product_page(pid):
    p = _visible_product_or_404(pid)
    _count_view(Product, p.id)
    return render_template("product.html", p=p)


@app.route("/wishlist/toggle/<int:pid>", methods=["POST"])
@login_required
@rate_limit(60, 60, "wishlist", per_user=True)
def toggle_wishlist(pid):
    _visible_product_or_404(pid)
    w = Wishlist.query.filter_by(user_id=current_user.id, product_id=pid).first()
    if w:
        db.session.delete(w)
        state = False
    else:
        db.session.add(Wishlist(user_id=current_user.id, product_id=pid))
        state = True
    db.session.commit()
    return jsonify({"saved": state})


@app.route("/wishlist")
@login_required
def wishlist():
    items = Wishlist.query.filter_by(user_id=current_user.id).all()
    return render_template("wishlist.html", items=items)


@app.route("/reels")
def reels_feed():
    reels = (Reel.query.filter_by(is_approved=True).join(Shop).filter(Shop.is_approved.is_(True))
             .order_by(Reel.is_sponsored.desc(), Reel.created_at.desc()).limit(30).all())
    return render_template("reels.html", reels=reels)


@app.route("/reels/<int:rid>/like", methods=["POST"])
@login_required
@rate_limit(60, 60, "like", per_user=True)
def like_reel(rid):
    r = Reel.query.filter_by(id=rid, is_approved=True).first_or_404()
    existing = ReelLike.query.filter_by(reel_id=r.id, user_id=current_user.id).first()
    if existing:
        db.session.delete(existing)
        r.likes = max(0, (r.likes or 0) - 1)
    else:
        db.session.add(ReelLike(reel_id=r.id, user_id=current_user.id))
        r.likes = (r.likes or 0) + 1
    db.session.commit()
    return jsonify({"likes": r.likes})


@app.route("/reels/<int:rid>/view", methods=["POST"])
@rate_limit(120, 60, "reelview")
def view_reel(rid):
    if limiter.allow(f"reelview:{rid}:{client_ip()}", 1, 3600):
        Reel.query.filter_by(id=rid, is_approved=True).update({Reel.views: Reel.views + 1}, synchronize_session=False)
        db.session.commit()
    return jsonify({"ok": True})


# ==================================================================
# CHAT
# ==================================================================
@app.route("/chat/<slug>")
@login_required
def chat(slug):
    shop = Shop.query.filter_by(slug=slug[:140], is_approved=True).first_or_404()
    customer_id = request.args.get("customer", type=int)
    if shop.owner_id == current_user.id:
        if not customer_id:
            return redirect(url_for("dashboard"))
        if not db.session.get(User, customer_id) or customer_id == current_user.id:
            abort(404)
    else:
        customer_id = current_user.id
    conv = Conversation.query.filter_by(customer_id=customer_id, shop_id=shop.id).first()
    if not conv:
        conv = Conversation(customer_id=customer_id, shop_id=shop.id)
        db.session.add(conv)
        db.session.commit()
    history = [{
        "id": m.id, "body": m.body, "sender_id": m.sender_id, "image": None,
        "created_at": m.created_at.strftime("%H:%M"),
    } for m in conv.messages[-200:]]
    return render_template("chat.html", conv=conv, shop=shop, history=history)


# ==================================================================
# CART & CHECKOUT
# ==================================================================
@app.route("/cart")
def cart():
    return render_template("cart.html")


class CheckoutError(Exception):
    pass


@app.route("/checkout", methods=["POST"])
@login_required
@rate_limit(10, 600, "checkout", per_user=True)
def checkout():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request"}), 400
    raw_items = data.get("items")
    if not isinstance(raw_items, list) or not raw_items or len(raw_items) > 50:
        return jsonify({"error": "Cart is empty or invalid"}), 400

    wanted = {}
    for it in raw_items:
        pid = parse_int(it.get("product_id"), 1, 2**31 - 1) if isinstance(it, dict) else None
        qty = parse_int(it.get("qty", 1), 1, 20) if isinstance(it, dict) else None
        if pid is None or qty is None:
            return jsonify({"error": "Invalid cart item"}), 400
        wanted[pid] = min(wanted.get(pid, 0) + qty, 20)

    address = clip_text(data.get("address"), 300)
    phone = clip(data.get("phone"), 40)
    if len(address) < 8:
        return jsonify({"error": "Please enter a full delivery address"}), 400
    if not is_valid_ng_phone(phone):
        return jsonify({"error": "Please enter a valid Nigerian phone number"}), 400

    try:
        lines, total = [], Decimal("0")
        for pid in sorted(wanted):
            p = Product.query.filter_by(id=pid).with_for_update().first()
            if not p or not p.is_active or not p.shop.is_approved:
                raise CheckoutError("A product in your cart is unavailable")
            if p.shop.owner_id == current_user.id:
                raise CheckoutError("You can't buy from your own shop")
            if p.stock < wanted[pid]:
                raise CheckoutError(f"{p.name} is out of stock")
            total += Decimal(str(p.price)) * wanted[pid]
            lines.append((p, wanted[pid]))

        total_f = float(total.quantize(Decimal("0.01")))
        order = Order(customer_id=current_user.id, total=total_f,
                      reference="ORD-" + uuid.uuid4().hex[:12].upper(), status="PENDING",
                      address=address, phone=normalize_phone(phone))
        db.session.add(order)
        db.session.flush()
        for p, qty in lines:
            db.session.add(OrderItem(order_id=order.id, shop_id=p.shop_id, product_id=p.id,
                                     name=p.name, price=p.price, qty=qty, status="PENDING"))
            p.stock -= qty
        db.session.commit()
    except CheckoutError as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400
    except Exception:
        db.session.rollback()
        log.exception("Checkout failed")
        return jsonify({"error": "A server error occurred. Please try again."}), 500

    auth_url = initialize_paystack(
        current_user.email, total_f, url_for("payment_success", reference=order.reference, _external=True),
        reference=order.reference, metadata={"type": "order", "order_id": order.id},
    )
    if not auth_url:
        restock_order(order)
        db.session.commit()
        return jsonify({"error": "Payment gateway error. Please try again."}), 502
    return jsonify({"authorization_url": auth_url, "reference": order.reference})


@app.route("/payment-success/<reference>")
@login_required
@rate_limit(30, 600, "payret", per_user=True)
def payment_success(reference):
    order = Order.query.filter_by(reference=reference[:40], customer_id=current_user.id).first_or_404()
    if order.status == "PENDING":
        status, data = verify_paystack(order.reference)
        if status == "success" and data.get("reference") == order.reference:
            apply_successful_payment(data)
            db.session.refresh(order)
    return render_template("payment_success.html", order=order)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if current_user.role == "vendor":
        return redirect(url_for("dashboard")) # Vendors use the vendor dashboard
        
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "update_info":
            new_username = clip(request.form.get("username"), 50)
            new_email = clip(request.form.get("email"), 120).lower()
            new_phone = normalize_phone(request.form.get("phone"))
            
            if not USERNAME_RE.match(new_username) or not EMAIL_RE.match(new_email):
                flash("Invalid name or email format.", "error")
            elif User.query.filter(User.id != current_user.id, (User.email == new_email) | (db.func.lower(User.username) == new_username.lower())).first():
                flash("That email or username is already taken.", "error")
            else:
                current_user.username = new_username
                current_user.email = new_email
                current_user.phone = new_phone
                db.session.commit()
                flash("Profile updated successfully!", "success")
                return redirect(url_for("profile"))
                
        elif action == "change_password":
            current_pw = request.form.get("current_password") or ""
            new_pw = request.form.get("new_password") or ""
            
            if not check_password_hash(current_user.password_hash, current_pw):
                flash("Current password is incorrect.", "error")
            elif not (10 <= len(new_pw) <= 128):
                flash("New password must be at least 10 characters.", "error")
            else:
                current_user.password_hash = generate_password_hash(new_pw)
                db.session.commit()
                flash("Password changed successfully!", "success")
                return redirect(url_for("profile"))

    my_orders_count = Order.query.filter_by(customer_id=current_user.id).count()
    wishlist_count = Wishlist.query.filter_by(user_id=current_user.id).count()
    
    return render_template("profile.html", orders_count=my_orders_count, wishlist_count=wishlist_count)


@app.route("/order/confirm-delivery/<int:item_id>", methods=["POST"])
@login_required
def confirm_delivery(item_id):
    item = OrderItem.query.filter_by(id=item_id).with_for_update().first_or_404()
    if item.order.customer_id != current_user.id:
        abort(403)
    if item.status == "SHIPPED":
        item.status = "DELIVERED"
        payout = round(item.price * item.qty * (1 - PLATFORM_COMMISSION), 2)
        Shop.query.filter_by(id=item.shop_id).update(
            {Shop.wallet_balance: Shop.wallet_balance + payout}, synchronize_session=False)
        db.session.commit()
        flash("Delivery confirmed! Funds released to vendor.", "success")
    return redirect(url_for("orders"))


# ==================================================================
# PAYSTACK WEBHOOK
# ==================================================================
@app.route("/paystack-webhook", methods=["POST"])
def paystack_webhook():
    signature = request.headers.get("X-Paystack-Signature", "")
    if not signature:
        return "Missing signature", 400
    raw = request.get_data()
    computed = hmac.new(PAYSTACK_SECRET_KEY.encode("utf-8"), msg=raw, digestmod=hashlib.sha512).hexdigest()
    if not hmac.compare_digest(computed, signature):
        return "Invalid signature", 400
    try:
        event = json.loads(raw)
    except ValueError:
        return "Bad payload", 400

    if isinstance(event, dict) and event.get("event") == "charge.success" and isinstance(event.get("data"), dict):
        reference = str(event["data"].get("reference") or "")
        status, verified = verify_paystack(reference)
        if status == "error":
            return "", 500
        if status == "success":
            try:
                apply_successful_payment(verified)
            except Exception:
                db.session.rollback()
                log.exception("Webhook processing failed")
                return "", 500
    return "", 200


# ==================================================================
# VENDOR
# ==================================================================
@app.route("/vendor/apply", methods=["GET", "POST"])
@login_required
def vendor_apply():
    if current_user.role != "vendor":
        return redirect(url_for("home"))
    existing = current_user.shop
    if existing and existing.verification_status == "ACTIVE":
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        form, files = request.form, request.files
        name = clip(form.get("name"), 120)
        seller_type = form.get("seller_type") if form.get("seller_type") in ("business", "individual") else "business"
        cac = clip(form.get("cac_number"), 60)
        errors = []
        if len(name) < 3:
            errors.append("Business name must be at least 3 characters.")
        if not is_valid_ng_phone(form.get("phone", "")):
            errors.append("Phone number must be a valid Nigerian number.")
        if seller_type == "business" and len(cac) < 4:
            errors.append("Registered businesses must provide a CAC / RC number.")
        clash = Shop.query.filter(Shop.name.ilike(name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"), escape="\\"))
        if existing:
            clash = clash.filter(Shop.id != existing.id)
        if clash.first():
            errors.append("A shop with this name already exists.")

        id_stream = sanitize_upload(files.get("id_image"), "image")
        if id_stream is None and not (existing and existing.id_image):
            errors.append("Please upload a clear photo (JPG/PNG/WEBP, max 5MB) of your government ID.")
        logo_stream = sanitize_upload(files.get("logo"), "image") if files.get("logo") and files["logo"].filename else None
        banner_stream = sanitize_upload(files.get("banner"), "image") if files.get("banner") and files["banner"].filename else None
        if (files.get("logo") and files["logo"].filename and logo_stream is None) or \
           (files.get("banner") and files["banner"].filename and banner_stream is None):
            errors.append("Logo/banner must be a valid image under 5MB.")

        if errors:
            for msg in errors:
                flash(msg, "error")
            return render_template("apply.html", shop=existing, form=form)

        if existing:
            shop = existing
            if shop.name.lower() != name.lower():
                shop.name, shop.slug = name, unique_slug(name)
        else:
            shop = Shop(owner_id=current_user.id, name=name, slug=unique_slug(name))
            db.session.add(shop)

        shop.category = clip(form.get("category"), 60)
        shop.description = clip_text(form.get("description"), 2000)
        shop.seller_type = seller_type
        shop.legal_name = clip(form.get("legal_name"), 200)
        shop.phone = normalize_phone(form.get("phone"))
        shop.whatsapp = clip(form.get("whatsapp"), 40)
        shop.business_email = clip(form.get("business_email"), 120)
        shop.address = clip_text(form.get("address"), 300)
        shop.city = clip(form.get("city"), 80)
        shop.state = clip(form.get("state"), 80)
        shop.location = f"{shop.city}, {shop.state}"
        shop.cac_number = cac
        shop.id_type = clip(form.get("id_type"), 40)
        shop.id_number = clip(form.get("id_number"), 80)
        shop.product_summary = clip_text(form.get("product_summary"), 1000)
        shop.price_range = clip(form.get("price_range"), 60)
        links = [safe_http_url(s) for s in (form.get("social_links") or "").splitlines()[:5]]
        shop.social_links = json.dumps([u for u in links if u])

        if id_stream is not None:
            shop.id_image = upload_private_id(id_stream) or shop.id_image
        if logo_stream is not None:
            shop.logo = upload_public(logo_stream, "image") or shop.logo
        if banner_stream is not None:
            shop.banner = upload_public(banner_stream, "image") or shop.banner

        shop.verification_status = "PENDING_REVIEW"
        shop.auto_flags = "[]"
        shop.submitted_at = datetime.utcnow()
        db.session.commit()
        flash("Application submitted for review.", "success")
        return redirect(url_for("vendor_status"))

    keys = ["name", "category", "description", "seller_type", "legal_name", "phone", "whatsapp", "business_email",
            "address", "city", "state", "cac_number", "id_type", "id_number", "product_summary", "price_range"]
    form = {k: getattr(existing, k, "") or "" for k in keys}
    if existing and existing.social_links:
        form["social_links"] = "\n".join(from_json_filter(existing.social_links))
    return render_template("apply.html", shop=existing, form=form)


@app.route("/vendor/status")
@login_required
def vendor_status():
    if current_user.role != "vendor":
        return redirect(url_for("home"))
    if not current_user.shop:
        return redirect(url_for("vendor_apply"))
    return render_template("vendor_status.html", shop=current_user.shop, fee=ACTIVATION_FEE_NGN)


@app.route("/vendor/pay-activation", methods=["GET", "POST"])
@login_required
def pay_activation():
    shop = current_user.shop
    if current_user.role != "vendor" or not shop:
        return redirect(url_for("vendor_apply"))
    if shop.verification_status not in ("APPROVED", "ACTIVE"):
        flash("Your application must be approved before you can activate your shop.", "error")
        return redirect(url_for("vendor_status"))

    if request.method == "POST":
        if not limiter.allow(f"payinit:{current_user.id}", 5, 600):
            abort(429)
        ref = f"ACT-{shop.id}-{uuid.uuid4().hex[:12]}"
        shop.activation_ref = ref
        db.session.commit()
        auth_url = initialize_paystack(
            current_user.email, ACTIVATION_FEE_NGN, url_for("activation_return", _external=True),
            reference=ref, metadata={"type": "activation", "shop_id": shop.id},
        )
        if not auth_url:
            flash("Payment gateway error. Please try again.", "error")
            return redirect(url_for("pay_activation"))
        return redirect(auth_url)
    return render_template("vendor_pay.html", shop=shop, fee=ACTIVATION_FEE_NGN)


@app.route("/vendor/pay-activation/return")
@login_required
@rate_limit(30, 600, "actreturn", per_user=True)
def activation_return():
    shop = current_user.shop
    ref = clip(request.args.get("reference"), 60)
    if not shop or not ref:
        return redirect(url_for("vendor_status"))
    if shop.activation_ref == ref:
        status, data = verify_paystack(ref)
        if status == "success" and apply_successful_payment(data):
            flash("Payment confirmed - your shop is LIVE for 30 days!", "success")
            return redirect(url_for("dashboard"))
    elif shop.verification_status == "ACTIVE" and shop.is_approved:
        return redirect(url_for("dashboard"))
    flash("We haven't received confirmation of your payment yet. If you were charged it will activate shortly.", "error")
    return redirect(url_for("vendor_status"))


@app.route("/dashboard")
@login_required
def dashboard():
    shop = current_user.shop
    if not shop:
        return redirect(url_for("vendor_apply"))
    if shop.verification_status in ("PENDING_REVIEW", "REJECTED"):
        return redirect(url_for("vendor_status"))
    if shop.verification_status == "APPROVED" and not shop.activation_paid:
        return redirect(url_for("pay_activation"))
    if shop.subscription_status == "EXPIRED":
        return redirect(url_for("pay_activation"))
    if shop.verification_status != "ACTIVE":
        return redirect(url_for("vendor_status"))

    # Paginated: a shop can hold up to MAX_PRODUCTS_PER_SHOP products, far too many to render at once.
    # Deleted (inactive) products are hidden here; they are only soft-deleted so old orders still work.
    product_pagination = (Product.query.filter_by(shop_id=shop.id, is_active=True)
                          .order_by(Product.created_at.desc())
                          .paginate(page=request.args.get("page", 1, type=int),
                                    per_page=DASHBOARD_PRODUCTS_PER_PAGE, error_out=False))
    products = product_pagination.items
    convos = Conversation.query.filter_by(shop_id=shop.id).order_by(Conversation.created_at.desc()).all()
    order_items = OrderItem.query.filter_by(shop_id=shop.id).order_by(OrderItem.id.desc()).all()
    reels = Reel.query.filter_by(shop_id=shop.id).order_by(Reel.created_at.desc()).all()
    days_left = max(0, (shop.subscription_expires_at - datetime.utcnow()).days) if shop.subscription_expires_at else 0
    total_sales = sum(i.price * i.qty for i in order_items if i.status in ["PAID", "SHIPPED", "DELIVERED"])
    return render_template("dashboard.html", shop=shop, products=products, order_items=order_items,
                           convos=convos, reels=reels, days_left=days_left, total_sales=total_sales,
                           product_pagination=product_pagination, max_products=MAX_PRODUCTS_PER_SHOP)


@app.route("/vendor/ship/<int:item_id>", methods=["POST"])
@login_required
def ship_item(item_id):
    item = OrderItem.query.filter_by(id=item_id).with_for_update().first_or_404()
    if item.shop.owner_id != current_user.id:
        abort(403)
    if item.status == "PAID":
        item.status = "SHIPPED"
        db.session.commit()
        flash("Marked as shipped. Waiting for customer confirmation.", "success")
    return redirect(url_for("dashboard"))


def _active_vendor_shop():
    shop = current_user.shop
    if current_user.role != "vendor" or not shop or shop.verification_status != "ACTIVE" \
            or shop.subscription_status != "ACTIVE":
        return None
    return shop


def store_image(f, label):
    """Validate + upload one image. Returns (url, error). (None, None) means no file was chosen."""
    if not f or not f.filename:
        return None, None
    if not cloudinary_ready():
        return None, "Image uploads are not set up on the server yet (Cloudinary keys are missing in .env)."
    stream = sanitize_upload(f, "image")
    if stream is None:
        return None, f"{label} must be a real JPG, PNG, WEBP or GIF image under 15MB."
    url = upload_public(stream, "image")
    if not url:
        return None, f"{label} upload failed: {g.get('upload_error') or 'unknown error'}"
    return url, None


@app.route("/vendor/product/add", methods=["POST"])
@login_required
@rate_limit(200, 3600, "addproduct", per_user=True)   # generous: sellers add catalogues in bulk
def add_product():
    shop = _active_vendor_shop()
    if not shop:
        return redirect(url_for("dashboard"))
    live_count = Product.query.filter_by(shop_id=shop.id, is_active=True).count()
    if live_count >= MAX_PRODUCTS_PER_SHOP:
        flash(f"You have reached the limit of {MAX_PRODUCTS_PER_SHOP:,} products. Remove some to add more.", "error")
        return redirect(url_for("dashboard"))
    name = clip(request.form.get("name"), 200)
    price = parse_money(request.form.get("price"), 1, 100_000_000)
    stock = parse_int(request.form.get("stock", 0), 0, 100_000)
    if len(name) < 2 or price is None or stock is None:
        flash("Enter a product name, a price between ₦1 and ₦100,000,000, and a stock of 0-100,000.", "error")
        return redirect(url_for("dashboard"))
    image, err = store_image(request.files.get("image"), "Product image")
    if err:
        flash(err, "error")           # product is NOT created, so you never get a silent image-less product
        return redirect(url_for("dashboard"))
    db.session.add(Product(shop_id=shop.id, name=name, description=clip_text(request.form.get("description"), 3000),
                           price=price, stock=stock, image=image))
    db.session.commit()
    flash("Product added.", "success")
    return redirect(url_for("dashboard"))


@app.route("/vendor/product/edit/<int:pid>", methods=["POST"])
@login_required
@rate_limit(60, 3600, "editproduct", per_user=True)
def edit_product(pid):
    shop = _active_vendor_shop()
    product = db.session.get(Product, pid)
    if not shop or not product or product.shop_id != shop.id:
        abort(403)
    name = clip(request.form.get("name"), 200)
    price = parse_money(request.form.get("price"), 1, 100_000_000)
    stock = parse_int(request.form.get("stock", 0), 0, 100_000)
    if len(name) < 2 or price is None or stock is None:
        flash("Enter a valid name, price, and stock.", "error")
        return redirect(url_for("dashboard"))
    new_image, err = store_image(request.files.get("image"), "Product image")
    if err:
        flash(err, "error")
        return redirect(url_for("dashboard"))
    product.name, product.price, product.stock = name, price, stock
    product.description = clip_text(request.form.get("description"), 3000)
    if new_image:
        product.image = new_image
    db.session.commit()
    flash("Product updated successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/vendor/product/delete/<int:pid>", methods=["POST"])
@login_required
def delete_product(pid):
    shop = _active_vendor_shop()
    product = db.session.get(Product, pid)
    if not shop or not product or product.shop_id != shop.id:
        abort(403)
    product.is_active = False   # soft delete: old orders keep their product reference
    db.session.commit()
    flash("Product removed from your shop.", "success")
    return redirect(url_for("dashboard"))


@app.route("/vendor/shop/edit", methods=["POST"])
@login_required
@rate_limit(20, 3600, "editshop", per_user=True)
def edit_shop():
    shop = _active_vendor_shop()
    if not shop:
        return redirect(url_for("dashboard"))
    name = clip(request.form.get("name"), 120)
    phone_raw = clip(request.form.get("phone"), 40)
    if len(name) < 3:
        flash("Shop name must be at least 3 characters.", "error")
        return redirect(url_for("dashboard"))
    clash = Shop.query.filter(db.func.lower(Shop.name) == name.lower(), Shop.id != shop.id).first()
    if clash:
        flash("Another shop already uses that name.", "error")
        return redirect(url_for("dashboard"))
    if phone_raw and not is_valid_ng_phone(phone_raw):
        flash("Enter a valid Nigerian phone number.", "error")
        return redirect(url_for("dashboard"))
    logo, err1 = store_image(request.files.get("logo"), "Logo")
    banner, err2 = store_image(request.files.get("banner"), "Banner")
    if err1 or err2:
        flash(err1 or err2, "error")
        return redirect(url_for("dashboard"))
    shop.name = name            # the public URL (slug) is deliberately NOT changed, so old links keep working
    shop.description = clip_text(request.form.get("description"), 2000)
    if phone_raw:
        shop.phone = normalize_phone(phone_raw)
    shop.location = clip(request.form.get("location"), 120)
    if logo:
        shop.logo = logo
    if banner:
        shop.banner = banner
    db.session.commit()
    flash("Shop profile updated successfully!", "success")
    return redirect(url_for("dashboard"))


# ==================================================================
# REEL PROMOTION
# ==================================================================
@app.route("/dashboard/reel/upload", methods=["POST"])
@login_required
@rate_limit(10, 3600, "reelupload", per_user=True)
def upload_reel():
    shop = _active_vendor_shop()
    if not shop:
        return jsonify({"error": "Shop must be active."}), 403
    if not cloudinary_ready():
        return jsonify({"error": "Video uploads are not set up on the server yet (Cloudinary keys are missing in .env)."}), 503

    video_stream = sanitize_upload(request.files.get("video"), "video")
    if video_stream is None:
        return jsonify({"error": "Please upload a valid MP4, WEBM or MOV video under 50MB."}), 400
    poster_file = request.files.get("poster")
    poster_stream = None
    if poster_file and poster_file.filename:
        poster_stream = sanitize_upload(poster_file, "image")
        if poster_stream is None:
            return jsonify({"error": "Poster must be a valid image under 15MB."}), 400

    product_id = None
    raw_pid = request.form.get("product_id")
    if raw_pid:
        pid = parse_int(raw_pid, 1, 2**31 - 1)
        if pid is None or not Product.query.filter_by(id=pid, shop_id=shop.id).first():
            return jsonify({"error": "Invalid product selected."}), 400
        product_id = pid

    video_url = upload_public(video_stream, "video")
    if not video_url:
        return jsonify({"error": f"Video upload failed: {g.get('upload_error') or 'unknown error'}"}), 500

    reel = Reel(shop_id=shop.id, video_url=video_url, poster_url=upload_public(poster_stream, "image"),
                caption=clip_text(request.form.get("caption"), 300), product_id=product_id,
                is_sponsored=False, is_approved=False)
    db.session.add(reel)
    db.session.commit()

    ref = f"REEL-{reel.id}-{uuid.uuid4().hex[:12]}"
    auth_url = initialize_paystack(
        current_user.email, REEL_PROMO_FEE_NGN, url_for("reel_return", _external=True), reference=ref,
        metadata={"type": "reel_promotion", "reel_id": reel.id},
    )
    if not auth_url:
        # No payment link means no promotion: remove the video we just uploaded instead of leaving it behind.
        delete_cloudinary_asset(reel.video_url, "video")
        delete_cloudinary_asset(reel.poster_url, "image")
        db.session.delete(reel)
        db.session.commit()
        return jsonify({"error": "Could not reach Paystack. You have not been charged. Please try again."}), 502
    return jsonify({"authorization_url": auth_url})


@app.route("/dashboard/reel/return")
@login_required
@rate_limit(30, 600, "reelreturn", per_user=True)
def reel_return():
    ref = clip(request.args.get("reference"), 60)
    m = re.fullmatch(r"REEL-(\d+)-[0-9a-f]{12}", ref)
    shop = current_user.shop
    if m and shop:
        reel = db.session.get(Reel, int(m.group(1)))
        if reel and reel.shop_id == shop.id:
            status, data = verify_paystack(ref)
            if status == "success" and (data.get("metadata") or {}).get("reel_id") == reel.id:
                apply_successful_payment(data)
                flash("Promotion paid. Your reel will go live once an admin approves it.", "success")
    return redirect(url_for("dashboard"))


# ==================================================================
# WITHDRAWALS
# ==================================================================
@app.route("/vendor/withdraw", methods=["POST"])
@login_required
@rate_limit(5, 3600, "withdraw", per_user=True)
def vendor_withdraw():
    shop = _active_vendor_shop()
    if not shop:
        return redirect(url_for("home"))
    amount = parse_money(request.form.get("amount"), 1, 50_000_000)
    bank_name = clip(request.form.get("bank_name"), 100)
    acc_name = clip(request.form.get("account_name"), 100)
    acc_num = re.sub(r"\s", "", request.form.get("account_number") or "")

    if not bank_name or not acc_name or not re.fullmatch(r"\d{10}", acc_num):
        flash("Enter your bank, the account name and a valid 10-digit account number.", "error")
        return redirect(url_for("dashboard"))
    if amount is None:
        flash("Enter a valid amount.", "error")
        return redirect(url_for("dashboard"))

    debited = Shop.query.filter(Shop.id == shop.id, Shop.wallet_balance >= amount).update(
        {Shop.wallet_balance: Shop.wallet_balance - amount}, synchronize_session=False)
    if debited != 1:
        db.session.rollback()
        flash("You cannot withdraw more than your balance.", "error")
        return redirect(url_for("dashboard"))
    db.session.add(Withdrawal(shop_id=shop.id, amount=amount, bank_name=bank_name,
                              account_name=acc_name, account_number=acc_num))
    db.session.commit()
    audit("withdrawal_requested", shop=shop.id, amount=amount)
    flash("Withdrawal request submitted! Admin will process it shortly.", "success")
    return redirect(url_for("dashboard"))


@app.route("/admin/withdrawals")
@admin_required
def admin_withdrawals():
    pending = Withdrawal.query.filter_by(status="PENDING").order_by(Withdrawal.created_at.desc()).all()
    history = (Withdrawal.query.filter(Withdrawal.status != "PENDING")
               .order_by(Withdrawal.processed_at.desc()).limit(20).all())
    return render_template("admin_withdrawals.html", pending=pending, history=history)


@app.route("/admin/withdrawals/<int:wid>/approve", methods=["POST"])
@admin_required
def admin_approve_withdrawal(wid):
    w = Withdrawal.query.filter_by(id=wid).with_for_update().first_or_404()
    if w.status == "PENDING":
        w.status = "PAID"
        w.processed_at = datetime.utcnow()
        db.session.commit()
        audit("withdrawal_paid", withdrawal=wid, amount=w.amount, shop=w.shop_id)
        send_email(
            w.shop.owner.email, f"Payout Processed - ₦{w.amount:,.2f}",
            f"<h2>Good news!</h2><p>Hi {escape(w.shop.name)},</p>"
            f"<p>Your withdrawal of <b>₦{w.amount:,.2f}</b> has been processed:</p>"
            f"<p><b>Bank:</b> {escape(w.bank_name)}<br><b>Account:</b> {escape(w.account_number)}</p>",
        )
        flash("Withdrawal marked as Paid.", "success")
    return redirect(url_for("admin_withdrawals"))


@app.route("/admin/withdrawals/<int:wid>/reject", methods=["POST"])
@admin_required
def admin_reject_withdrawal(wid):
    w = Withdrawal.query.filter_by(id=wid).with_for_update().first_or_404()
    if w.status == "PENDING":
        w.status = "REJECTED"
        w.processed_at = datetime.utcnow()
        Shop.query.filter_by(id=w.shop_id).update(
            {Shop.wallet_balance: Shop.wallet_balance + w.amount}, synchronize_session=False)
        db.session.commit()
        audit("withdrawal_rejected", withdrawal=wid, shop=w.shop_id)
        flash("Withdrawal rejected and funds returned to vendor.", "success")
    return redirect(url_for("admin_withdrawals"))


# ==================================================================
# ADMIN
# ==================================================================
@app.route("/admin")
@admin_required
def admin_dashboard():
    active_shops = Shop.query.filter(Shop.activation_paid == True).count()
    delivered = OrderItem.query.filter_by(status="DELIVERED").all()
    commission = sum(i.price * i.qty * PLATFORM_COMMISSION for i in delivered)
    sub_revenue = active_shops * ACTIVATION_FEE_NGN
    reel_revenue = Reel.query.filter_by(is_sponsored=True).count() * REEL_PROMO_FEE_NGN
    stats = {
        "sub_revenue": sub_revenue, "commission_revenue": commission, "reel_revenue": reel_revenue,
        "total_revenue": sub_revenue + commission + reel_revenue,
        "pending_apps": Shop.query.filter_by(verification_status="PENDING_REVIEW").count(),
        "pending_payouts": Withdrawal.query.filter_by(status="PENDING").count(),
        "total_users": User.query.count(), "total_orders": Order.query.count(),
        "total_products": Product.query.count(), "active_shops": active_shops,
    }
    return render_template("admin_dashboard.html", stats=stats)


@app.route("/admin/applications")
@admin_required
def admin_applications():
    return render_template(
        "admin_applications.html",
        pending=Shop.query.filter_by(verification_status="PENDING_REVIEW").all(),
        approved=Shop.query.filter_by(verification_status="APPROVED").all(),
        rejected=Shop.query.filter_by(verification_status="REJECTED").all(),
        active=Shop.query.filter_by(verification_status="ACTIVE").all())


@app.route("/admin/applications/<int:sid>/approve", methods=["POST"])
@admin_required
def admin_approve(sid):
    shop = Shop.query.filter_by(id=sid).with_for_update().first_or_404()
    if shop.verification_status != "PENDING_REVIEW":
        flash("That application is not awaiting review.", "error")
        return redirect(url_for("admin_applications"))
    shop.verification_status = "APPROVED"
    shop.reviewed_at = datetime.utcnow()
    db.session.commit()
    audit("shop_approved", shop=sid)
    send_email(
        shop.owner.email, "Your Mall Application is Approved!",
        f"<h2>Welcome to the Mall!</h2><p>Hi {escape(shop.owner.username)},</p>"
        f"<p>Your shop <b>{escape(shop.name)}</b> has been reviewed and approved.</p>"
        f"<p>To start selling, log in and pay the activation fee of ₦{ACTIVATION_FEE_NGN:,} to make your shop live.</p>"
        f"<p><a href=\"{escape(url_for('dashboard', _external=True))}\">Log in and activate your shop.</a></p>",
    )
    flash(f"{shop.name} approved.", "success")
    return redirect(url_for("admin_applications"))


@app.route("/admin/applications/<int:sid>/reject", methods=["POST"])
@admin_required
def admin_reject(sid):
    shop = Shop.query.filter_by(id=sid).with_for_update().first_or_404()
    if shop.verification_status not in ("PENDING_REVIEW", "APPROVED"):
        flash("That application can't be rejected in its current state.", "error")
        return redirect(url_for("admin_applications"))
    shop.verification_status = "REJECTED"
    shop.rejection_reason = clip_text(request.form.get("reason"), 500) or "Invalid details."
    shop.reviewed_at = datetime.utcnow()
    db.session.commit()
    audit("shop_rejected", shop=sid)
    send_email(
        shop.owner.email, "Update on your Mall Application",
        f"<h2>Application Status Update</h2><p>Hi {escape(shop.owner.username)},</p>"
        f"<p>Your application for <b>{escape(shop.name)}</b> was not approved at this time.</p>"
        f"<p><b>Reason:</b> {escape(shop.rejection_reason)}</p>"
        f"<p>You can log in to review this and submit a new application.</p>",
    )
    flash("Shop rejected.", "success")
    return redirect(url_for("admin_applications"))


@app.route("/admin/reels")
@admin_required
def admin_reels():
    pending = Reel.query.filter_by(is_approved=False).order_by(Reel.created_at.desc()).all()
    approved = Reel.query.filter_by(is_approved=True).order_by(Reel.created_at.desc()).all()
    return render_template("admin_reels.html", pending=pending, approved=approved)


@app.route("/admin/reels/<int:rid>/approve", methods=["POST"])
@admin_required
def admin_approve_reel(rid):
    r = Reel.query.get_or_404(rid)
    r.is_approved = True
    db.session.commit()
    audit("reel_approved", reel=rid)
    flash("Reel approved.", "success")
    return redirect(url_for("admin_reels"))


@app.route("/admin/reels/<int:rid>/reject", methods=["POST"])
@admin_required
def admin_reject_reel(rid):
    r = Reel.query.get_or_404(rid)
    ReelLike.query.filter_by(reel_id=r.id).delete()
    db.session.delete(r)
    db.session.commit()
    audit("reel_removed", reel=rid)
    flash("Reel removed.", "success")
    return redirect(url_for("admin_reels"))


# ==================================================================
# CLI
# ==================================================================
@app.cli.command("create-admin")
@click.option("--email", prompt=True)
@click.option("--username", default="Admin", show_default=True)
@click.password_option(confirmation_prompt=True)
def create_admin(email, username, password):
    email = email.strip().lower()
    if not EMAIL_RE.match(email) or len(password) < 12:
        raise click.ClickException("Use a valid email and a password of at least 12 characters.")
    if User.query.filter_by(email=email).first():
        raise click.ClickException("A user with that email already exists.")
    db.session.add(User(username=username, email=email, role="admin",
                        password_hash=generate_password_hash(password)))
    db.session.commit()
    click.echo(f"Admin {email} created.")


@app.cli.command("seed-demo")
@click.option("--force", is_flag=True, help="Allow in production (not recommended).")
def seed_demo(force):
    if IS_PROD and not force:
        raise click.ClickException("Refusing to seed demo data in production.")
    if Shop.query.count() > 0:
        raise click.ClickException("Already seeded.")
    demo = [("Royal Collections", "Watches", 189.0), ("Fashion House", "Fashion", 49.0), ("Tech World", "Electronics", 299.0)]
    for name, cat, base_price in demo:
        pw = secrets.token_urlsafe(12)
        email = name.lower().replace(" ", "") + "@mall.test"
        vendor = User(username=name, email=email, password_hash=generate_password_hash(pw), role="vendor")
        db.session.add(vendor)
        db.session.flush()
        shop = Shop(owner_id=vendor.id, name=name, slug=slugify(name), category=cat, description="Demo shop.",
                    verification_status="ACTIVE", activation_paid=True, subscription_status="ACTIVE",
                    subscription_expires_at=datetime.utcnow() + timedelta(days=30), is_approved=True)
        db.session.add(shop)
        db.session.flush()
        for i in range(1, 4):
            db.session.add(Product(shop_id=shop.id, name=f"{name} Item {i}", price=base_price * i, stock=10))
        click.echo(f"{email}  /  {pw}")
    db.session.commit()


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    dev = APP_ENV == "development"
    socketio.run(app, debug=dev, host="127.0.0.1" if dev else "0.0.0.0",
                 port=int(os.environ.get("PORT", 5000)), allow_unsafe_werkzeug=dev)