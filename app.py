import os
import re
import json
import uuid
import hmac
import hashlib
import requests
import cloudinary
import cloudinary.uploader
from datetime import datetime, timedelta
from sqlalchemy.pool import NullPool

from flask import (
    Flask, render_template, request, redirect, url_for, jsonify, flash,
)
from flask_login import (
    LoginManager, login_user, login_required, logout_user, current_user,
)
from flask_mail import Mail, Message as MailMessage
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from models import (
    db, User, Shop, Product, Conversation, Message,
    Order, OrderItem, Review, Reel, Wishlist, Withdrawal
)
from sockets import socketio

# ==================================================================
# CONFIG & HELPERS
# ==================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ACTIVATION_FEE_NGN = 10000
PLATFORM_COMMISSION = 0.05

PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "sk_test_xxxx")

# Setup Cloudinary
cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET"),
    secure=True
)

def slugify(text: str) -> str:
    text = re.sub(r"[^\w\s-]", "", (text or "").lower())
    return re.sub(r"[-\s]+", "-", text).strip("-") or "shop"

def normalize_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw or "")
    if digits.startswith("234"): return "+" + digits
    if digits.startswith("0") and len(digits) == 11: return "+234" + digits[1:]
    return digits

def is_valid_ng_phone(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw or "")
    return bool(re.match(r"^(234|0)[789][01]\d{8}$", digits))

def run_application_checks(form, files) -> dict:
    blocking, warnings = [], []
    name = (form.get("name") or "").strip()
    phone = form.get("phone", "")
    seller_type = form.get("seller_type", "business")
    cac = (form.get("cac_number") or "").strip()
    
    if len(name) < 3: blocking.append("Business name must be at least 3 characters.")
    if not is_valid_ng_phone(phone): blocking.append("Phone number must be a valid Nigerian number.")
    if seller_type == "business" and len(cac) < 4: blocking.append("Registered businesses must provide a CAC / RC number.")
    if Shop.query.filter(Shop.name.ilike(name)).first(): blocking.append("A shop with this name already exists.")
    if not files.get("id_image") or files.get("id_image").filename == "": blocking.append("Please upload a photo of your government ID.")
    
    return {"blocking": blocking, "warnings": warnings}

# ==================================================================
# APP SETUP & EMAIL
# ==================================================================
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-change-me-please"),
    SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///mall.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={
        "poolclass": NullPool,
        "pool_pre_ping": True,
    },
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    
    # EMAIL CONFIG
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_USERNAME')
)

db.init_app(app)
socketio.init_app(app)
mail = Mail(app)

def send_email(to_email, subject, html_body):
    if not app.config['MAIL_USERNAME']: return 
    try:
        msg = MailMessage(subject, recipients=[to_email])
        msg.html = html_body
        mail.send(msg)
    except Exception as e:
        print(f"❌ Email failed to send: {e}")

@app.template_filter("from_json")
def from_json_filter(value):
    try: return json.loads(value or "[]")
    except Exception: return []

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "error"

@login_manager.user_loader
def load_user(uid):
    return User.query.get(int(uid))

ALLOWED_EXT = {"png", "jpg", "jpeg", "webp", "gif", "mp4", "webm", "mov"}

# --- UPDATED SAVE_FILE FUNCTION ---
def save_file(f):
    if not f or f.filename == "": return None
    ext = f.filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXT: return None
    
    try:
        # Upload directly to Cloudinary
        upload_result = cloudinary.uploader.upload(f)
        return upload_result.get("secure_url")
    except Exception as e:
        print(f"Cloudinary Upload Error: {e}")
        return None

# ==================================================================
# PAYSTACK HELPER
# ==================================================================
def initialize_paystack(email, amount_ngn, callback_url, metadata=None):
    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "email": email,
        "amount": int(amount_ngn * 100),
        "callback_url": callback_url,
        "metadata": metadata or {}
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        return response.json()["data"]["authorization_url"]
    return None

# ==================================================================
# AUTO-EXPIRY SYSTEM
# ==================================================================
@app.before_request
def check_expired_subscriptions():
    if request.endpoint in ('static', 'admin_applications', 'admin_reels', 'paystack_webhook'): return
    now = datetime.utcnow()
    expired_shops = Shop.query.filter(
        Shop.subscription_status == "ACTIVE",
        Shop.subscription_expires_at < now
    ).all()
    if expired_shops:
        for shop in expired_shops:
            shop.subscription_status = "EXPIRED"
            shop.is_approved = False
        db.session.commit()

# ==================================================================
# AUTH
# ==================================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated: return redirect(url_for("home"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") else url_for("home"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated: return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role     = request.form.get("role", "customer")
        if role not in ("customer", "vendor"): role = "customer"

        if not username or not email or len(password) < 6:
            flash("Please fill every field (password ≥ 6 characters).", "error")
            return render_template("login.html")

        if User.query.filter((User.email == email) | (User.username == username)).first():
            flash("That email or username is already taken.", "error")
            return render_template("login.html")

        user = User(username=username, email=email, password_hash=generate_password_hash(password), role=role)
        db.session.add(user); db.session.commit()
        login_user(user)

        if role == "vendor": return redirect(url_for("vendor_apply"))
        return redirect(url_for("home"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

# ==================================================================
# PUBLIC ROUTES
# ==================================================================
@app.route("/")
def home():
    shops = Shop.query.filter_by(is_approved=True).order_by(Shop.created_at.desc()).limit(12).all()
    products = Product.query.filter_by(is_active=True).join(Shop).filter(Shop.is_approved.is_(True)).order_by(Product.created_at.desc()).limit(16).all()
    return render_template("home.html", shops=shops, products=products)

@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "")
    query = Product.query.filter_by(is_active=True).join(Shop).filter(Shop.is_approved.is_(True))
    if q: query = query.filter(Product.name.ilike(f"%{q}%") | Product.description.ilike(f"%{q}%"))
    if category: query = query.filter(Product.shop.has(Shop.category == category))
    products = query.order_by(Product.created_at.desc()).all()
    return render_template("search.html", products=products, q=q, category=category)

@app.route("/shop/<slug>")
def shop_page(slug):
    shop = Shop.query.filter_by(slug=slug, is_approved=True).first_or_404()
    shop.views += 1
    db.session.commit()
    reviews = Review.query.filter_by(shop_id=shop.id).order_by(Review.created_at.desc()).all()
    avg_rating = sum([r.rating for r in reviews]) / len(reviews) if reviews else 0.0
    return render_template("shop.html", shop=shop, reviews=reviews, avg_rating=avg_rating)

@app.route("/shop/<slug>/review", methods=["POST"])
@login_required
def add_review(slug):
    shop = Shop.query.filter_by(slug=slug).first_or_404()
    rating = int(request.form.get("rating", 5))
    comment = request.form.get("comment", "")
    bought = OrderItem.query.join(Order).filter(Order.customer_id == current_user.id, OrderItem.shop_id == shop.id).first()
    if not bought:
        flash("You can only review shops you have purchased from.", "error")
        return redirect(url_for("shop_page", slug=slug))
    db.session.add(Review(shop_id=shop.id, customer_id=current_user.id, rating=rating, comment=comment))
    db.session.commit()
    flash("Review submitted!", "success")
    return redirect(url_for("shop_page", slug=slug))

@app.route("/product/<int:pid>")
def product_page(pid):
    p = Product.query.get_or_404(pid)
    p.views += 1
    db.session.commit()
    return render_template("product.html", p=p)

@app.route("/wishlist/toggle/<int:pid>", methods=["POST"])
@login_required
def toggle_wishlist(pid):
    w = Wishlist.query.filter_by(user_id=current_user.id, product_id=pid).first()
    if w:
        db.session.delete(w); state = False
    else:
        db.session.add(Wishlist(user_id=current_user.id, product_id=pid)); state = True
    db.session.commit()
    return jsonify({"saved": state})

@app.route("/wishlist")
@login_required
def wishlist():
    items = Wishlist.query.filter_by(user_id=current_user.id).all()
    return render_template("wishlist.html", items=items)

@app.route("/reels")
def reels_feed():
    reels = Reel.query.filter_by(is_approved=True).join(Shop).filter(Shop.is_approved.is_(True)).order_by(Reel.is_sponsored.desc(), Reel.created_at.desc()).limit(30).all()
    return render_template("reels.html", reels=reels)

@app.route("/reels/<int:rid>/like", methods=["POST"])
@login_required
def like_reel(rid):
    r = Reel.query.get_or_404(rid); r.likes = (r.likes or 0) + 1
    db.session.commit(); return jsonify({"likes": r.likes})

@app.route("/reels/<int:rid>/view", methods=["POST"])
def view_reel(rid):
    r = Reel.query.get(rid)
    if r: r.views = (r.views or 0) + 1; db.session.commit()
    return jsonify({"ok": True})

# ==================================================================
# CHAT
# ==================================================================
@app.route("/chat/<slug>", methods=["GET", "POST"])
@login_required
def chat(slug):
    shop = Shop.query.filter_by(slug=slug, is_approved=True).first_or_404()
    customer_id = request.args.get("customer", type=int)
    if customer_id and shop.owner_id == current_user.id:
        conv = Conversation.query.filter_by(customer_id=customer_id, shop_id=shop.id).first()
        if not conv:
            conv = Conversation(customer_id=customer_id, shop_id=shop.id)
            db.session.add(conv); db.session.commit()
        return render_template("chat.html", conv=conv, shop=shop)
    if shop.owner_id == current_user.id: return redirect(url_for("dashboard"))
    conv = Conversation.query.filter_by(customer_id=current_user.id, shop_id=shop.id).first()
    if not conv:
        conv = Conversation(customer_id=current_user.id, shop_id=shop.id)
        db.session.add(conv); db.session.commit()
    return render_template("chat.html", conv=conv, shop=shop)

# ==================================================================
# CART & CHECKOUT
# ==================================================================
@app.route("/cart")
def cart():
    return render_template("cart.html")

@app.route("/checkout", methods=["POST"])
@login_required
def checkout():
    data  = request.get_json(silent=True) or {}
    items = data.get("items", [])
    if not items: return jsonify({"error": "Cart is empty"}), 400

    total, lines = 0.0, []
    for it in items:
        p = Product.query.get(it.get("product_id"))
        if not p or not p.is_active or not p.shop.is_approved:
            return jsonify({"error": "A product in your cart is unavailable"}), 400
        qty = max(1, int(it.get("qty", 1)))
        if p.stock < qty:
            return jsonify({"error": f"{p.name} is out of stock"}), 400
        total += p.price * qty
        lines.append((p, qty))

    order = Order(
        customer_id=current_user.id, total=total,
        reference="ORD-" + uuid.uuid4().hex[:8].upper(),
        status="PENDING", 
        address=data.get("address"), phone=data.get("phone"),
    )
    db.session.add(order); db.session.flush()
    
    for p, qty in lines:
        db.session.add(OrderItem(
            order_id=order.id, shop_id=p.shop_id, product_id=p.id,
            name=p.name, price=p.price, qty=qty, status="PENDING"))
        p.stock -= qty
    db.session.commit()

    callback_url = url_for('payment_success', reference=order.reference, _external=True)
    auth_url = initialize_paystack(current_user.email, total, callback_url)

    if not auth_url:
        flash("Could not connect to payment gateway. Try again.", "error")
        return jsonify({"error": "Payment gateway error"}), 500

    return jsonify({"authorization_url": auth_url, "reference": order.reference})

@app.route("/payment-success/<reference>")
@login_required
def payment_success(reference):
    order = Order.query.filter_by(reference=reference, customer_id=current_user.id).first_or_404()
    return render_template("payment_success.html", order=order)

@app.route("/orders")
@login_required
def orders():
    my_orders = Order.query.filter_by(customer_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template("orders.html", orders=my_orders)

@app.route("/order/confirm-delivery/<int:item_id>", methods=["POST"])
@login_required
def confirm_delivery(item_id):
    item = OrderItem.query.get_or_404(item_id)
    if item.order.customer_id != current_user.id: return "Unauthorized", 403
    if item.status == "SHIPPED":
        item.status = "DELIVERED"
        payout = (item.price * item.qty) * (1 - PLATFORM_COMMISSION)
        item.shop.wallet_balance += payout
        db.session.commit()
        flash("Delivery confirmed! Funds released to vendor.", "success")
    return redirect(url_for("orders"))

# ==================================================================
# PAYSTACK WEBHOOK
# ==================================================================
@app.route("/paystack-webhook", methods=["POST"])
def paystack_webhook():
    signature = request.headers.get('X-Paystack-Signature', '')
    if not signature: return 'Missing signature', 400

    computed_hash = hmac.new(
        PAYSTACK_SECRET_KEY.encode('utf-8'),
        msg=request.data,
        digestmod=hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(computed_hash, signature):
        return 'Invalid signature', 400

    event = json.loads(request.data)
    if event.get('event') == 'charge.success':
        reference = event['data']['reference']
        order = Order.query.filter_by(reference=reference).first()
        
        if order and order.status == "PENDING":
            order.status = "PAID"
            for item in order.items:
                item.status = "PAID"
            db.session.commit()
            
            shops_in_order = {item.shop for item in order.items}
            for shop in shops_in_order:
                vendor_email = shop.owner.email
                send_email(
                    vendor_email,
                    f"🛒 New Order #{order.reference} - {shop.name}",
                    f"""
                    <h2>You have a new order!</h2>
                    <p>Hi {shop.name},</p>
                    <p>Order <b>#{order.reference}</b> has been paid for by {order.customer.username}.</p>
                    <p><b>Delivery Address:</b> {order.address}</p>
                    <p><b>Phone:</b> {order.phone}</p>
                    <br>
                    <p><a href="https://your-render-url.onrender.com/dashboard">Click here to log in and mark it as shipped.</a></p>
                    """
                )
            
            print(f"✅ Payment verified for Order {reference}")

    return '', 200

# ==================================================================
# VENDOR DASHBOARD
# ==================================================================
@app.route("/vendor/apply", methods=["GET", "POST"])
@login_required
def vendor_apply():
    if current_user.role != "vendor": return redirect(url_for("home"))
    existing = current_user.shop
    if existing and existing.verification_status == "ACTIVE": return redirect(url_for("dashboard"))

    if request.method == "POST":
        form, files = request.form, request.files
        checks = run_application_checks(form, files)
        if checks["blocking"]:
            for msg in checks["blocking"]: flash(msg, "error")
            return render_template("apply.html", shop=existing, form=form)

        name = form["name"].strip()
        if existing:
            shop = existing
            if shop.name.lower() != name.lower():
                base = slugify(name); slug, i = base, 1
                while Shop.query.filter_by(slug=slug).first(): i += 1; slug = f"{base}-{i}"
                shop.name, shop.slug = name, slug
        else:
            base = slugify(name); slug, i = base, 1
            while Shop.query.filter_by(slug=slug).first(): i += 1; slug = f"{base}-{i}"
            shop = Shop(owner_id=current_user.id, name=name, slug=slug)
            db.session.add(shop)

        shop.category = form.get("category"); shop.description = form.get("description")
        shop.seller_type = form.get("seller_type"); shop.phone = normalize_phone(form.get("phone"))
        shop.business_email = form.get("business_email"); shop.address = form.get("address")
        shop.city = form.get("city"); shop.state = form.get("state"); shop.location = f"{form.get('city')}, {form.get('state')}"
        shop.cac_number = form.get("cac_number"); shop.id_type = form.get("id_type"); shop.id_number = form.get("id_number")
        shop.product_summary = form.get("product_summary"); shop.price_range = form.get("price_range")
        shop.social_links = json.dumps([s.strip() for s in (form.get("social_links") or "").splitlines() if s.strip()])
        
        shop.logo = save_file(files.get("logo")) or shop.logo
        shop.banner = save_file(files.get("banner")) or shop.banner
        shop.id_image = save_file(files.get("id_image")) or shop.id_image

        shop.verification_status = "PENDING_REVIEW"
        shop.auto_flags = json.dumps(checks["warnings"])
        shop.submitted_at = datetime.utcnow()
        db.session.commit()
        flash("Application submitted for review.", "success")
        return redirect(url_for("vendor_status"))
    
    form = {k: getattr(existing, k, "") or "" for k in ["name","category","description","seller_type","phone","business_email","address","city","state","cac_number","id_type","id_number","product_summary","price_range"]}
    if existing and existing.social_links: form["social_links"] = "\n".join(json.loads(existing.social_links))
    return render_template("apply.html", shop=existing, form=form)

@app.route("/vendor/status")
@login_required
def vendor_status():
    if current_user.role != "vendor": return redirect(url_for("home"))
    if not current_user.shop: return redirect(url_for("vendor_apply"))
    return render_template("vendor_status.html", shop=current_user.shop, fee=ACTIVATION_FEE_NGN)

@app.route("/vendor/pay-activation", methods=["GET", "POST"])
@login_required
def pay_activation():
    shop = current_user.shop
    if not shop: return redirect(url_for("vendor_apply"))
    
    if request.method == "POST":
        shop.activation_paid = True
        shop.verification_status = "ACTIVE"
        shop.subscription_status = "ACTIVE"
        shop.is_approved = True
        
        now = datetime.utcnow()
        if shop.subscription_expires_at and shop.subscription_expires_at > now:
            shop.subscription_expires_at = shop.subscription_expires_at + timedelta(days=30)
        else:
            shop.subscription_expires_at = now + timedelta(days=30)
            
        db.session.commit()
        flash("🎉 Payment confirmed — your shop is LIVE for 30 days!", "success")
        return redirect(url_for("dashboard"))
    return render_template("vendor_pay.html", shop=shop, fee=ACTIVATION_FEE_NGN)

@app.route("/dashboard")
@login_required
def dashboard():
    shop = current_user.shop
    if not shop: return redirect(url_for("vendor_apply"))
    if shop.verification_status == "PENDING_REVIEW": return redirect(url_for("vendor_status"))
    if shop.verification_status == "REJECTED": return redirect(url_for("vendor_status"))
    if shop.verification_status == "APPROVED" and not shop.activation_paid: return redirect(url_for("pay_activation"))
    if shop.subscription_status == "EXPIRED": return redirect(url_for("pay_activation"))
    if shop.verification_status != "ACTIVE": return redirect(url_for("vendor_status"))

    products    = Product.query.filter_by(shop_id=shop.id).order_by(Product.created_at.desc()).all()
    convos      = Conversation.query.filter_by(shop_id=shop.id).order_by(Conversation.created_at.desc()).all()
    order_items = OrderItem.query.filter_by(shop_id=shop.id).order_by(OrderItem.id.desc()).all()
    
    days_left = max(0, (shop.subscription_expires_at - datetime.utcnow()).days) if shop.subscription_expires_at else 0
    total_sales = sum(i.price * i.qty for i in order_items if i.status in ["PAID", "SHIPPED", "DELIVERED"])
    
    return render_template("dashboard.html", shop=shop, products=products, order_items=order_items, convos=convos, days_left=days_left, total_sales=total_sales)

@app.route("/vendor/ship/<int:item_id>", methods=["POST"])
@login_required
def ship_item(item_id):
    item = OrderItem.query.get_or_404(item_id)
    if item.shop.owner_id != current_user.id: return "Unauthorized", 403
    if item.status == "PAID":
        item.status = "SHIPPED"
        db.session.commit()
        flash("Marked as shipped. Waiting for customer confirmation.", "success")
    return redirect(url_for("dashboard"))

@app.route("/vendor/product/add", methods=["POST"])
@login_required
def add_product():
    shop = current_user.shop
    if not shop or shop.verification_status != "ACTIVE": return redirect(url_for("dashboard"))
    db.session.add(Product(
        shop_id=shop.id, name=request.form.get("name"),
        description=request.form.get("description"),
        price=float(request.form.get("price", 0)), stock=int(request.form.get("stock", 0)),
        image=save_file(request.files.get("image"))
    ))
    db.session.commit(); flash("Product added.", "success")
    return redirect(url_for("dashboard"))

# ==================================================================
# WITHDRAWALS
# ==================================================================
@app.route("/vendor/withdraw", methods=["POST"])
@login_required
def vendor_withdraw():
    shop = current_user.shop
    if not shop: return redirect(url_for("home"))
    
    amount = float(request.form.get("amount", 0))
    bank_name = request.form.get("bank_name")
    acc_name = request.form.get("account_name")
    acc_num = request.form.get("account_number")

    if amount <= 0 or amount > shop.wallet_balance:
        flash("Invalid amount. You cannot withdraw more than your balance.", "error")
        return redirect(url_for("dashboard"))

    if not bank_name or not acc_name or not acc_num:
        flash("Please fill in all bank details.", "error")
        return redirect(url_for("dashboard"))

    shop.wallet_balance -= amount
    withdrawal = Withdrawal(shop_id=shop.id, amount=amount, bank_name=bank_name, account_name=acc_name, account_number=acc_num)
    db.session.add(withdrawal)
    db.session.commit()
    
    flash("Withdrawal request submitted! Admin will process it shortly.", "success")
    return redirect(url_for("dashboard"))

@app.route("/admin/withdrawals")
@login_required
def admin_withdrawals():
    if current_user.role != "admin": return redirect(url_for("home"))
    pending = Withdrawal.query.filter_by(status="PENDING").order_by(Withdrawal.created_at.desc()).all()
    history = Withdrawal.query.filter(Withdrawal.status != "PENDING").order_by(Withdrawal.processed_at.desc()).limit(20).all()
    return render_template("admin_withdrawals.html", pending=pending, history=history)

@app.route("/admin/withdrawals/<int:wid>/approve", methods=["POST"])
@login_required
def admin_approve_withdrawal(wid):
    if current_user.role != "admin": return "Forbidden", 403
    w = Withdrawal.query.get_or_404(wid)
    if w.status == "PENDING":
        w.status = "PAID"
        w.processed_at = datetime.utcnow()
        db.session.commit()
        
        send_email(
            w.shop.owner.email,
            f"💰 Payout Processed - ₦{w.amount:,.2f}",
            f"""
            <h2>Good news!</h2>
            <p>Hi {w.shop.name},</p>
            <p>Your withdrawal request of <b>₦{w.amount:,.2f}</b> has been successfully processed and sent to your bank account:</p>
            <p><b>Bank:</b> {w.bank_name}<br>
            <b>Account:</b> {w.account_number}</p>
            <p>Thank you for doing business with us!</p>
            """
        )
        
        flash("Withdrawal marked as Paid.", "success")
    return redirect(url_for("admin_withdrawals"))

@app.route("/admin/withdrawals/<int:wid>/reject", methods=["POST"])
@login_required
def admin_reject_withdrawal(wid):
    if current_user.role != "admin": return "Forbidden", 403
    w = Withdrawal.query.get_or_404(wid)
    if w.status == "PENDING":
        w.status = "REJECTED"
        w.processed_at = datetime.utcnow()
        w.shop.wallet_balance += w.amount
        db.session.commit()
        flash("Withdrawal rejected and funds returned to vendor.", "success")
    return redirect(url_for("admin_withdrawals"))

# ==================================================================
# ADMIN MASTER DASHBOARD & OTHERS
# ==================================================================
@app.route("/admin")
@login_required
def admin_dashboard():
    if current_user.role != "admin": return redirect(url_for("home"))
    
    active_shops = Shop.query.filter(Shop.activation_paid == True).count()
    sub_revenue = active_shops * ACTIVATION_FEE_NGN
    delivered_items = OrderItem.query.filter_by(status="DELIVERED").all()
    commission_revenue = sum((item.price * item.qty) * PLATFORM_COMMISSION for item in delivered_items)
    
    stats = {
        "sub_revenue": sub_revenue,
        "commission_revenue": commission_revenue,
        "total_revenue": sub_revenue + commission_revenue,
        "pending_apps": Shop.query.filter_by(verification_status="PENDING_REVIEW").count(),
        "pending_payouts": Withdrawal.query.filter_by(status="PENDING").count(),
        "total_users": User.query.count(),
        "total_orders": Order.query.count(),
        "total_products": Product.query.count(),
        "active_shops": active_shops
    }
    return render_template("admin_dashboard.html", stats=stats)

@app.route("/admin/applications")
@login_required
def admin_applications():
    if current_user.role != "admin": return redirect(url_for("home"))
    return render_template("admin_applications.html", 
        pending=Shop.query.filter_by(verification_status="PENDING_REVIEW").all(),
        approved=Shop.query.filter_by(verification_status="APPROVED").all(),
        rejected=Shop.query.filter_by(verification_status="REJECTED").all(),
        active=Shop.query.filter_by(verification_status="ACTIVE").all())

@app.route("/admin/applications/<int:sid>/approve", methods=["POST"])
@login_required
def admin_approve(sid):
    if current_user.role != "admin": return "Forbidden", 403
    shop = Shop.query.get_or_404(sid)
    shop.verification_status = "APPROVED"
    shop.reviewed_at = datetime.utcnow()
    db.session.commit()
    
    send_email(
        shop.owner.email,
        "🎉 Your Mall Application is Approved!",
        f"""
        <h2>Welcome to the Mall!</h2>
        <p>Hi {shop.owner.username},</p>
        <p>Your shop <b>{shop.name}</b> has been reviewed and approved.</p>
        <p>To start selling, please log in and pay the one-time activation fee of ₦10,000 to make your shop live.</p>
        <br>
        <p><a href="https://your-render-url.onrender.com/dashboard">Click here to log in and activate your shop.</a></p>
        """
    )
    
    flash(f"{shop.name} approved.", "success")
    return redirect(url_for("admin_applications"))

@app.route("/admin/applications/<int:sid>/reject", methods=["POST"])
@login_required
def admin_reject(sid):
    if current_user.role != "admin": return "Forbidden", 403
    shop = Shop.query.get_or_404(sid)
    shop.verification_status = "REJECTED"
    shop.rejection_reason = request.form.get("reason", "Invalid details.")
    shop.reviewed_at = datetime.utcnow()
    db.session.commit()
    
    send_email(
        shop.owner.email,
        "Update on your Mall Application",
        f"""
        <h2>Application Status Update</h2>
        <p>Hi {shop.owner.username},</p>
        <p>Unfortunately, your application for <b>{shop.name}</b> was not approved at this time.</p>
        <p><b>Reason:</b> {shop.rejection_reason}</p>
        <p>You can log in to review this and submit a new application if you wish.</p>
        """
    )
    
    flash("Shop rejected.", "success")
    return redirect(url_for("admin_applications"))

@app.route("/admin/reels")
@login_required
def admin_reels():
    if current_user.role != "admin": return redirect(url_for("home"))
    pending  = Reel.query.filter_by(is_approved=False).order_by(Reel.created_at.desc()).all()
    approved = Reel.query.filter_by(is_approved=True).order_by(Reel.created_at.desc()).all()
    return render_template("admin_reels.html", pending=pending, approved=approved)

@app.route("/admin/reels/<int:rid>/approve", methods=["POST"])
@login_required
def admin_approve_reel(rid):
    if current_user.role != "admin": return "Forbidden", 403
    r = Reel.query.get_or_404(rid); r.is_approved = True
    db.session.commit(); flash("Reel approved.", "success")
    return redirect(url_for("admin_reels"))

@app.route("/admin/reels/<int:rid>/reject", methods=["POST"])
@login_required
def admin_reject_reel(rid):
    if current_user.role != "admin": return "Forbidden", 403
    r = Reel.query.get_or_404(rid); db.session.delete(r); db.session.commit()
    flash("Reel removed.", "success")
    return redirect(url_for("admin_reels"))

# ==================================================================
# DEV UTILITIES
# ==================================================================
@app.route("/seed")
def seed():
    if Shop.query.count() > 0: return "Already seeded."
    demo = [("Royal Collections", "Watches", 189.0), ("Fashion House", "Fashion", 49.0), ("Tech World", "Electronics", 299.0)]
    for name, cat, base_price in demo:
        email = name.lower().replace(" ", "") + "@mall.test"
        vendor = User(username=name, email=email, password_hash=generate_password_hash("demo123"), role="vendor")
        db.session.add(vendor); db.session.flush()
        shop = Shop(owner_id=vendor.id, name=name, slug=slugify(name), category=cat, description="Demo shop.",
                    verification_status="ACTIVE", activation_paid=True, subscription_status="ACTIVE",
                    subscription_expires_at=datetime.utcnow()+timedelta(days=30), is_approved=True)
        db.session.add(shop); db.session.flush()
        for i in range(1, 4):
            db.session.add(Product(shop_id=shop.id, name=f"{name} Item {i}", price=base_price*i, stock=10))
    db.session.commit(); return "Seeded."

@app.route("/admin/create")
def admin_create():
    if User.query.filter_by(email="admin@mall.test").first(): return "Admin exists."
    db.session.add(User(username="Admin", email="admin@mall.test", password_hash=generate_password_hash("admin123"), role="admin"))
    db.session.commit(); return "Admin created."

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    socketio.run(app, debug=True, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)s