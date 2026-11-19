from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="customer")  # customer | vendor | admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    shop = db.relationship("Shop", backref="owner", uselist=False)
    wishlist = db.relationship("Wishlist", backref="user", lazy=True, cascade="all, delete")


class Shop(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(120), unique=True, nullable=False)
    slug = db.Column(db.String(140), unique=True, nullable=False)
    category = db.Column(db.String(60))
    description = db.Column(db.Text)
    logo = db.Column(db.String(255))
    banner = db.Column(db.String(255))
    location = db.Column(db.String(120))

    # Verification / KYC
    legal_name = db.Column(db.String(200))
    seller_type = db.Column(db.String(20))
    phone = db.Column(db.String(40))
    whatsapp = db.Column(db.String(40))
    business_email = db.Column(db.String(120))
    address = db.Column(db.Text)
    city = db.Column(db.String(80))
    state = db.Column(db.String(80))
    cac_number = db.Column(db.String(60))
    id_type = db.Column(db.String(40))
    id_number = db.Column(db.String(80))
    id_image = db.Column(db.String(255))
    social_links = db.Column(db.Text)
    product_summary = db.Column(db.Text)
    price_range = db.Column(db.String(60))

    # Workflow & Wallet
    verification_status = db.Column(db.String(30), default="PENDING_REVIEW")
    auto_flags = db.Column(db.Text, default="[]")
    rejection_reason = db.Column(db.Text)
    activation_paid = db.Column(db.Boolean, default=False)
    activation_ref = db.Column(db.String(40))
    subscription_status = db.Column(db.String(20), default="INACTIVE")
    subscription_expires_at = db.Column(db.DateTime)
    
    # Analytics & Wallet
    is_approved = db.Column(db.Boolean, default=False)
    views = db.Column(db.Integer, default=0)
    wallet_balance = db.Column(db.Float, default=0.0)
    
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    products = db.relationship("Product", backref="shop", lazy=True, cascade="all, delete")
    reviews = db.relationship("Review", backref="shop", lazy=True, cascade="all, delete")


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shop_id = db.Column(db.Integer, db.ForeignKey("shop.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(255))
    stock = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    views = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    reviews = db.relationship("Review", backref="product", lazy=True, cascade="all, delete")


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    shop_id = db.Column(db.Integer, db.ForeignKey("shop.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    messages = db.relationship("Message", backref="conversation", lazy=True,
                               cascade="all, delete", order_by="Message.created_at")


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("conversation.id"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    body = db.Column(db.Text)
    image = db.Column(db.String(255))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    total = db.Column(db.Float, nullable=False)
    reference = db.Column(db.String(40), unique=True)
    status = db.Column(db.String(20), default="PAID")
    address = db.Column(db.Text)
    phone = db.Column(db.String(40))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    items = db.relationship("OrderItem", backref="order", cascade="all, delete")


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)
    shop_id = db.Column(db.Integer, db.ForeignKey("shop.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    name = db.Column(db.String(200))
    price = db.Column(db.Float)
    qty = db.Column(db.Integer, default=1)
    
    # Status Flow: PAID -> SHIPPED -> DELIVERED (Funds Released)
    status = db.Column(db.String(20), default="PAID") 

    shop = db.relationship("Shop")
    product = db.relationship("Product")


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shop_id = db.Column(db.Integer, db.ForeignKey("shop.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    rating = db.Column(db.Integer, default=5)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    customer = db.relationship("User")


class Wishlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    product = db.relationship("Product")


class Reel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shop_id = db.Column(db.Integer, db.ForeignKey("shop.id"), nullable=False)
    video_url = db.Column(db.String(255), nullable=False)
    poster_url = db.Column(db.String(255))
    caption = db.Column(db.Text)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"))
    is_sponsored = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, default=False)
    views = db.Column(db.Integer, default=0)
    likes = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    shop = db.relationship("Shop")
    product = db.relationship("Product")