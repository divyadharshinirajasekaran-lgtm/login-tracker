from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    locked = db.Column(db.Boolean, default=False)
    fail_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    ip_address = db.Column(db.String(50))
    status = db.Column(db.String(10))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    device = db.Column(db.String(200))
    os_info = db.Column(db.String(100))
    browser = db.Column(db.String(100))
    threat_score = db.Column(db.Integer, default=0)
    location = db.Column(db.String(100))
    is_suspicious = db.Column(db.Boolean, default=False)
    suspicious_reason = db.Column(db.String(300))

class BannedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True)
    banned_at = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.String(200))
