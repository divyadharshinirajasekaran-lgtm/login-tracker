from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import hashlib

db = SQLAlchemy()

def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    admin_module = db.Column(db.String(100))  # 'student', 'hotel', etc.
    locked = db.Column(db.Boolean, default=False)
    fail_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    ip_address = db.Column(db.String(50))
    status = db.Column(db.String(20))  # 'success', 'failed'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    device = db.Column(db.String(200))
    os_info = db.Column(db.String(100))
    browser = db.Column(db.String(100))
    threat_score = db.Column(db.Integer, default=0)
    threat_level = db.Column(db.String(20))  # LOW, MEDIUM, HIGH, CRITICAL
    location = db.Column(db.String(100))
    is_suspicious = db.Column(db.Boolean, default=False)
    
    # NEW: Advanced attack detection
    attack_type = db.Column(db.String(100))  # e.g., "Brute Force", "Bot", etc.
    attack_indicators = db.Column(db.Text)  # JSON: list of indicators found
    attack_evidence = db.Column(db.Text)  # JSON: evidence supporting attack
    velocity_score = db.Column(db.Integer, default=0)  # How fast requests
    bot_probability = db.Column(db.Integer, default=0)  # % chance it's automated
    
    # Website/Module info
    website = db.Column(db.String(100), default='general')  # 'student', 'hotel', 'ecommerce'
    module = db.Column(db.String(100))  # alternative to website
    
    # Additional metadata
    request_id = db.Column(db.String(100), unique=True)
    is_analyzed = db.Column(db.Boolean, default=False)

class BannedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True)
    banned_at = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.String(300))
    ban_type = db.Column(db.String(50))  # temporary, permanent
    expires_at = db.Column(db.DateTime)
    website = db.Column(db.String(100))  # which website banned it

class AttackSignature(db.Model):
    """Store known attack patterns and indicators"""
    id = db.Column(db.Integer, primary_key=True)
    attack_type = db.Column(db.String(100), unique=True)
    description = db.Column(db.Text)
    indicators = db.Column(db.Text)  # JSON: list of indicators
    base_threat_score = db.Column(db.Integer)  # baseline threat
    detection_rules = db.Column(db.Text)  # JSON: detection logic
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class WebsiteConfig(db.Model):
    """Configuration for each connected website"""
    id = db.Column(db.Integer, primary_key=True)
    website_name = db.Column(db.String(100), unique=True)
    api_key = db.Column(db.String(200), unique=True)
    description = db.Column(db.String(300))
    threshold_threat = db.Column(db.Integer, default=70)  # alert if > this
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AttackLog(db.Model):
    """Detailed log of all detected attacks"""
    id = db.Column(db.Integer, primary_key=True)
    login_attempt_id = db.Column(db.Integer, db.ForeignKey('login_attempt.id'))
    attack_type = db.Column(db.String(100))
    threat_score = db.Column(db.Integer)
    threat_level = db.Column(db.String(20))
    indicators_found = db.Column(db.Integer)  # how many indicators matched
    website = db.Column(db.String(100))
    ip_address = db.Column(db.String(50))
    action_taken = db.Column(db.String(200))  # "IP Banned", "Account Locked", etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
