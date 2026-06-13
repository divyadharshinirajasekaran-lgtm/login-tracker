from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, LoginAttempt, BannedIP, AttackLog, WebsiteConfig, hash_pw
from datetime import datetime, timedelta
import os
import json
import uuid
from user_agents import parse
import requests

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///tracker.db')
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ============ UTILITY FUNCTIONS ============

def get_device_info(user_agent_string):
    """Extract device, OS, browser info"""
    try:
        ua = parse(user_agent_string)
        return str(ua.device), str(ua.os), str(ua.browser)
    except:
        return 'Unknown', 'Unknown', 'Unknown'

def fake_location(ip):
    """Get location from IP"""
    if ip in ['127.0.0.1', 'localhost']:
        return 'Local Network'
    try:
        response = requests.get(f'https://ip-api.com/json/{ip}', timeout=2)
        data = response.json()
        if data.get('status') == 'success':
            return f"{data.get('city', '')}, {data.get('country', '')}"
    except:
        pass
    return 'Unknown'

# ============ ADVANCED ATTACK DETECTION ENGINE ============

class AttackDetectionEngine:
    """Universal attack detection for any website"""
    
    ATTACK_TYPES = {
        'brute_force': {
            'name': 'Brute Force Attack',
            'base_threat': 70,
            'indicators': [
                '3+ failed logins from same IP in 10 minutes',
                'Rapid-fire requests (< 1 second apart)',
                'Sequential or common password attempts',
                'Failed attempts followed by success'
            ]
        },
        'credential_stuffing': {
            'name': 'Credential Stuffing Attack',
            'base_threat': 85,
            'indicators': [
                '5+ different usernames attempted from same IP',
                'Mix of successful and failed attempts',
                'Common password patterns detected',
                'Volume suggests automation (10+ attempts/minute)'
            ]
        },
        'account_enumeration': {
            'name': 'Account Enumeration',
            'base_threat': 55,
            'indicators': [
                'Testing which usernames exist',
                'Different response times for valid vs invalid users',
                'No password attempts, only username probing',
                '3+ different usernames from same IP'
            ]
        },
        'bot_attack': {
            'name': 'Automated Bot Attack',
            'base_threat': 75,
            'indicators': [
                '5+ requests in under 60 seconds',
                'Identical user agents or no user agent',
                'Exact timing between requests (< 100ms)',
                'No human-like behavior patterns'
            ]
        },
        'distributed_attack': {
            'name': 'Distributed Attack',
            'base_threat': 90,
            'indicators': [
                'Same username attacked from 5+ different IPs',
                'Coordinated timing across IPs',
                'Different geographic locations',
                'Professional attack infrastructure signatures'
            ]
        },
        'dictionary_attack': {
            'name': 'Dictionary Attack',
            'base_threat': 68,
            'indicators': [
                'Systematic password testing',
                'Uses common password lists',
                'Multiple failed attempts for single account',
                'Predictable password sequences'
            ]
        },
        'odd_hours_access': {
            'name': 'Suspicious Time Access',
            'base_threat': 35,
            'indicators': [
                'Login attempt between 12 AM - 5 AM',
                'Outside normal user activity hours',
                'Unusual for this account',
                'Combined with other factors'
            ]
        },
        'location_anomaly': {
            'name': 'Location Anomaly',
            'base_threat': 45,
            'indicators': [
                'Login from new geographic location',
                'Impossible travel time between locations',
                'VPN or proxy detected',
                'First-time country access'
            ]
        },
        'session_hijacking': {
            'name': 'Session Hijacking Attempt',
            'base_threat': 80,
            'indicators': [
                'Different device/browser for known account',
                'Device fingerprint mismatch',
                'Unusual user agent string',
                'IP change mid-session'
            ]
        },
        'privilege_escalation': {
            'name': 'Privilege Escalation Attempt',
            'base_threat': 95,
            'indicators': [
                'Admin account targeted',
                'Multiple failed attempts on admin account',
                'Access to sensitive functions attempted',
                'Unusual for this user account'
            ]
        }
    }
    
    @staticmethod
    def analyze_login(username, ip, status, website, device='Unknown', os_info='Unknown', browser='Unknown'):
        """Comprehensive attack analysis"""
        
        indicators_found = []
        evidence = []
        attack_type = None
        threat_score = 0
        
        # Check IP history
        ip_fails_10min = LoginAttempt.query.filter(
            LoginAttempt.ip_address == ip,
            LoginAttempt.status == 'failed',
            LoginAttempt.timestamp >= datetime.utcnow() - timedelta(minutes=10),
            LoginAttempt.website == website
        ).count()
        
        ip_attempts_1min = LoginAttempt.query.filter(
            LoginAttempt.ip_address == ip,
            LoginAttempt.timestamp >= datetime.utcnow() - timedelta(minutes=1),
            LoginAttempt.website == website
        ).count()
        
        # Check username history
        user_fails_30min = LoginAttempt.query.filter(
            LoginAttempt.username == username,
            LoginAttempt.status == 'failed',
            LoginAttempt.timestamp >= datetime.utcnow() - timedelta(minutes=30),
            LoginAttempt.website == website
        ).count()
        
        different_users_10min = LoginAttempt.query.filter(
            LoginAttempt.ip_address == ip,
            LoginAttempt.timestamp >= datetime.utcnow() - timedelta(minutes=10),
            LoginAttempt.website == website
        ).distinct(LoginAttempt.username).count()
        
        # DETECT: Brute Force
        if ip_fails_10min >= 3:
            indicators_found.append('3+ failed logins in 10 minutes')
            evidence.append(f'{ip_fails_10min} failed attempts from same IP')
            attack_type = 'brute_force'
            threat_score = 70
        
        # DETECT: Bot Attack
        if ip_attempts_1min >= 5:
            indicators_found.append('5+ requests in 60 seconds')
            evidence.append(f'{ip_attempts_1min} rapid requests detected')
            attack_type = 'bot_attack'
            threat_score = max(threat_score, 75)
        
        # DETECT: Credential Stuffing
        if different_users_10min >= 5:
            indicators_found.append('5+ different usernames attempted')
            evidence.append(f'{different_users_10min} different accounts probed')
            attack_type = 'credential_stuffing'
            threat_score = max(threat_score, 85)
        
        # DETECT: Account Enumeration
        if different_users_10min >= 3 and status == 'failed':
            indicators_found.append('Account enumeration pattern detected')
            evidence.append(f'Multiple usernames tested: {different_users_10min}')
            if not attack_type:
                attack_type = 'account_enumeration'
                threat_score = max(threat_score, 55)
        
        # DETECT: Odd Hours Access
        hour = datetime.utcnow().hour
        if hour >= 0 and hour < 5:
            indicators_found.append('Login during odd hours (12 AM - 5 AM)')
            evidence.append(f'Attempt at {hour}:XX (unusual time)')
            threat_score += 20
        
        # DETECT: Admin targeting
        if 'admin' in username.lower():
            indicators_found.append('Admin account targeted')
            evidence.append('Attempt on privileged account detected')
            threat_score += 25
            if threat_score >= 80:
                attack_type = 'privilege_escalation'
        
        # Velocity score (how fast)
        if ip_attempts_1min >= 1:
            velocity_score = min((ip_attempts_1min / 5) * 100, 100)
        else:
            velocity_score = 0
        
        # Bot probability
        if ip_attempts_1min >= 5 or (ip_fails_10min >= 3 and browser == 'Unknown'):
            bot_probability = 85
        elif ip_fails_10min >= 1:
            bot_probability = 45
        else:
            bot_probability = 10
        
        # Threat level
        if threat_score >= 80:
            threat_level = 'CRITICAL'
        elif threat_score >= 60:
            threat_level = 'HIGH'
        elif threat_score >= 40:
            threat_level = 'MEDIUM'
        else:
            threat_level = 'LOW'
        
        is_suspicious = threat_score >= 40
        
        return {
            'attack_type': attack_type,
            'indicators': indicators_found,
            'evidence': evidence,
            'threat_score': threat_score,
            'threat_level': threat_level,
            'is_suspicious': is_suspicious,
            'velocity_score': velocity_score,
            'bot_probability': bot_probability
        }

# ============ UNIVERSAL API ENDPOINT ============

@app.route('/api/track-login', methods=['POST'])
def api_track_login():
    """
    Universal endpoint for ANY website to send login data
    
    POST /api/track-login
    {
        "username": "user@email.com",
        "ip_address": "192.168.1.5",
        "status": "success",  # or "failed"
        "device": "Mobile",
        "browser": "Chrome",
        "os": "Android",
        "website": "student-management"  # or "hotel", "ecommerce", etc.
    }
    """
    
    try:
        data = request.json
        
        username = data.get('username', 'unknown')
        ip = data.get('ip_address', request.remote_addr)
        status = data.get('status', 'unknown')
        device = data.get('device', 'Unknown')
        browser = data.get('browser', 'Unknown')
        os_info = data.get('os', 'Unknown')
        website = data.get('website', 'general')
        
        location = fake_location(ip)
        
        # Run attack detection
        detection = AttackDetectionEngine.analyze_login(
            username, ip, status, website, device, os_info, browser
        )
        
        # Save login attempt
        request_id = str(uuid.uuid4())
        attempt = LoginAttempt(
            username=username,
            ip_address=ip,
            status=status,
            device=device,
            os_info=os_info,
            browser=browser,
            threat_score=detection['threat_score'],
            threat_level=detection['threat_level'],
            location=location,
            is_suspicious=detection['is_suspicious'],
            attack_type=detection['attack_type'],
            attack_indicators=json.dumps(detection['indicators']),
            attack_evidence=json.dumps(detection['evidence']),
            velocity_score=detection['velocity_score'],
            bot_probability=detection['bot_probability'],
            website=website,
            request_id=request_id,
            is_analyzed=True
        )
        db.session.add(attempt)
        
        # Log attack if detected
        if detection['is_suspicious'] and detection['attack_type']:
            attack_log = AttackLog(
                login_attempt_id=attempt.id,
                attack_type=detection['attack_type'],
                threat_score=detection['threat_score'],
                threat_level=detection['threat_level'],
                indicators_found=len(detection['indicators']),
                website=website,
                ip_address=ip
            )
            db.session.add(attack_log)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'request_id': request_id,
            'threat_score': detection['threat_score'],
            'threat_level': detection['threat_level'],
            'attack_type': detection['attack_type'],
            'is_suspicious': detection['is_suspicious'],
            'message': 'Login tracked successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

# ============ ADMIN ROUTES ============

@app.route('/')
def index():
    """Redirect to dashboard"""
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        module = request.form.get('module', 'student')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == hash_pw(password):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        
        flash('Invalid credentials', 'danger')
        return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    """Admin dashboard - shows attacks based on admin_module"""
    
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    website = current_user.admin_module
    
    # Stats
    total_attempts = LoginAttempt.query.filter_by(website=website).count()
    successful = LoginAttempt.query.filter_by(website=website, status='success').count()
    failed = LoginAttempt.query.filter_by(website=website, status='failed').count()
    suspicious = LoginAttempt.query.filter_by(website=website, is_suspicious=True).count()
    critical_attacks = LoginAttempt.query.filter(
        LoginAttempt.website == website,
        LoginAttempt.threat_level == 'CRITICAL'
    ).count()
    
    # Recent attacks
    recent_attacks = LoginAttempt.query.filter(
        LoginAttempt.website == website,
        LoginAttempt.is_suspicious == True
    ).order_by(LoginAttempt.timestamp.desc()).limit(20).all()
    
    # Attack breakdown
    attack_types = db.session.query(
        LoginAttempt.attack_type,
        db.func.count(LoginAttempt.id)
    ).filter(
        LoginAttempt.website == website,
        LoginAttempt.is_suspicious == True
    ).group_by(LoginAttempt.attack_type).all()
    
    return render_template('admin_dashboard.html',
        total=total_attempts,
        successful=successful,
        failed=failed,
        suspicious=suspicious,
        critical=critical_attacks,
        recent_attacks=recent_attacks,
        attack_types=attack_types,
        website=website
    )

@app.route('/admin/attacks')
@login_required
def view_attacks():
    """Detailed attack log"""
    
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    website = current_user.admin_module
    
    attacks = LoginAttempt.query.filter(
        LoginAttempt.website == website,
        LoginAttempt.is_suspicious == True
    ).order_by(LoginAttempt.timestamp.desc()).all()
    
    return render_template('admin_attacks.html', attacks=attacks, website=website)

@app.route('/admin/attack/<int:attack_id>')
@login_required
def attack_detail(attack_id):
    """Detailed attack analysis"""
    
    attack = LoginAttempt.query.get(attack_id)
    
    if not attack or attack.website != current_user.admin_module:
        return redirect(url_for('admin_dashboard'))
    
    indicators = json.loads(attack.attack_indicators) if attack.attack_indicators else []
    evidence = json.loads(attack.attack_evidence) if attack.attack_evidence else []
    
    return render_template('attack_detail.html',
        attack=attack,
        indicators=indicators,
        evidence=evidence
    )

# ============ INITIALIZATION ============

with app.app_context():
    db.create_all()
    
    # Create default admins
    if not User.query.filter_by(username='admin_student').first():
        admin_student = User(
            username='admin_student',
            password=hash_pw('student123'),
            is_admin=True,
            admin_module='student'
        )
        db.session.add(admin_student)
    
    if not User.query.filter_by(username='admin_hotel').first():
        admin_hotel = User(
            username='admin_hotel',
            password=hash_pw('hotel123'),
            is_admin=True,
            admin_module='hotel'
        )
        db.session.add(admin_hotel)
    
    db.session.commit()

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))  # change default port for each
    app.run(debug=False, host='0.0.0.0', port=port)
