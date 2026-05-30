from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, LoginAttempt, BannedIP
from datetime import datetime, timedelta
from user_agents import parse as ua_parse
import hashlib

app = Flask(__name__)
app.secret_key = 'internship_secret_2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

MAX_FAIL = 5
IP_BAN_LIMIT = 10

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def get_device_info():
    ua = ua_parse(request.headers.get('User-Agent', ''))
    device = 'Mobile' if ua.is_mobile else ('Tablet' if ua.is_tablet else 'Desktop')
    return device, f"{ua.os.family} {ua.os.version_string}".strip(), f"{ua.browser.family}".strip()

def fake_location(ip):
    try:
        if ip == '127.0.0.1' or ip.startswith('192.168') or ip.startswith('10.') or ip.startswith('172.'):
            return 'Local Network'
        import requests
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
        data = response.json()
        if data['status'] == 'success':
            return f"{data['city']}, {data['regionName']}, {data['country']}"
        else:
            return 'Unknown Location'
    except:
        return 'Unknown Location'

def calculate_threat(ip, username):
    score = 0
    now = datetime.utcnow()
    ip_fails = LoginAttempt.query.filter_by(ip_address=ip, status='failed')\
        .filter(LoginAttempt.timestamp > now - timedelta(minutes=10)).count()
    score += min(ip_fails * 20, 60)
    user_fails = LoginAttempt.query.filter_by(username=username, status='failed')\
        .filter(LoginAttempt.timestamp > now - timedelta(minutes=30)).count()
    score += min(user_fails * 10, 40)
    if now.hour >= 0 and now.hour < 5:
        score += 15
    return min(score, 100)

def detect_suspicious(ip, username, threat_score):
    reasons = []
    now = datetime.utcnow()

    ip_fails_10m = LoginAttempt.query.filter_by(ip_address=ip, status='failed')\
        .filter(LoginAttempt.timestamp > now - timedelta(minutes=10)).count()
    if ip_fails_10m >= 3:
        reasons.append('Brute Force')

    user_fails_30m = LoginAttempt.query.filter_by(username=username, status='failed')\
        .filter(LoginAttempt.timestamp > now - timedelta(minutes=30)).count()
    if user_fails_30m >= 5:
        reasons.append('Credential Stuffing')

    if now.hour >= 0 and now.hour < 5:
        reasons.append('Odd Hours')

    unique_users = db.session.query(LoginAttempt.username)\
        .filter_by(ip_address=ip)\
        .filter(LoginAttempt.timestamp > now - timedelta(minutes=30))\
        .distinct().count()
    if unique_users >= 3:
        reasons.append('Username Enumeration')

    rapid = LoginAttempt.query.filter_by(ip_address=ip)\
        .filter(LoginAttempt.timestamp > now - timedelta(seconds=60)).count()
    if rapid >= 5:
        reasons.append('Automated Bot')

    if BannedIP.query.filter_by(ip_address=ip).first():
        reasons.append('Banned IP Attempt')

    if threat_score >= 60 and not reasons:
        reasons.append('High Threat Score')

    return bool(reasons), ', '.join(reasons)

def maybe_ban_ip(ip):
    if ip == '127.0.0.1':  # Never ban localhost
        return
    fails = LoginAttempt.query.filter_by(ip_address=ip, status='failed')\
        .filter(LoginAttempt.timestamp > datetime.utcnow() - timedelta(hours=1)).count()
    if fails >= IP_BAN_LIMIT:
        if not BannedIP.query.filter_by(ip_address=ip).first():
            db.session.add(BannedIP(ip_address=ip, reason=f'Auto-banned: {fails} failed attempts in 1 hour'))
            db.session.commit()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ip = request.remote_addr
        device, os_info, browser = get_device_info()
        location = fake_location(ip)
        threat = calculate_threat(ip, username)
        is_sus, sus_reason = detect_suspicious(ip, username, threat)

        if BannedIP.query.filter_by(ip_address=ip).first():
            db.session.add(LoginAttempt(username=username, ip_address=ip, status='blocked',
                device=device, os_info=os_info, browser=browser, threat_score=100,
                location=location, is_suspicious=True, suspicious_reason='Banned IP Attempt'))
            db.session.commit()
            flash('Access denied. Your IP is banned.', 'danger')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()
        if not user:
            db.session.add(LoginAttempt(username=username, ip_address=ip, status='failed',
                device=device, os_info=os_info, browser=browser, threat_score=threat,
                location=location, is_suspicious=is_sus, suspicious_reason=sus_reason))
            db.session.commit()
            maybe_ban_ip(ip)
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')

        if user.locked:
            db.session.add(LoginAttempt(username=username, ip_address=ip, status='blocked',
                device=device, os_info=os_info, browser=browser, threat_score=100,
                location=location, is_suspicious=True, suspicious_reason='Account Locked'))
            db.session.commit()
            return redirect(url_for('locked'))

        if user.password != hash_pw(password):
            user.fail_count += 1
            if user.fail_count >= MAX_FAIL:
                user.locked = True
            db.session.add(LoginAttempt(username=username, ip_address=ip, status='failed',
                device=device, os_info=os_info, browser=browser, threat_score=threat,
                location=location, is_suspicious=is_sus, suspicious_reason=sus_reason))
            db.session.commit()
            maybe_ban_ip(ip)
            remaining = max(0, MAX_FAIL - user.fail_count)
            if user.locked:
                return redirect(url_for('locked'))
            flash(f'Wrong password. {remaining} attempt(s) remaining.', 'danger')
            return render_template('login.html')

        user.fail_count = 0
        db.session.add(LoginAttempt(username=username, ip_address=ip, status='success',
            device=device, os_info=os_info, browser=browser, threat_score=0,
            location=location, is_suspicious=False, suspicious_reason=''))
        db.session.commit()
        login_user(user)
        return redirect(url_for('admin') if user.is_admin else url_for('dashboard'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if len(username) < 3:
            flash('Username must be at least 3 characters.', 'danger')
            return render_template('register.html')
        if len(password) < 4:
            flash('Password must be at least 4 characters.', 'danger')
            return render_template('register.html')
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return render_template('register.html')
        db.session.add(User(username=username, password=hash_pw(password)))
        db.session.commit()
        flash('Account created! Please sign in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    attempts = LoginAttempt.query.filter_by(username=current_user.username)\
        .order_by(LoginAttempt.timestamp.desc()).limit(20).all()
    total = len(attempts)
    success = sum(1 for a in attempts if a.status == 'success')
    failed = sum(1 for a in attempts if a.status == 'failed')
    suspicious = sum(1 for a in attempts if a.is_suspicious)
    last_login = next((a for a in attempts if a.status == 'success'), None)
    hour_data = [0] * 24
    for a in LoginAttempt.query.filter_by(username=current_user.username).all():
        hour_data[a.timestamp.hour] += 1
    import json
    return render_template('dashboard.html', attempts=attempts, total=total,
        success=success, failed=failed, suspicious=suspicious,
        last_login=last_login, hour_data=json.dumps(hour_data))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    import json
    attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).limit(100).all()
    users = User.query.filter_by(is_admin=False).all()
    banned = BannedIP.query.all()
    suspicious_list = LoginAttempt.query.filter_by(is_suspicious=True)\
        .order_by(LoginAttempt.timestamp.desc()).limit(20).all()
    total = LoginAttempt.query.count()
    success = LoginAttempt.query.filter_by(status='success').count()
    failed = LoginAttempt.query.filter_by(status='failed').count()
    sus_count = LoginAttempt.query.filter_by(is_suspicious=True).count()
    locked_count = User.query.filter_by(locked=True).count()
    hour_data = [0] * 24
    for a in LoginAttempt.query.all():
        hour_data[a.timestamp.hour] += 1
    return render_template('admin.html', attempts=attempts, users=users,
        banned=banned, suspicious_list=suspicious_list,
        total=total, success=success, failed=failed,
        sus_count=sus_count, locked_count=locked_count,
        hour_data=json.dumps(hour_data))

@app.route('/unlock/<username>')
@login_required
def unlock(username):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    user = User.query.filter_by(username=username).first()
    if user:
        user.locked = False
        user.fail_count = 0
        db.session.commit()
        flash(f'{username} has been unlocked.', 'success')
    return redirect(url_for('admin'))

@app.route('/unban/<ip>')
@login_required
def unban(ip):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    ban = BannedIP.query.filter_by(ip_address=ip).first()
    if ban:
        db.session.delete(ban)
        db.session.commit()
        flash(f'IP {ip} has been unbanned.', 'success')
    return redirect(url_for('admin'))

@app.route('/api/stats')
@login_required
def api_stats():
    if not current_user.is_admin:
        return jsonify({'error': 'unauthorized'}), 403
    return jsonify({
        'total': LoginAttempt.query.count(),
        'success': LoginAttempt.query.filter_by(status='success').count(),
        'failed': LoginAttempt.query.filter_by(status='failed').count(),
        'suspicious': LoginAttempt.query.filter_by(is_suspicious=True).count(),
        'locked': User.query.filter_by(locked=True).count()
    })

@app.route('/locked')
def locked():
    return render_template('locked.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        db.session.add(User(username='admin', password=hash_pw('admin123'), is_admin=True))
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
