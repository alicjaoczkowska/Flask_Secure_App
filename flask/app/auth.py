from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from io import BytesIO
from base64 import b64encode
import pyotp
import qrcode
from .models import User
import math
import time
from . import db

MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION = 300
failed_login_attempts = {}
key =  pyotp.random_base32()

auth = Blueprint('auth', __name__)

def password_strength(password):
    unique_characters = len(set(password))
    
    entropy = math.log2(unique_characters ** len(password))
    
    if entropy < 25:
        return "Weak"
    elif entropy < 60:
        return "Moderate"
    else:
        return "Strong"

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        failed_login_attempts[email] = failed_login_attempts.get(email, 0) + 1
        delay_seconds = 2 ** failed_login_attempts[email]
        time.sleep(delay_seconds)
        if failed_login_attempts[email] >= MAX_FAILED_ATTEMPTS:
                lockout_time = time.time() + LOCKOUT_DURATION
                failed_login_attempts[email] = lockout_time
        return redirect(url_for('auth.login'))
    else:
        failed_login_attempts[email] = 0

    login_user(user, remember=remember)
    
    return redirect(url_for('auth.totp'))

@auth.route('/totp')
def totp():
    uri = pyotp.totp.TOTP(key).provisioning_uri(name=current_user.email, issuer_name="Flask Security App")
    base64_qr_image = get_b64encoded_qr(uri)
    return render_template('totp.html', qr_image=base64_qr_image)

@auth.route('/totp', methods=['POST'])
def totp_post():
    code = request.form.get('code')
    totp = pyotp.TOTP(key)
    if not totp.verify(code):
        flash('Code incorrect.')
        return redirect(url_for('auth.login'))

    return redirect(url_for('main.profile'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()

    if user:
        flash('Email address already exists')
        return redirect(url_for('auth.signup'))
    
    if password_strength(password) == "Weak":
        flash('Password is too weak. Try adding big letters, numbers and characters.')
        return redirect(url_for('auth.signup'))

    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

def get_b64encoded_qr(data):
    print(data)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered)
    return b64encode(buffered.getvalue()).decode("utf-8")