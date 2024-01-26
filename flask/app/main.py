from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from .models import Note
from .auth import password_strength
from bleach import clean
import markdown
import secrets
from . import db
import os

main = Blueprint('main', __name__)

@main.route('/')
def login():
    return render_template('login.html')

@main.route('/home')
@login_required
def home():
    notes = (
        db.session.query(Note).filter(Note.public == True).order_by(Note.date.desc()).limit(20).all()
    )
    return render_template('home.html', notes=notes)

@main.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile_post():
    if request.method == 'POST': 
        title = request.form.get('note_title')
        note = request.form.get('note')
        public = True if request.form.get('public') else False
        encrypted = True if request.form.get('encrypted')  else False
        if encrypted:
            password = request.form.get('note_password')
        else:
            password = None

        if len(note) < 1:
            flash('Note is too short!', category='error')
        elif public and encrypted:
            flash('Note cannot be public and encrypted.', category='error') 
        elif not title:
            flash('Title cannot be empty.', category='error') 
        elif len(title) > 100:
            flash('Title can contain up to 100 characters.', category='error') 
        else:

            if encrypted:
                if password_strength(password) == "Weak":
                    flash('Password is too weak. Try adding big letters, numbers and characters.')
                    return render_template("profile.html", user=current_user)
                note = encrypt(note.encode('utf-8'), password)
                print(note)
                password = generate_password_hash(password, method='sha256')
            
            new_note = Note(title = title, data=note, public = public, encrypted = encrypted, password = password, user_id=current_user.id) 
            db.session.add(new_note)
            db.session.commit()
            flash('Note added!', category='success')

    return render_template("profile.html", user=current_user)

@main.route('/<note_id>', methods=['GET', 'POST'])
@login_required
def note(note_id):
    note = Note.query.get(note_id)
    if note:
        if (not note.public and (note.user_id != current_user.id)):
            return "Access to note forbidden!", 403
        
        if ( not note.encrypted and (note.user_id == current_user.id)):
            sanitized_content = clean(note.data, tags=current_app.config['ALLOWED_TAGS'], attributes={'a': ['href']})
            rendered = markdown.markdown(sanitized_content)
            return render_template("note.html", note=note, data=note.data, rendered=rendered, user=current_user)
        elif ( note.encrypted  and (note.user_id == current_user.id)):
            return render_template("decrypt_note.html", note_id=note_id, user=current_user)

    return "Note not found", 404

@main.route('/decrypt_note', methods=['GET', 'POST'])
@login_required
def decrypt_note():
    note_id = request.form.get('note_id')
    note = Note.query.get(note_id)
    password = request.form.get('note_password')

    if not check_password_hash(note.password, password):
        flash('Please check passphrase and try again.')
        return render_template("decrypt_note.html", note_id=note_id, user=current_user)
    
    print(note.data)
    decrypted_data = decrypt(bytes(note.data), password)
    print(decrypted_data)
    sanitized_content = clean(decrypted_data, tags=current_app.config['ALLOWED_TAGS'], attributes={'a': ['href']})
    rendered = markdown.markdown(sanitized_content)

    return render_template("note.html", note=note, rendered=rendered, user=current_user)

backend = default_backend()
iterations = 100_000

def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))

def encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode('utf-8'), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )

def decrypt(token: bytes, password: str) -> str:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    decrypted_bytes = Fernet(key).decrypt(token)
    return decrypted_bytes.decode('utf-8')