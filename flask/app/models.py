from flask_login import UserMixin
from sqlalchemy.sql import func
from . import db

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    data = db.Column(db.String(10000))
    public = db.Column(db.Boolean, default=False)
    encrypted = db.Column(db.Boolean, default=False)
    password = db.Column(db.String(100))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    notes = db.relationship('Note')