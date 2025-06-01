from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import AnonymousUserMixin

from config import Config  


class User(db.Model, UserMixin):
    __tablename__ = 'users'  # rename table
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=False, nullable=True)  # Wyłącz unikalność
    password_hash = db.Column(db.String(128))
    role = db.Column(db.Integer, default=0)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
       
    def has_role(self, role_name):
        return self.role >= Config.USER_ROLES.get(role_name, 0)
    
    files = db.relationship('File', backref='owner', lazy=True)  # Dodaj relację




class AnonymousUser(AnonymousUserMixin):
    def has_role(self, role_name):
        return False
        
        
        
class BannedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False, unique=True)
    reason = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    ip = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.Text)
    path = db.Column(db.String(500), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
class File(db.Model):
    __tablename__ = 'files'  # rename table
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    original_name = db.Column(db.String(100), nullable=False)  
    visibility = db.Column(db.String(10), default='public')
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)  
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # Apply for new name
    
    
    
 
    