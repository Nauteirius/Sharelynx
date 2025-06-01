import os
from pathlib import Path

# instance path
instance_path = Path(__file__).parent / "instance"
instance_path.mkdir(exist_ok=True)  # Make folder if not exists

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'change-me-to-a-secure-key'
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{instance_path}/site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = instance_path / 'uploads'
    # Allowed extensions 
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif',
        'py', 'zip', 'rar', 'mp4', 'mov', 'avi', 'mkv', 'webm',
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'
    }
    
    # Max filesize
    MAX_CONTENT_LENGTH = 15 * 1024 * 1024 * 1024  # 15 GB
    USER_ROLES = {
        'admin': 2,
        'user': 1,
        'guest': 0
    }