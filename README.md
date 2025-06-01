# Sharelynx - Secure File Sharing Platform

Sharelynx is a secure file sharing platform with military-grade encryption, user authentication, and role-based access control.

![App Screenshot](/app/static/images/screen.jpg)
![App Screenshot](/app/static/images/screen1.jpg)

## Features
- 🔐 User authentication with secure password hashing
- 📁 File uploads with visibility settings (public/protected/private)
- 👑 Admin dashboard with user management
- 🛡️ IP banning and activity logging
- ⚡ Cloudflare tunnel support
- 📦 Docker container support
- 🚀 Automatic production deployment via SSH

## Quick Start
```bash
git clone https://github.com/Nauteirius/Sharelynx.git
cd Sharelynx
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate    # Windows
pip install -r requirements.txt
cp config.example.py config.py
# Edit config.py and set SECRET_KEY
flask db upgrade
flask run
