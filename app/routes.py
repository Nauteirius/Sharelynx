from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
#from werkzeug import useragents
#from werkzeug import user_agent
from user_agents import parse  # Wymaga zainstalowanego pakietu 'user-agents'
from app import db, login_manager
from app.models import User, File, BannedIP, UserActivity
from config import Config
import os
from datetime import datetime


main_bp = Blueprint('main', __name__)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

@main_bp.route('/')
def home():
    return render_template('index.html')

@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.files'))
    
    if request.method == 'POST':
        username = request.form.get('username')  # Zmiana z email na username
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()  # Szukaj po username
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.files'))
        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
    
    return render_template('login.html')

@main_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@main_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')  # Może być puste
        password = request.form.get('password')
        
        # Sprawdzamy tylko nazwę użytkownika
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('main.register'))
        
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        new_user.role = Config.USER_ROLES['user']
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please login', 'success')
        return redirect(url_for('main.login'))
    
    return render_template('register.html')

@main_bp.route('/files')
@main_bp.route('/files')
def files():
    # Pobierz pliki wg uprawnień
    if not current_user.is_authenticated:
        accessible_files = File.query.filter_by(visibility='public').all()
    elif current_user.has_role('admin'):
        accessible_files = File.query.all()
    else:
        accessible_files = File.query.filter(
            (File.visibility == 'public') | 
            (File.visibility == 'protected')
        ).all()
    
    return render_template('files.html', files=accessible_files)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

@main_bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
       #  Check file size before processing
    if request.content_length > Config.MAX_CONTENT_LENGTH:
        flash('File exceeds maximum size limit of 15GB', 'danger')
        return redirect(url_for('main.files'))
    
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('main.files'))
    
    file = request.files['file']
    visibility = request.form.get('visibility', 'public')
    
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('main.files'))
    
    # 4. Check allowed file type
    if file and allowed_file(file.filename):
        # Clean original filename
        original_name = secure_filename(file.filename)
        base, ext = os.path.splitext(original_name)
        
        # Generate unique filename if exists
        counter = 1
        unique_name = original_name
        save_path = Config.UPLOAD_FOLDER / visibility / unique_name
        
        # Prevent overwriting existing files
        while save_path.exists():
            unique_name = f"{base}_{counter}{ext}"
            save_path = Config.UPLOAD_FOLDER / visibility / unique_name
            counter += 1
        
        # Create directory if needed
        save_path.parent.mkdir(exist_ok=True, parents=True)
        
        # Save file
        file.save(save_path)
        
        # Create database record
        new_file = File(
            filename=unique_name,        # Unique filename for storage
            original_name=original_name,  # Original name for display
            visibility=visibility,
            user_id=current_user.id,
            upload_date=datetime.utcnow()
        )
        db.session.add(new_file)
        db.session.commit()
        
        flash('File uploaded successfully', 'success')
    else:
        flash('Invalid file type', 'danger')
    
    return redirect(url_for('main.files'))


@main_bp.route('/download/<visibility>/<filename>')
def download_file(visibility, filename):
    if visibility == 'public':
        return send_from_directory(str(Config.UPLOAD_FOLDER / 'public'), filename)
    elif visibility == 'protected':
        if not current_user.is_authenticated:
            abort(403)
        return send_from_directory(str(Config.UPLOAD_FOLDER / 'protected'), filename)
    elif visibility == 'private':
        if not current_user.is_authenticated or (
            current_user.role < Config.USER_ROLES['admin'] and 
            not File.query.filter_by(filename=filename, user_id=current_user.id).first()
        ):
            abort(403)
        return send_from_directory(str(Config.UPLOAD_FOLDER / 'private'), filename)
    else:
        abort(404)


    
    
@main_bp.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.has_role('admin'):
        abort(403)
        
        
    # Get all users and create mapping
    all_users = User.query.all()
    user_map = {user.id: user.username for user in all_users}    
    # Get page number from query params
    page = request.args.get('page', 1, type=int)
    
    # Paginate activities
    activities = UserActivity.query.order_by(
        UserActivity.timestamp.desc()
    ).paginate(page=page, per_page=50)
    

    
    return render_template('admin/dashboard.html',
        users=all_users,
        user_map = user_map,
        activities=activities,#UserActivity.query.order_by(UserActivity.timestamp.desc()).limit(100).all(),
        banned_ips=BannedIP.query.all(),
        files=File.query.all()
    )

@main_bp.route('/admin/ban_ip', methods=['POST'])
@login_required
def ban_ip():
    if not current_user.has_role('admin'):
        abort(403)
    
    ip = request.form.get('ip')
    reason = request.form.get('reason')
    
    existing = BannedIP.query.filter_by(ip=ip).first()
    if not existing:
        new_ban = BannedIP(ip=ip, reason=reason)
        db.session.add(new_ban)
        db.session.commit()
        flash('IP banned successfully', 'success')
    else:
        flash('IP already banned', 'warning')
    
    return redirect(url_for('main.admin_dashboard'))

@main_bp.route('/admin/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    if not current_user.has_role('admin'):
        abort(403)
    
    file = File.query.get_or_404(file_id)
    
    # Usuń plik z dysku
    file_path = Config.UPLOAD_FOLDER / file.visibility / file.filename
    if file_path.exists():
        file_path.unlink()
    
    db.session.delete(file)
    db.session.commit()
    flash('File deleted successfully', 'success')
    return redirect(url_for('main.admin_dashboard'))

@main_bp.route('/admin/rename_file/<int:file_id>', methods=['POST'])
@login_required
def rename_file(file_id):
    if not current_user.has_role('admin'):
        abort(403)
    
    file = File.query.get_or_404(file_id)
    new_name = request.form.get('new_name')
    
    if not new_name or '.' not in new_name:
        flash('Invalid filename', 'danger')
        return redirect(url_for('main.admin_dashboard'))
    
    # Get file extension
    _, ext = os.path.splitext(file.filename)
    
    # Validate extension
    if ext[1:].lower() not in Config.ALLOWED_EXTENSIONS:
        flash('Invalid file extension', 'danger')
        return redirect(url_for('main.admin_dashboard'))
    
    # Preserve extension
    if not new_name.endswith(ext):
        new_name += ext
    
    # Sanitize filename
    safe_name = secure_filename(new_name)
    
    # Rename physical file
    old_path = Config.UPLOAD_FOLDER / file.visibility / file.filename
    new_path = Config.UPLOAD_FOLDER / file.visibility / safe_name
    
    if old_path.exists():
        try:
            old_path.rename(new_path)
            file.filename = safe_name
            db.session.commit()
            flash('File renamed successfully', 'success')
        except Exception as e:
            flash(f'Error renaming file: {str(e)}', 'danger')
    else:
        flash('Original file not found', 'danger')
    
    return redirect(url_for('main.admin_dashboard'))

@main_bp.route('/admin/change_visibility/<int:file_id>', methods=['POST'])
@login_required
def change_visibility(file_id):
    if not current_user.has_role('admin'):
        abort(403)
    
    file = File.query.get_or_404(file_id)
    new_visibility = request.form.get('visibility')
    
    if new_visibility not in ['public', 'protected', 'private']:
        flash('Invalid visibility setting', 'danger')
        return redirect(url_for('main.admin_dashboard'))
    
    # Jeśli zmieniamy widoczność, przenosimy plik między folderami
    if file.visibility != new_visibility:
        old_path = Config.UPLOAD_FOLDER / file.visibility / file.filename
        new_path = Config.UPLOAD_FOLDER / new_visibility / file.filename
        
        # Utwórz folder docelowy jeśli nie istnieje
        new_path.parent.mkdir(exist_ok=True, parents=True)
        
        if old_path.exists():
            old_path.rename(new_path)
        
        file.visibility = new_visibility
        db.session.commit()
        flash('File visibility changed successfully', 'success')
    else:
        flash('Visibility unchanged', 'info')
    
    return redirect(url_for('main.admin_dashboard'))
    
    
    
    
@main_bp.route('/admin/unban_ip/<int:ip_id>', methods=['POST'])
@login_required
def unban_ip(ip_id):
    if not current_user.has_role('admin'):
        abort(403)
    
    ip_to_unban = BannedIP.query.get_or_404(ip_id)
    db.session.delete(ip_to_unban)
    db.session.commit()
    flash('IP has been unbanned successfully', 'success')
    return redirect(url_for('main.admin_dashboard'))
@main_bp.route('/admin/change-password', methods=['POST'])
@login_required
def admin_change_password():
    if current_user.role < Config.USER_ROLES['admin']:
        abort(403)
        
    username = request.form.get('username')
    new_password = request.form.get('new_password')
    
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('main.admin_dashboard'))
    
    user.set_password(new_password)
    db.session.commit()
    flash('Password changed successfully', 'success')
    return redirect(url_for('main.admin_dashboard'))