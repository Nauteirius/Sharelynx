from datetime import datetime
from flask import Flask, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_migrate import Migrate  
from user_agents  import parse  
from werkzeug.middleware.proxy_fix import ProxyFix


db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    
    app.wsgi_app = ProxyFix( # for properly IP detections while using tunnel
        app.wsgi_app,
        x_for=1,   # Number of proxies to trust
        x_proto=1,
        x_host=1,
        x_prefix=1
    )
    
    # initialise extensions
    db.init_app(app)
    migrate.init_app(app, db) 
    login_manager.init_app(app)

    
    # Import models after initalising db
    from app.models import User, File, AnonymousUser, BannedIP, UserActivity
    login_manager.anonymous_user = AnonymousUser
    
    # Register blueprints
    from app.routes import main_bp
    app.register_blueprint(main_bp)
    
    # Make table in app context
    with app.app_context():
        db.create_all()
        
        
    
    # Ninja filters Jinja2
    @app.template_filter('datetimeformat')
    def datetimeformat_filter(value, format='%Y-%m-%d %H:%M'):
        if isinstance(value, datetime):
            return value.strftime(format)
        return value
        
        
        # Middleware
    @app.before_request
    def track_activity_and_block():
        #ip = request.remote_addr
        ip = request.headers.get('CF-Connecting-IP') or \
          request.headers.get('X-Forwarded-For', request.remote_addr)
        
        # check if IP is banned
        if BannedIP.query.filter_by(ip=ip).first():
            abort(403)
        
        # Log activity
        #user_agent = useragents.parse(request.headers.get('User-Agent', ''))
        user_agent = parse(request.headers.get('User-Agent', ''))  
        
        activity = UserActivity(
            user_id=current_user.id if current_user.is_authenticated else None,
            ip=ip,
            user_agent=str(user_agent),
            path=request.path,
            method=request.method
        )
        db.session.add(activity)
        db.session.commit()
    return app
    
    