# Import required Flask extensions and modules
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask import current_app
from flask import send_from_directory
from flask_login import LoginManager
from flask_dance.contrib.google import make_google_blueprint, google
from config import Config
import os

# Initialize Flask extensions
db = SQLAlchemy()
login_manager = LoginManager()


def create_app():
    # Create Flask application instance with static folder configuration
    app = Flask(__name__, static_folder='static')
    app.config.from_object(Config)
    # Configure application settings
    
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path,'static', 'uploads')
    
    
   
    # Initialize Flask extensions with the app
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    
    
    @app.route('/uploads/<filename>')
    def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    # Import User model for login manager
    from .model import User
    
    # User loader callback for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Google OAuth Blueprint
    google_bp = make_google_blueprint(
        client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
        client_secret=app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
        scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ],
        #redirect_to="auth.google_authorized"  # This is the route to handle Google OAuth callback
    )
    
    # Register Google OAuth blueprint
    app.register_blueprint(google_bp, url_prefix="/google")
    
    # Import and register other blueprints
    from .routes.auth import auth as auth_blueprint
    from .routes.blog import blog as blog_blueprint
    from .routes.main import main

    # Register blueprints with the application
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(blog_blueprint)
    app.register_blueprint(main)

    return app


    
