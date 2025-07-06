from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
migrate = Migrate()

def create_app():
    app = Flask(__name__, static_folder='static', template_folder='templates')
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)

    login_manager.login_view = 'auth.login'

    # Register blueprints
    from app.auth import auth_bp
    from app.admin import admin_bp
    from app.questions import questions_bp
    from app.stats import stats_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(questions_bp, url_prefix='/questions')
    app.register_blueprint(stats_bp, url_prefix='/stats')

    @app.route('/')
    def index():
        return "<h1>Gabarite a Lei - Simulados Legislativos</h1><p><a href='/login'>Login</a> | <a href='/signup'>Cadastrar</a></p>"

    return app
