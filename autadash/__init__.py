# =================================== Init Dependencies ===================================
from flask import Flask, render_template, request, redirect
from itsdangerous import URLSafeTimedSerializer
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager
from flask_babel import Babel, _
from config import Config
import logging

# =================================== Create globals variable ===================================
mail = Mail()
db = SQLAlchemy()
login_manager = LoginManager()
babel = Babel()
app = Flask(__name__,
            static_url_path = '',
            static_folder = 'assets',
            template_folder = 'templates')

# =================================== Supported Languages ===================================
SUPPORTED_LANGUAGES = {
    'en': 'English',
    'fr': 'Français',
}

# =================================== Init Flask app ===================================
def init() -> Flask:
    # Project settings
    app.config.from_object(Config)

    # Init logging
    logging.basicConfig(level = logging.INFO,
                        format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        handlers = [logging.FileHandler('autadash.log'),
                                    logging.StreamHandler()])

    logger = logging.getLogger(__name__)
    logger.info('Application started')

    # Init flask_mail
    mail.init_app(app)

    # Init flask_login
    login_manager.init_app(app)

    # Init flask_babel
    babel.init_app(app, locale_selector=get_locale)

    # Init SQLAlchemy
    db.init_app(app)

    # To initialise tables
    with app.app_context():
        db.create_all()

    # Publish the APP SECRET KEY
    # log('INFO', f'APP SECRET KEY SET TO {app.config['SECRET_KEY']}')
    print(f'APP SECRET KEY SET TO {app.config['SECRET_KEY']}')
    
    # Add get_locale to the context
    @app.context_processor
    def inject_get_locale():
        return dict(get_locale=get_locale)

    # =================================== Routes ===================================
    @app.route('/')
    def index():
        return render_template('index.html', SUPPORTED_LANGUAGES=SUPPORTED_LANGUAGES)

    @app.route('/test')
    def test():
        return render_template('test.html')

    @app.route('/set_language', methods=['POST'])
    def set_language():
        language = request.form.get('language')
        response = redirect(request.referrer)
        response.set_cookie('lang', language)
        return response

    # Import and egistrer blueprints
    from .auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    return app

# =================================== Utils ===================================
def get_locale():
    return request.cookies.get('lang', request.accept_languages.best_match(SUPPORTED_LANGUAGES.keys()))

def send_email(to, subject, template) -> None:
    msg = Message(
        subject,
        recipients=[to],
        html=template,
    )
    mail.send(msg)
    # log('INFO', f'Email sent to {to}')

def generate_confirmation_token(email) -> str:
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token: str, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email
