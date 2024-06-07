from flask import Flask, render_template, request, redirect, url_for
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager
from flask_babel import Babel, _
from config import Config
import logging
import random
import string

# =================================== Create globals variable ===================================
mail = Mail()
db = SQLAlchemy()
login_manager = LoginManager()
babel = Babel()
app = Flask(__name__,
            static_url_path='',
            static_folder='assets',
            template_folder='templates')

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
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        handlers=[logging.FileHandler('autadash.log'),
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
    from .models import User

    # To initialise tables
    with app.app_context():
        db.create_all()

    # Publish the APP SECRET KEY
    print(f'APP SECRET KEY SET TO {app.config["SECRET_KEY"]}')

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

    @app.errorhandler(401)
    def unauthorized_redirect(e):
        return redirect(url_for('index'))

    @app.errorhandler(404)
    def not_found(e):
        return render_template('error/404.html')

    # Import and register blueprints
    from .auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    return app

# =================================== Utils ===================================
def get_locale():
    return request.cookies.get('lang', request.accept_languages.best_match(SUPPORTED_LANGUAGES.keys()))


def generate_verification_code(size: int = 6) -> str:
    CHARS = string.ascii_letters + string.digits
    return ''.join(random.choice(CHARS) for _ in range(size))


def send_verification_email(user):
    # Generate and send verification code if email is confirmed
    verification_code = generate_verification_code()
    user.verification_code = verification_code
    db.session.commit()
    
    verification_code = generate_verification_code()
    user.verification_code = verification_code
    user.verification_code_expiry = datetime.now() + timedelta(minutes=10)  # Code valid for 10 minutes
    db.session.commit()
    subject = "Votre code de vérification"
    html = render_template('email/verification_code.html',
                           verification_code=verification_code)
    send_email(user.email, subject, html)


def get_device_info():
    user_agent = request.headers.get('User-Agent')
    ip_address = request.remote_addr
    accept_headers = request.headers.get('Accept')
    platform = request.user_agent.platform
    browser = request.user_agent.browser
    language = request.headers.get('Accept-Language')

    device_info = {
        'user_agent': user_agent,
        'ip_address': ip_address,
        'accept_headers': accept_headers,
        'platform': platform,
        'browser': browser,
        'language': language
    }

    print('Device infos :', *device_info.items(), sep='\n', end='\n\n')
    return device_info


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
