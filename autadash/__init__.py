# =================================== Init Dependencies ===================================
from itsdangerous import URLSafeTimedSerializer
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager
from config import Config
import debug_sys

# =================================== Create globals variable ===================================
mail = Mail()
db = SQLAlchemy()
login_manager = LoginManager()
app = Flask(__name__, static_url_path='',
            static_folder='assets',
            template_folder='templates')

# =================================== Init Flask app ===================================
def init() -> Flask:
    # Project settings
    app.config.from_object(Config)

    # Init flask_mail
    mail.init_app(app)

    # Init flask_login
    login_manager.init_app(app)

    # Init SQLAlchemy
    db.init_app(app)

    # To initialise tables
    with app.app_context():
        db.create_all()

    # Publish the APP SECRET KEY
    debug_sys.log('INFO', f'APP SECRET KEY SET TO {app.config['SECRET_KEY']}')
    print(f'APP SECRET KEY SET TO {app.config['SECRET_KEY']}')

    # =================================== Routes ===================================
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/test')
    def test():
        return render_template('test.html')

    # Regegister blueprints
    from . import auth 
    app.register_blueprint(auth.bp)

    return app

# =================================== Utils ===================================
def send_email(to, subject, template) -> None:
    msg = Message(
        subject,
        recipients=[to],
        html=template,
    )
    mail.send(msg)
    debug_sys.log('INFO', f'Email sent to {to}')

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
