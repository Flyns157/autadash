from flask import Flask, render_template, request, flash, url_for, redirect, render_template_string, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_babel import Babel, _
from .config import Config
import logging
import random
import string
import json
import re

__version__ = '0.2.3'
__authors__ = ['Cuisset Mattéo']

class Server(Flask):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config.from_object(Config)
        self.languages = kwargs.get('languages', ['en'])
        self.babel = Babel()
        self.login_manager = LoginManager()
        self.mail = Mail()
        self.db = SQLAlchemy()
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                            handlers=[logging.FileHandler('autadash.log'), logging.StreamHandler()])
        self.logger = logging.getLogger(__name__)
        
        self.User = self.create_user_model()
        
        @self.login_manager.user_loader
        def load_user(user_id): return self.User.query.get(int(user_id))
        
        self.add_auth_routes()

    def run(self, host: str = None, port: int = None, debug: bool = None, load_dotenv: bool = True, **options) -> None:
        # Init flask_mail
        self.mail.init_app(self)

        # Init flask_login
        self.login_manager.init_app(self)

        # Init flask_babel
        self.babel.init_app(self, locale_selector=lambda : request.accept_languages.best_match(self.languages))

        # Init SQLAlchemy
        self.db.init_app(self)
        with self.app_context(): self.db.create_all()
        # TODO : prendre en compte les changement de paramètres et modifier la BD si nécessaire
        return super().run(host, port, debug, load_dotenv, **options)

    def create_user_model(self):
        global User
        class User(UserMixin, self.db.Model):
            """
            Data model for users.
            """
            id = self.db.Column(self.db.Integer, primary_key=True)
            username = self.db.Column(self.db.String(100), unique=True)
            email = self.db.Column(self.db.String(100), unique=True)
            password = self.db.Column(self.db.String(100))
            known_devices = self.db.Column(self.db.String, default='[]')  # Storing known devices as JSON string
            if self.config['V2F'] > 0:
                email_confirmed = self.db.Column(self.db.Boolean, default=False)
                verification_code = self.db.Column(self.db.String(6))
                verification_code_expiry = self.db.Column(self.db.DateTime)  # Column for verification code expiry
                v2f = self.db.Column(self.db.Boolean, default=False)

            def set_password(self, password):
                self.password = generate_password_hash(password)

            def check_password(self, password):
                return check_password_hash(self.password, password)

            def add_known_device(self, device_info):
                devices = json.loads(self.known_devices)
                devices.append(device_info)
                self.known_devices = json.dumps(devices)

            def is_device_known(self, device_info):
                devices = json.loads(self.known_devices)
                return device_info in devices
            
            def verification_code_alive(self)-> bool:
                if self.verification_code_expiry is None:
                    return False
                return self.verification_code_expiry > datetime.now()
        
        return User

    def add_auth_routes(self):
        if self.config['INDEPENDENT_REGISTER']:
            @self.route('/register', methods=['GET', 'POST'])
            def register():
                if request.method == 'POST':
                    username = request.form.get('username')
                    email = request.form.get('email')
                    password = request.form.get('password')

                    self.logger.info(f'User register attempt: username={username}, email={email}')

                    # Vérifier le format de l'email
                    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                        flash(_('Format d\'email invalide'))
                        self.logger.warning(f'Invalid email format: {email}')
                        return redirect(url_for('register'))

                    # Vérifier si l'email est jetable
                    if email.split('@')[1] in ['jetable.com', 'yopmail.com']:
                        flash(_('Veuillez utiliser une adresse email non jetable'))
                        self.logger.warning(f'Disposable email used: {email} by {username}')
                        return redirect(url_for('register'))

                    # Vérifier si l'email existe déjà
                    user = User.query.filter_by(email=email).first()
                    if user:
                        flash(_('L\'email est déjà utilisé'))
                        self.logger.warning(f'Email already in use: {email} ({username} try but {user} exist with tis email)')
                        return redirect(url_for('register'))

                    user = User.query.filter_by(username=username).first()
                    if user:
                        flash(_('Le nom d\'utilisateur existe déjà'))
                        self.logger.warning(f'Username already exists: {username} {"(with " + email + ")" if email != user.email else ""}')
                        return redirect(url_for('register'))

                    new_user = User(username=username, email=email)
                    new_user.set_password(password)
                    self.db.session.add(new_user)
                    self.db.session.commit()

                    self.logger.info(f'New user created: {username}, {email}')

                    if self.config['V2F'] > 0:
                        # Envoyer un email de confirmation
                        token = self.generate_confirmation_token(new_user.email)
                        confirm_url = url_for('confirm_email', token=token, _external=True)
                        html = render_template('email/activate.html', confirm_url=confirm_url, SUPPORTED_LANGUAGES=self.languages)
                        self.send_email(new_user.email, 'Veuillez confirmer votre email', html)

                        self.logger.info(f'Confirmation email sent to: {email}')
                        
                        if self.config['V2F'] == 2:
                            return redirect(url_for('login'))

                        user = User.query.filter(User.email == email).first()
                        login_user(user)
                        self.logger.info(f'User logged in: {user.username}')
                        return redirect(url_for('/'))

                    login_user(user)
                    self.logger.info(f'User logged in: {user.username}')
                    return redirect(url_for('/'))
                return render_template('auth/register.html', SUPPORTED_LANGUAGES=self.languages)

        @self.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                username_or_email = request.form.get('username_or_email')
                password = request.form.get('password')

                self.logger.info(f'Login attempt: username_or_email={username_or_email}')

                user = User.query.filter((User.email == username_or_email) | (User.username == username_or_email)).first()
                if not user or not user.check_password(password):
                    self.logger.warning(f'Login failed for: {username_or_email}')
                    flash(_('Veuillez vérifier vos identifiants'))
                    return redirect(url_for('login'))

                if self.config['V2F'] == 2:
                    if not user.email_confirmed:
                        self.logger.warning(f'Email not confirmed for: {username_or_email}')
                        flash(_('Veuillez confirmer votre adresse email avant de vous connecter'))
                        return redirect(url_for('login'))
                    self.send_verification_email(user)
                    self.logger.info(f'Verification code sent to: {user.email}')

                    return redirect(url_for('verify', user_id=user.id))
                
                login_user(user)
                self.logger.info(f'User logged in: {user.username}')
                return redirect(url_for('/'))

            return render_template('auth/login.html', SUPPORTED_LANGUAGES=self.languages)

        if self.config['V2F'] > 0:
            @self.route('/verify/<int:user_id>', methods=['GET', 'POST'])
            def verify(user_id):
                user = User.query.get(user_id)
                if request.method == 'POST':
                    verification_code = request.form.get('verification_code')
                
                    print(user.verification_code, verification_code)
                    if user.verification_code != verification_code:
                        self.logger.warning(f'Invalid verification code for: {user.email}')
                        flash(_('Code de vérification incorrect'))
                        return redirect(url_for('verify', user_id=user_id))

                    print(user.verification_code_expiry , datetime.now())
                    if not user.verification_code_alive():
                        self.logger.warning(f'Expired verification code for: {user.email}')
                        flash(_('Code de vérification expiré'))
                        return redirect(url_for('login'))

                    # Clear the verification code and expiry after successful verification
                    user.verification_code = None
                    user.verification_code_expiry = None
                    self.db.session.commit()

                    login_user(user)
                    self.logger.info(f'User logged in: {user.username}')
                    return redirect(url_for('/'))

                return render_template('auth/verify.html', user_id=user_id, SUPPORTED_LANGUAGES=self.languages)

            @self.route('/reset_password_request', methods=['GET', 'POST'])
            def reset_password_request():
                if request.method == 'POST':
                    email = request.form.get('email')
                    user = User.query.filter_by(email=email).first()
                    if user:
                        token = self.generate_confirmation_token(user.email)
                        reset_url = url_for('reset_password', token=token, _external=True)
                        html = render_template('email/reset_password.html', reset_url=reset_url)
                        self.send_email(user.email, 'Réinitialisation du mot de passe', html)
                        flash(_('Un email avec les instructions pour réinitialiser votre mot de passe a été envoyé.'), 'info')
                    else:
                        flash(_('Cet email n\'est pas enregistré.'), 'warning')
                    return redirect(url_for('login'))
                return render_template('auth/reset_password_request.html', SUPPORTED_LANGUAGES=self.languages)

            @self.route('/reset_password/<token>', methods=['GET', 'POST'])
            def reset_password(token):
                
                try:
                    email = self.confirm_token(token)
                except:
                    flash(_('Le lien de réinitialisation est invalide ou a expiré.'), 'danger')
                    return redirect(url_for('login'))
                
                if request.method == 'POST':
                    password = request.form.get('password')
                    user = User.query.filter_by(email=email).first()
                    if user:
                        user.set_password(password)
                        self.db.session.commit()
                        flash(_('Votre mot de passe a été mis à jour.'), 'success')
                        return redirect(url_for('login'))
                    else:
                        flash(_('Utilisateur non trouvé.'), 'danger')
                        return redirect(url_for('reset_password_request'))
                
                return render_template('auth/reset_password.html', token=token, SUPPORTED_LANGUAGES=self.languages)

            @self.route('/confirm/<token>')
            def confirm_email(token):
                try:
                    email = self.confirm_token(token)
                except:
                    self.logger.error(f'Invalid or expired confirmation token used: {token}')
                    flash(_('Le lien de confirmation est invalide ou a expiré.'), 'danger')
                    return redirect(url_for('login'))

                user = User.query.filter_by(email=email).first_or_404()
                if user.email_confirmed:
                    self.logger.info(f'Email already confirmed: {email}')
                    flash(_('Compte déjà confirmé. Veuillez vous connecter.'), 'success')
                else:
                    user.email_confirmed = True
                    self.db.session.add(user)
                    self.db.session.commit()
                    self.logger.info(f'Email confirmed: {email}')
                    flash(_('Vous avez confirmé votre compte. Merci!'), 'success')
                return redirect(url_for('login'))

            @self.route('/send-confirmation-email', methods=['POST'])
            @login_required
            def send_confirmation_email():
                user = current_user
                if not user.email_confirmed:
                    token = self.generate_confirmation_token(user.email)
                    confirm_url = url_for('confirm_email', token=token, _external=True)
                    html = render_template('email/activate.html', confirm_url=confirm_url, SUPPORTED_LANGUAGES=self.languages)
                    self.send_email(user.email, 'Veuillez confirmer votre email', html)
                    self.logger.info(f'Confirmation email resent to: {user.email}')
                    flash(_('Un email de confirmation a été envoyé.'), 'success')
                else:
                    self.logger.info(f'Confirmation email not sent, already confirmed: {user.email}')
                    flash(_('Votre email est déjà confirmé.'), 'info')
                return redirect(url_for('/'))

        @self.route('/logout')
        @login_required
        def logout():
            self.logger.info(f'User logged out: {current_user.username}')
            logout_user()
            return redirect(url_for('index'))


# =================================== Utils ===================================
    def send_verification_email(self, user):
        # Generate and send verification code if email is confirmed
        verification_code = Utils.generate_verification_code()
        user.verification_code = verification_code
        self.db.session.commit()
        
        verification_code = Utils.generate_verification_code()
        user.verification_code = verification_code
        user.verification_code_expiry = datetime.now() + timedelta(minutes=10)  # Code valid for 10 minutes
        self.db.session.commit()
        subject = "Votre code de vérification"
        html = render_template('email/verification_code.html',
                            verification_code=verification_code)
        self.send_email(user.email, subject, html)


    def send_email(self, to, subject, template) -> None:
        msg = Message(
            subject,
            recipients=[to],
            html=template,
        )
        self.mail.send(msg)
        # log('INFO', f'Email sent to {to}')


    def generate_confirmation_token(self, email) -> str:
        serializer = URLSafeTimedSerializer(self.config['SECRET_KEY'])
        return serializer.dumps(email, salt=self.config['SECURITY_PASSWORD_SALT'])


    def confirm_token(self, token: str, expiration=3600):
        serializer = URLSafeTimedSerializer(self.config['SECRET_KEY'])
        try:
            email = serializer.loads(
                token,
                salt=self.config['SECURITY_PASSWORD_SALT'],
                max_age=expiration
            )
        except:
            return False
        return email

class Utils:
    def generate_verification_code(size: int = 6) -> str:
        CHARS = string.ascii_letters + string.digits
        return ''.join(random.choice(CHARS) for _ in range(size))

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