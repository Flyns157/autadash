from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask, render_template, request, flash, url_for, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_babel import Babel
import logging
import random
import string
import json
import re

class Server(Flask):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.languages = kwargs.get('languages', ['en'])
        self.babel = Babel()
        self.login_manager = LoginManager()
        self.mail = Mail()
        self.db = SQLAlchemy()
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                            handlers=[logging.FileHandler('autadash.log'), logging.StreamHandler()])
        self.logger = logging.getLogger(__name__)
        
        self.create_user_model()

    def run(self, host: str | None = None, port: int | None = None, debug: bool | None = None, load_dotenv: bool = True, **options) -> None:
        # Init flask_mail
        self.mail.init_app(self)

        # Init flask_login
        self.login_manager.init_app(self)

        # Init flask_babel
        self.babel.init_app(self, locale_selector=lambda : request.accept_languages.best_match(self.languages))

        # Init SQLAlchemy
        self.db.init_app(self)
        with self.app_context(): self.db.create_all()
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
            email_confirmed = self.db.Column(self.db.Boolean, default=False)
            password = self.db.Column(self.db.String(100))
            known_devices = self.db.Column(self.db.String, default='[]')  # Storing known devices as JSON string
            verification_code = self.db.Column(self.db.String(6))
            verification_code_expiry = self.db.Column(self.db.DateTime)  # Column for verification code expiry

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
        
        def add_auth_routes(self):

            @self.login_manager.user_loader
            def load_user(user_id):
                return User.query.get(int(user_id))

            @self.route('/signup', methods=['GET', 'POST'])
            def signup():
                if request.method == 'POST':
                    username = request.form.get('username')
                    email = request.form.get('email')
                    password = request.form.get('password')

                    self.logger.info(f'User signup attempt: username={username}, email={email}')

                    # Vérifier le format de l'email
                    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                        flash('Format d\'email invalide')
                        self.logger.warning(f'Invalid email format: {email}')
                        return redirect(url_for('auth.signup'))

                    # Vérifier si l'email est jetable
                    if email.split('@')[1] in ['jetable.com', 'yopmail.com']:
                        flash('Veuillez utiliser une adresse email non jetable')
                        self.logger.warning(f'Disposable email used: {email}')
                        return redirect(url_for('auth.signup'))

                    # Vérifier si l'email existe déjà
                    user = User.query.filter_by(email=email).first()
                    if user:
                        flash('L\'email est déjà utilisé')
                        self.logger.warning(f'Email already in use: {email}')
                        return redirect(url_for('auth.signup'))

                    user = User.query.filter_by(username=username).first()
                    if user:
                        flash('Le nom d\'utilisateur existe déjà')
                        self.logger.warning(f'Username already exists: {username}')
                        return redirect(url_for('auth.signup'))

                    new_user = User(username=username, email=email)
                    new_user.set_password(password)
                    db.session.add(new_user)
                    db.session.commit()

                    self.logger.info(f'New user created: {username}, {email}')

                    # Envoyer un email de confirmation
                    token = generate_confirmation_token(new_user.email)
                    confirm_url = url_for('auth.confirm_email', token=token, _external=True)
                    html = render_template('email/activate.html', confirm_url=confirm_url, SUPPORTED_LANGUAGES=SUPPORTED_LANGUAGES)
                    send_email(new_user.email, 'Veuillez confirmer votre email', html)

                    self.logger.info(f'Confirmation email sent to: {email}')

                    return redirect(url_for('auth.login'))
                return render_template('auth/signup.html', SUPPORTED_LANGUAGES=SUPPORTED_LANGUAGES)

            @self.route('/login', methods=['GET', 'POST'])
            def login():
                if request.method == 'POST':
                    username_or_email = request.form.get('username_or_email')
                    password = request.form.get('password')

                    self.logger.info(f'Login attempt: username_or_email={username_or_email}')

                    user = User.query.filter((User.email == username_or_email) | (User.username == username_or_email)).first()
                    if not user or not user.check_password(password):
                        self.logger.warning(f'Login failed for: {username_or_email}')
                        flash('Veuillez vérifier vos identifiants')
                        return redirect(url_for('auth.login'))

                    if not user.email_confirmed:
                        self.logger.warning(f'Email not confirmed for: {username_or_email}')
                        flash('Veuillez confirmer votre adresse email avant de vous connecter')
                        return redirect(url_for('auth.login'))
                    send_verification_email(user)
                    self.logger.info(f'Verification code sent to: {user.email}')

                    return redirect(url_for('auth.verify', user_id=user.id))

                return render_template('auth/login.html', SUPPORTED_LANGUAGES=SUPPORTED_LANGUAGES)

            @self.route('/verify/<int:user_id>', methods=['GET', 'POST'])
            def verify(user_id):
                user = User.query.get(user_id)
                if request.method == 'POST':
                    verification_code = request.form.get('verification_code')
                
                    print(user.verification_code, verification_code)
                    if user.verification_code != verification_code:
                        self.logger.warning(f'Invalid verification code for: {user.email}')
                        flash('Code de vérification incorrect')
                        return redirect(url_for('auth.verify', user_id=user_id))

                    print(user.verification_code_expiry , datetime.now())
                    if not user.verification_code_alive():
                        self.logger.warning(f'Expired verification code for: {user.email}')
                        flash('Code de vérification expiré')
                        return redirect(url_for('auth.login'))

                    # Clear the verification code and expiry after successful verification
                    user.verification_code = None
                    user.verification_code_expiry = None
                    self.db.session.commit()

                    login_user(user)
                    self.logger.info(f'User logged in: {user.username}')
                    return redirect(url_for('auth.profile'))

                return render_template('auth/verify.html', user_id=user_id, SUPPORTED_LANGUAGES=SUPPORTED_LANGUAGES)

            @self.route('/reset_password_request', methods=['GET', 'POST'])
            def reset_password_request():
                if request.method == 'POST':
                    email = request.form.get('email')
                    user = User.query.filter_by(email=email).first()
                    if user:
                        token = generate_confirmation_token(user.email)
                        reset_url = url_for('auth.reset_password', token=token, _external=True)
                        html = render_template('email/reset_password.html', reset_url=reset_url)
                        send_email(user.email, 'Réinitialisation du mot de passe', html)
                        flash('Un email avec les instructions pour réinitialiser votre mot de passe a été envoyé.', 'info')
                    else:
                        flash('Cet email n\'est pas enregistré.', 'warning')
                    return redirect(url_for('auth.login'))
                return render_template('auth/reset_password_request.html', SUPPORTED_LANGUAGES=SUPPORTED_LANGUAGES)

            @self.route('/reset_password/<token>', methods=['GET', 'POST'])
            def reset_password(token):
                try:
                    email = confirm_token(token)
                except:
                    flash('Le lien de réinitialisation est invalide ou a expiré.', 'danger')
                    return redirect(url_for('auth.login'))
                
                if request.method == 'POST':
                    password = request.form.get('password')
                    user = User.query.filter_by(email=email).first()
                    if user:
                        user.set_password(password)
                        self.db.session.commit()
                        flash('Votre mot de passe a été mis à jour.', 'success')
                        return redirect(url_for('auth.login'))
                    else:
                        flash('Utilisateur non trouvé.', 'danger')
                        return redirect(url_for('auth.reset_password_request'))
                
                return render_template('auth/reset_password.html', token=token, SUPPORTED_LANGUAGES=SUPPORTED_LANGUAGES)

            @self.route('/confirm/<token>')
            def confirm_email(token):
                try:
                    email = confirm_token(token)
                except:
                    self.logger.error(f'Invalid or expired confirmation token used: {token}')
                    flash('Le lien de confirmation est invalide ou a expiré.', 'danger')
                    return redirect(url_for('auth.login'))

                user = User.query.filter_by(email=email).first_or_404()
                if user.email_confirmed:
                    self.logger.info(f'Email already confirmed: {email}')
                    flash('Compte déjà confirmé. Veuillez vous connecter.', 'success')
                else:
                    user.email_confirmed = True
                    self.db.session.add(user)
                    self.db.session.commit()
                    self.logger.info(f'Email confirmed: {email}')
                    flash('Vous avez confirmé votre compte. Merci!', 'success')
                return redirect(url_for('auth.login'))

            @self.route('/send-confirmation-email', methods=['POST'])
            @login_required
            def send_confirmation_email():
                user = current_user
                if not user.email_confirmed:
                    token = generate_confirmation_token(user.email)
                    confirm_url = url_for('auth.confirm_email', token=token, _external=True)
                    html = render_template('email/activate.html', confirm_url=confirm_url, SUPPORTED_LANGUAGES=SUPPORTED_LANGUAGES)
                    send_email(user.email, 'Veuillez confirmer votre email', html)
                    self.logger.info(f'Confirmation email resent to: {user.email}')
                    flash('Un email de confirmation a été envoyé.', 'success')
                else:
                    self.logger.info(f'Confirmation email not sent, already confirmed: {user.email}')
                    flash('Votre email est déjà confirmé.', 'info')
                return redirect(url_for('auth.profile'))

            @self.route('/profile')
            @login_required
            def profile():
                return render_template('auth/profile.html', name=current_user.username, email=current_user.email, email_confirmed=current_user.email_confirmed, SUPPORTED_LANGUAGES=SUPPORTED_LANGUAGES)

            @self.route('/logout')
            @login_required
            def logout():
                self.logger.info(f'User logged out: {current_user.username}')
                logout_user()
                return redirect(url_for('index'))


# =================================== Utils ===================================
    def send_verification_email(self, user):
        # Generate and send verification code if email is confirmed
        verification_code = generate_verification_code()
        user.verification_code = verification_code
        self.db.session.commit()
        
        verification_code = generate_verification_code()
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