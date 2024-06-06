"""
Manages authentication.
"""

import logging
from flask import (
    Blueprint,
    render_template,
    request,
    url_for,
    redirect,
    flash
)
from flask_login import (
    login_user,
    login_required,
    logout_user,
    current_user
)
from . import (
    db,
    SUPPORTED_LANGUAGES,
    send_email,
    login_manager,
    generate_confirmation_token,
    confirm_token,
    get_device_info
)
from autadash.models import User
import re

logger = logging.getLogger(__name__)

bp = Blueprint("auth", __name__, url_prefix="/auth")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        logger.info(f'User signup attempt: username={username}, email={email}')

        # Vérifier le format de l'email
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Format d\'email invalide')
            logger.warning(f'Invalid email format: {email}')
            return redirect(url_for('auth.signup'))

        # Vérifier si l'email est jetable
        if email.split('@')[1] in ['jetable.com', 'yopmail.com']:
            flash('Veuillez utiliser une adresse email non jetable')
            logger.warning(f'Disposable email used: {email}')
            return redirect(url_for('auth.signup'))

        # Vérifier si l'email existe déjà
        user = User.query.filter_by(email=email).first()
        if user:
            flash('L\'email est déjà utilisé')
            logger.warning(f'Email already in use: {email}')
            return redirect(url_for('auth.signup'))

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Le nom d\'utilisateur existe déjà')
            logger.warning(f'Username already exists: {username}')
            return redirect(url_for('auth.signup'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        logger.info(f'New user created: {username}, {email}')

        # Envoyer un email de confirmation
        token = generate_confirmation_token(new_user.email)
        confirm_url = url_for('auth.confirm_email', token=token, _external=True)
        html = render_template('email/activate.html', confirm_url=confirm_url, SUPPORTED_LANGUAGES=SUPPORTED_LANGUAGES)
        send_email(new_user.email, 'Veuillez confirmer votre email', html)

        logger.info(f'Confirmation email sent to: {email}')

        return redirect(url_for('auth.login'))
    return render_template('auth/signup.html', SUPPORTED_LANGUAGES=SUPPORTED_LANGUAGES)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email')
        password = request.form.get('password')

        logger.info(f'Login attempt: username_or_email={username_or_email}')

        user = User.query.filter((User.email == username_or_email) | (User.username == username_or_email)).first()
        if not user or not user.check_password(password):
            logger.warning(f'Login failed for: {username_or_email}')
            flash('Veuillez vérifier vos identifiants')
            return redirect(url_for('auth.login'))

        device_info = get_device_info()
        if not user.is_device_known(device_info):
            # Envoyer un email si le dispositif est nouveau
            html = render_template('email/new_device.html', device_info=device_info)
            send_email(user.email, 'Nouvelle connexion détectée', html)
            user.add_known_device(device_info)
            db.session.commit()
            logger.info(f'New device detected and email sent to: {user.email}')

        login_user(user)
        logger.info(f'User logged in: {user.username}')
        return redirect(url_for('auth.profile'))

    return render_template('auth/login.html', SUPPORTED_LANGUAGES=SUPPORTED_LANGUAGES)

@bp.route('/reset_password_request', methods=['GET', 'POST'])
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

@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
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
            db.session.commit()
            flash('Votre mot de passe a été mis à jour.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Utilisateur non trouvé.', 'danger')
            return redirect(url_for('auth.reset_password_request'))
    
    return render_template('auth/reset_password.html', token=token, SUPPORTED_LANGUAGES=SUPPORTED_LANGUAGES)

@bp.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        logger.error(f'Invalid or expired confirmation token used: {token}')
        flash('Le lien de confirmation est invalide ou a expiré.', 'danger')
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(email=email).first_or_404()
    if user.email_confirmed:
        logger.info(f'Email already confirmed: {email}')
        flash('Compte déjà confirmé. Veuillez vous connecter.', 'success')
    else:
        user.email_confirmed = True
        db.session.add(user)
        db.session.commit()
        logger.info(f'Email confirmed: {email}')
        flash('Vous avez confirmé votre compte. Merci!', 'success')
    return redirect(url_for('auth.login'))

@bp.route('/send-confirmation-email', methods=['POST'])
@login_required
def send_confirmation_email():
    user = current_user
    if not user.email_confirmed:
        token = generate_confirmation_token(user.email)
        confirm_url = url_for('auth.confirm_email', token=token, _external=True)
        html = render_template('email/activate.html', confirm_url=confirm_url, SUPPORTED_LANGUAGES=SUPPORTED_LANGUAGES)
        send_email(user.email, 'Veuillez confirmer votre email', html)
        logger.info(f'Confirmation email resent to: {user.email}')
        flash('Un email de confirmation a été envoyé.', 'success')
    else:
        logger.info(f'Confirmation email not sent, already confirmed: {user.email}')
        flash('Votre email est déjà confirmé.', 'info')
    return redirect(url_for('auth.profile'))

@bp.route('/profile')
@login_required
def profile():
    return render_template('auth/profile.html', name=current_user.username, email=current_user.email, email_confirmed=current_user.email_confirmed, SUPPORTED_LANGUAGES=SUPPORTED_LANGUAGES)

@bp.route('/logout')
@login_required
def logout():
    logger.info(f'User logged out: {current_user.username}')
    logout_user()
    return redirect(url_for('index'))
