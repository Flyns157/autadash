"""
Manages authentication.
"""

from flask import (
    Blueprint,
    render_template,
    request,
    url_for,
    redirect,
    flash
)
bp = Blueprint("auth", __name__, url_prefix="/auth")

from flask_login import (
    login_user,
    login_required,
    logout_user,
    current_user)
from . import (
    db, 
    send_email, 
    login_manager,
    generate_confirmation_token,
    confirm_token
)
from autadash.models import User
import debug_sys
import re

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Vérifier le format de l'email
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Format d\'email invalide')
            return redirect(url_for('auth.signup'))

        # Vérifier si l'email est jetable
        if email.split('@')[1] in ['jetable.com', 'yopmail.com']:
            flash('Veuillez utiliser une adresse email non jetable')
            return redirect(url_for('auth.signup'))
        
        # Vérifier si l'email existe déjà
        user = User.query.filter_by(email=email).first()
        if user:
            flash('L\'email est déjà utilisé')
            return redirect(url_for('auth.signup'))

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Le nom d\'utilisateur existe déjà')
            return redirect(url_for('auth.signup'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Envoyer un email de confirmation
        token = generate_confirmation_token(new_user.email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('email/activate.html', confirm_url=confirm_url)
        send_email(new_user.email, 'Veuillez confirmer votre email', html)

        return redirect(url_for('auth.login'))
    return render_template('auth/signup.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email')
        password = request.form.get('password')

        user = User.query.filter((User.email == username_or_email) | (User.username == username_or_email)).first()
        if not user or not user.check_password(password):
            debug_sys.log(['INFO', 'DINIED'],f'User : {user} >> demande de connexion (with username_or_email={username_or_email}; password={password}; refusé)')
            flash('Veuillez vérifier vos identifiants')
            return redirect(url_for('auth.login'))

        login_user(user)
        debug_sys.log('INFO',f'User : {user} >> demande de connexion (accepté)')
        return redirect(url_for('auth.profile'))

    return render_template('auth/login.html')

@bp.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        debug_sys.log(['INFO', 'DENIED'],f'Email : {email} >> demande de confirmation (invalide ou expiré)')
        flash('Le lien de confirmation est invalide ou a expiré.', 'danger')
    user = User.query.filter_by(email=email).first_or_404()
    if user.email_confirmed:
        debug_sys.log('INFO',f'Email : {email} >> demande de confirmation (déjà confirmé)')
        flash('Compte déjà confirmé. Veuillez vous connecter.', 'success')
    else:
        user.email_confirmed = True
        db.session.add(user)
        db.session.commit()
        debug_sys.log(['INFO', 'ACCEPTED'],f'Email : {email} >> demande de confirmation (accepté)')
        flash('Vous avez confirmé votre compte. Merci!', 'success')
    return redirect(url_for('auth.login'))

@bp.route('/send-confirmation-email', methods=['POST'])
@login_required
def send_confirmation_email():
    user = current_user
    if not user.email_confirmed:
        token = generate_confirmation_token(user.email)
        confirm_url = url_for('auth.confirm_email', token=token, _external=True)
        html = render_template('email/activate.html', confirm_url=confirm_url)
        send_email(user.email, 'Veuillez confirmer votre email', html)
        flash('Un email de confirmation a été envoyé.', 'success')
    else:
        flash('Votre email est déjà confirmé.', 'info')
    return redirect(url_for('auth.profile'))

@bp.route('/profile')
@login_required
def profile():
    return render_template('auth/profile.html', name=current_user.username, email=current_user.email, email_confirmed=current_user.email_confirmed)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))