# =================================== Init Dependencies ===================================
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import re
from random import random, choice
import time
from datetime import datetime
import string
# personnal modules
import debug_sys

# =================================== Utils ===================================
def generate_key(size: int = 50) -> str:
    """
    Generate a random key
    """
    return ''.join(str(datetime.now()).split()) + ''.join(choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(size))

# =================================== Init Flask app ===================================
app = Flask(__name__, static_url_path='',
            static_folder='static',
            template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SECRET_KEY'] = 'votre_secret_key'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# =================================== Init Flask DB ===================================
# Après la définition de vos modèles
with app.app_context():
    db.create_all()

# =================================== Init login manager | Flas_login ===================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# =================================== Init Auth routes ===================================
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Vérifier le format de l'email
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Format d\'email invalide')
            return redirect(url_for('signup'))

        # Vérifier si l'email est jetable
        if email.split('@')[1] in ['jetable.com', 'yopmail.com']:
            flash('Veuillez utiliser une adresse email non jetable')
            return redirect(url_for('signup'))
        
        # Vérifier si l'email existe déjà
        user = User.query.filter_by(email=email).first()
        if user:
            flash('L\'email est déjà utilisé')
            return redirect(url_for('signup'))

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Le nom d\'utilisateur existe déjà')
            return redirect(url_for('signup'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template('auth/signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email')
        password = request.form.get('password')

        user = User.query.filter((User.email == username_or_email) | (User.username == username_or_email)).first()
        if not user or not user.check_password(password):
            flash('Veuillez vérifier vos identifiants')
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('profile'))

    return render_template('auth/login.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('auth/profile.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# =================================== Init routes ===================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/test')
def test():
    return render_template('test.html')

# =================================== Run specifications ===================================
if __name__ == '__main__':
    app.run(debug=True)
