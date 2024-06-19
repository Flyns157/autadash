from dotenv import load_dotenv
import secrets
import random
import string
import os

# récupération des variables d'environnement
load_dotenv()

def generate_password(size: int = 15) -> str:
    CHARS = string.ascii_letters + string.digits
    return ''.join(random.choice(CHARS) for _ in range(size))

class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI') or 'sqlite:///db.sqlite'
    SECRET_KEY = os.getenv('SECRET_KEY') if os.getenv('SECRET_KEY') and os.getenv('SECRET_KEY').lower() != 'auto' else secrets.token_urlsafe()
    SECURITY_PASSWORD_SALT = os.getenv('SECURITY_PASSWORD_SALT') if os.getenv('SECURITY_PASSWORD_SALT') and os.getenv('SECURITY_PASSWORD_SALT').lower() != 'auto' else secrets.token_hex(16)
    MAIL_DEBUG = os.getenv('MAIL_DEBUG').lower() == 'true'
    MAIL_SERVER = os.getenv('MAIL_SERVER')
    MAIL_PORT = os.getenv('MAIL_PORT')
    MAIL_USE_TLS = os.getenv('MAIL_USE').upper() == "TLS"
    MAIL_USE_SSL = os.getenv('MAIL_USE').upper() == "SSL"
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = ('Autadash', os.getenv('MAIL_DEFAULT_SENDER'))
    DEFAULT_LANGUAGE = os.getenv('DEFAULT_LANGUAGE') or 'en'
    BABEL_DEFAULT_LOCALE = str(os.getenv('INDEPENDENT_REGISTER')) or 'translations'
    BABEL_DEFAULT_TIMEZONE = os.getenv('DEFAULT_TIMEZONE') or 'UTC'
    ADMIN_PASSWORD = generate_password() if not os.getenv('ADMIN_PASSWORD') or os.getenv('ADMIN_PASSWORD').upper() == 'AUTO' else os.getenv('ADMIN_PASSWORD')
    MAIL_SERVICES=str(os.getenv('MAIL_SERVICES') or 'False').lower() == 'true'
    V2F=int(os.getenv('V2F') or '0')
    INDEPENDENT_REGISTER=str(os.getenv('INDEPENDENT_REGISTER') or 'True').lower() == 'true'