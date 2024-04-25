from dotenv import load_dotenv
import secrets
import os

# récupération des variables d'environnement
load_dotenv()

class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
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
