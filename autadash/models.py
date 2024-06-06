"""
This module defines the data models for the application.
It includes the User model.
"""
import json
from . import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    """
    Data model for users.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    email_confirmed = db.Column(db.Boolean, default=False)
    password = db.Column(db.String(100))
    known_devices = db.Column(db.String, default='[]')  # Storing known devices as JSON string

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