# Autadash

## Overview

Autadash is a Flask-based web application designed to provide user authentication and email verification functionalities. It supports features such as user registration, login, password reset, email confirmation, and two-factor authentication (2FA).

## Project Structure

```plaintext
│ __init__.py
│ __main__.py
| .env
| .env.example
| .gitignore
│ config.py
| Dockerfile
| LICENCE
| README.md
| requirements.txt
│
├───assets
│   ├───css
│   │      style.css
│   │
│   ├───img
│   └───js
└───templates
    │    layout.html
    │
    ├───auth
    │      login.html
    │      register.html
    │      reset_password.html
    │      reset_password_request.html
    │      verify.html
    │
    └───email
            activate.html
            new_device.html
            reset_password.html
            verification_code.html

+ translations
```

## Getting Started

### Prerequisites

- Python 3.x
- Flask
- Flask-Login
- Flask-Mail
- Flask-Babel
- Flask-WTF
- Flask-SQLAlchemy
- dotenv
- Werkzeug
- itsdangerous

### Installation

1. Clone the repository:

   ```bash
   cd path/to/your/project
   git clone https://github.com/yourusername/autadash.git
   ```
2. (Optional) Create a virtual environment and activate it:

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```
3. Install the required packages:

   ```bash
   pip install -r requirements.txt
   ```
4. Create a `.env` file by copying `.env.example` and filling in the required environment variables:

   ```bash
   cp .env.example .env
   ```

### Running your Application

1. Start the Flask application:

   ```bash
   python -m flask run
   ```
2. Open your browser and navigate to `http://127.0.0.1:5000`.

### Docker

You can also run the application using Docker, for example:

1. Build the Docker image (see the [Docker example](Dockerfile.example)):

   ```bash
   docker build -t autadash_example .
   ```
2. Run the Docker container:

   ```bash
   docker run --rm -it -v $PWD/:/autadash -p 8080:8080 autadash_example
   ```

## Configuration

Configuration settings are stored in the `config.py` file and can be overridden using environment variables defined in the `.env` file. Key configurations include:

- `SQLALCHEMY_DATABASE_URI`: Database connection string
- `SECRET_KEY`: Secret key for session management and security
- `SECURITY_PASSWORD_SALT`: Salt for password security
- `MAIL_*`: Email server configurations
- `DEFAULT_LANGUAGE`: Default language for the application
- `BABEL_DEFAULT_LOCALE`: Default locale for Babel
- `BABEL_DEFAULT_TIMEZONE`: Default timezone
- `ADMIN_PASSWORD`: Admin password
- `V2F`: Two-factor authentication setting
- `INDEPENDENT_REGISTER`: Flag for independent registration

## Project Files

### `./__init__.py`

This file initializes the Flask application, sets up configurations, and defines routes for authentication, user management, and email verification.

### `./config.py`

Contains the configuration settings for the Flask application, which are loaded from environment variables.

### `./__main__.py`

Contains the entry point to run the Flask application.

### Templates

- `layout.html`: Base template
- `auth/`: Templates for authentication (login, register, reset password, verify)
- `email/`: Templates for email content (activation, new device, reset password, verification code)

### Assets

Contains static files such as CSS, JavaScript, and images.

## Contributing

1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-branch
   ```
3. Make your changes and commit them:
   ```bash
   git commit -m 'Add some feature'
   ```
4. Push to the branch:
   ```bash
   git push origin feature-branch
   ```
5. Open a pull request.

## Notes :

**Some points for improvement:**

* Security: Make sure your application follows security best practices. For example, you might consider using flask_wtf for forms to protect against CSRF attacks.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Authors

- Cuisset Mattéo

## Version

Current version: 0.2.4
