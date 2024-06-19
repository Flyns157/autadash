# Autadash

## Overview

Autadash is a Flask-based web application designed to provide user authentication and email verification functionalities. It supports features such as user registration, login, password reset, email confirmation, and two-factor authentication (2FA).

## Project Structure

```plaintext
| .env
| .env.example
| .gitignore
| Dockerfile
| LICENCE
| README.md
| requirements.txt
|
└───autadash
    │ config.py
    │ __init__.py
    │ __main__.py
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
- Flask-SQLAlchemy
- dotenv
- Werkzeug
- itsdangerous

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/autadash.git
   cd autadash
   ```

2. Create a virtual environment and activate it:
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

### Running the Application

1. Start the Flask application:
   ```bash
   python -m autadash
   ```

2. Open your browser and navigate to `http://127.0.0.1:5000`.

### Docker

You can also run the application using Docker:

1. Build the Docker image:
   ```bash
   docker build -t autadash .
   ```

2. Run the Docker container:
   ```bash
   docker run -d -p 5000:5000 --env-file .env autadash
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

### `autadash/__init__.py`

This file initializes the Flask application, sets up configurations, and defines routes for authentication, user management, and email verification.

### `autadash/config.py`

Contains the configuration settings for the Flask application, which are loaded from environment variables.

### `autadash/__main__.py`

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

* Error handling: Currently, your code doesn't seem to handle errors that might occur when executing certain operations, such as adding a new user to the database. You might consider adding error handling to improve the robustness of your application.
* Logs: Although you may have set up a logger, it might be useful to add more logs throughout your application to facilitate debugging and monitoring.
* Security: Make sure your application follows security best practices. For example, you might consider using flask_wtf for forms to protect against CSRF attacks.
* Configuration: It might be useful to separate your configuration into a separate configuration file or object, rather than having it directly in your code. This would make your application more flexible and easier to configure in different environments.

**Quelques points à améliorer :**

* Gestion des erreurs : Actuellement, votre code ne semble pas gérer les erreurs qui pourraient survenir lors de l’exécution de certaines opérations, comme l’ajout d’un nouvel utilisateur à la base de données. Vous pourriez envisager d’ajouter une gestion des erreurs pour améliorer la robustesse de votre application.
* Logs : Bien que vous ayez configuré un logger, il pourrait être utile d’ajouter plus de logs à travers votre application pour faciliter le débogage et la surveillance de votre application.
* Sécurité : Assurez-vous que votre application suit les meilleures pratiques de sécurité. Par exemple, vous pourriez envisager d’utiliser flask_wtf pour les formulaires afin de vous protéger contre les attaques CSRF.
* Configuration : Il pourrait être utile de séparer votre configuration dans un fichier ou un objet de configuration distinct, plutôt que de l’avoir directement dans votre code. Cela rendrait votre application plus flexible et plus facile à configurer dans différents environnements.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Authors

- Cuisset Mattéo

## Version

Current version: 0.2.4