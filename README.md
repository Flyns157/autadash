# Plan de restructuration du projet Autadash:

## Structure de fichiers prévue :

```
│   .env
│   .env.example
│   .gitignore
│   LICENSE
│   README.md
│   requirement.txt
│
└───autadash
    │   __init__.py
    │   __main__.py
    │   auth.py
    │   config.py
    │
    └───assets
        ├───css
        ├───img
        │       logo.svg
        │       logo_white.svg
        │
        ├───js
        └───templates
            ├───auth
            │       login.partial.html
            │       verify.partial.html
            │       register.partial.html
            │       reset_password.partial.html
            │
            └───mail
                    activate.html
                    new_device.html
                    reset_password.html
                    verification_code.html

+ translations
```

## Liste des principales fonctionalitées :

* authentification
* multilangue
* mailing
