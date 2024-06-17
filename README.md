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

## Notes :

Quelques points à améliorer :

* Gestion des erreurs : Actuellement, votre code ne semble pas gérer les erreurs qui pourraient survenir lors de l’exécution de certaines opérations, comme l’ajout d’un nouvel utilisateur à la base de données. Vous pourriez envisager d’ajouter une gestion des erreurs pour améliorer la robustesse de votre application.
* Logs : Bien que vous ayez configuré un logger, il pourrait être utile d’ajouter plus de logs à travers votre application pour faciliter le débogage et la surveillance de votre application.
* Sécurité : Assurez-vous que votre application suit les meilleures pratiques de sécurité. Par exemple, vous pourriez envisager d’utiliser flask_wtf pour les formulaires afin de vous protéger contre les attaques CSRF.
* Configuration : Il pourrait être utile de séparer votre configuration dans un fichier ou un objet de configuration distinct, plutôt que de l’avoir directement dans votre code. Cela rendrait votre application plus flexible et plus facile à configurer dans différents environnements.
