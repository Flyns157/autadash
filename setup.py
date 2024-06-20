from setuptools import setup, find_packages

setup(
    name='autadash',
    version='0.2.6',
    packages=find_packages(),
    author='Cuisset Mattéo',
    author_email='votre.email@example.com',
    description='Une courte description de votre projet',
    long_description=open('README.md').read(),
    install_requires=['Flask', 'Flask-Login', 'Flask-WTF', 'Flask-Mail', 'Flask-SQLAlchemy', 'itsdangerous', 'python-dotenv', 'flask_babel'],
)
