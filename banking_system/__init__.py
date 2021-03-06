import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from banking_system.config import Config


db = SQLAlchemy()
bcrypt = Bcrypt()

mail = Mail()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)

    from banking_system.users.routes import users
    from banking_system.main.routes import main
    # from banking_system.errors.handlers import errors

    app.register_blueprint(users)
    app.register_blueprint(main)
    # app.register_blueprint(errors)

    return app
