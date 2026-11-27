from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .models import db

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishshield.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    limiter.init_app(app)

    with app.app_context():
        db.create_all()

    from .routes import api_bp
    app.register_blueprint(api_bp)

    return app
