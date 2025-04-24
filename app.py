from flask import Flask
from flask_cors import CORS
from flask_session import Session
from dotenv import load_dotenv
import os

from db import db_session
from routes.users import users
from routes.cart import cart
from routes.session import session
from routes.teas import teas
from routes.goodies import goodies

load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["https://jnhvanepger556sc.anvil.app/"])

# Configuration des sessions avec PostgreSQL
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db_session
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'None'


db_session.init_app(app)

Session(app)

# Blueprints enregistrés
app.register_blueprint(users, url_prefix="/users")
app.register_blueprint(cart, url_prefix="/cart")
app.register_blueprint(session, url_prefix="/session")
app.register_blueprint(teas, url_prefix="/teas")
app.register_blueprint(goodies, url_prefix="/goodies")

@app.route("/")
def index():
    return {"message": "API Flask est en ligne 🚀"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
