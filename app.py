from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
import os

from db import db_session
from routes.users import users
from routes.users.crud import users_crud
from routes.cart import cart
from routes.session import session
from routes.teas import teas
from routes.goodies import goodies
from routes.cart.crud import cart_crud
from routes.teas.crud import teas_crud
from routes.goodies.crud import goodies_crud

load_dotenv()

app = Flask(__name__)

# CORS autorisé pour ton app Anvil uniquement (avec envoi d'en-tête Authorization)
anvil_app_origin = "https://jnhvanepger556sc.anvil.app"
CORS(app, supports_credentials=True, origins=[anvil_app_origin])

# Configuration de base
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
# Initialisation de SQLAlchemy
db_session.init_app(app)
with app.app_context():
    db_session.create_all()

# Enregistrement des blueprints
app.register_blueprint(users_crud, url_prefix="/users")
app.register_blueprint(session, url_prefix="/session")
app.register_blueprint(cart_crud, url_prefix="/cart")
app.register_blueprint(teas_crud, url_prefix="/teas")
app.register_blueprint(goodies_crud, url_prefix="/goodies")


@app.route("/")
def index():
    return {"message": "API Flask est en ligne "}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
