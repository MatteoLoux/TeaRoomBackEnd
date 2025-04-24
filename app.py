from flask import Flask
from flask_cors import CORS

from routes.users import users
from routes.products import products
from routes.cart import cart
from routes.session import session
from routes.products.teas import teas
from routes.products.goodies import goodies

app = Flask(__name__)
CORS(app)

# Blueprints enregistrés
app.register_blueprint(users, url_prefix="/users")
app.register_blueprint(products, url_prefix="/products")
app.register_blueprint(cart, url_prefix="/cart")
app.register_blueprint(session, url_prefix="/session")
app.register_blueprint(teas, url_prefix="/teas")
app.register_blueprint(goodies, url_prefix="/goodies")

@app.route("/")
def index():
    return {"message": "API Flask est en ligne 🚀"}

if __name__ == "__main__":
    app.run(debug=True)
