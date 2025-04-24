from flask import Blueprint

cart = Blueprint('cart', __name__)

@cart.route("/")
def home():
    return {"message": "Cart controller OK"}
