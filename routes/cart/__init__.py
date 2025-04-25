from flask import Blueprint
from .crud import cart_crud

cart = Blueprint("cart", __name__)
cart.register_blueprint(cart_crud)
