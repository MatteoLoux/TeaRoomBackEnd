from flask import Blueprint
from .crud import goodies_crud

goodies = Blueprint("teas", __name__)
goodies.register_blueprint(goodies_crud)