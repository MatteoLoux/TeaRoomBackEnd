from flask import Blueprint
from .crud import teas_crud

teas = Blueprint("teas", __name__)
teas.register_blueprint(teas_crud)