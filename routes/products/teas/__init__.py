from flask import Blueprint

teas = Blueprint('teas', __name__)

@teas.route("/")
def home():
    return {"message": "Teas controller OK"}
