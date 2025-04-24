from flask import Blueprint

goodies = Blueprint('goodies', __name__)

@goodies.route("/")
def home():
    return {"message": "Goodies controller OK"}
