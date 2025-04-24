from flask import Blueprint

users = Blueprint('users', __name__)

@users.route("/")
def users_home():
    return {"message": "Module users actif"}