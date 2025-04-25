from flask import Blueprint
from .crud import users_crud

users = Blueprint("users", __name__)
users.register_blueprint(users_crud)