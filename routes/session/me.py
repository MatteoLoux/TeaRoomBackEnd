from flask import Blueprint

me_routes = Blueprint('me_routes', __name__)


@me_routes.route("/me", methods=["GET"])
def get_user_info():
    pass