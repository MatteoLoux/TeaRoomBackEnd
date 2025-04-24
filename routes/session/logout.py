from flask import Blueprint

logout_routes = Blueprint('logout_routes', __name__)


@logout_routes.route("/logout", methods=["POST"])
def logout():
    pass