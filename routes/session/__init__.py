from flask import Blueprint
from .login import login_routes
from .logout import logout_routes
from .me import me_routes

session = Blueprint('session', __name__)
session.register_blueprint(login_routes)
session.register_blueprint(logout_routes)
session.register_blueprint(me_routes)
