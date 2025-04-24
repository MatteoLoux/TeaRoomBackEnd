from flask import Blueprint, jsonify, session
from db import db_session, User

me_routes = Blueprint('me_routes', __name__)


@me_routes.route("/me", methods=["GET"])
def get_user_info():
    print("DEBUG SESSION:", dict(session), flush=True)
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"logged_in": False})

    user = db_session.session.query(User).get(user_id)

    if user is None:
        session.clear()
        return jsonify({"logged_in": False})

    user_id, email, firstname, lastname, is_admin = user

    return jsonify({
        "logged_in": True,
        "user": {
            "id": user_id,
            "email": email,
            "firstname": firstname,
            "lastname": lastname,
            "is_admin": is_admin
        }
    })