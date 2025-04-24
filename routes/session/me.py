from flask import Blueprint, jsonify, session
from db import db_session, User

me_routes = Blueprint('me_routes', __name__)


@me_routes.route("/me", methods=["GET"])
def get_user_info():
    print("DEBUG SESSION:", dict(session), flush=True)
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"logged_in": False})

    user = db_session.session.query(User).filter_by(id=user_id).first()

    if user is None:
        session.clear()
        return jsonify({"logged_in": False})
    
    return jsonify({
        "logged_in": True,
        "user": {
            "id": user_id,
            "email": user.email,
            "firstname": user.firstname,
            "lastname": user.lastname,
            "is_admin": user.is_admin
        }
    })