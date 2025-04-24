from flask import Blueprint, jsonify, request
from db import db_session, User
import jwt
import os

me_routes = Blueprint('me_routes', __name__)
JWT_SECRET = os.getenv("SECRET_KEY")

@me_routes.route("/me", methods=["GET"])
def get_user_info():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"logged_in": False}), 401

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"logged_in": False, "error": "expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"logged_in": False, "error": "invalid"}), 401

    user = db_session.session.query(User).filter_by(id=payload["user_id"]).first()
    if not user:
        return jsonify({"logged_in": False}), 401

    return jsonify({
        "logged_in": True,
        "user": {
            "id": user.id,
            "email": user.email,
            "firstname": user.firstname,
            "lastname": user.lastname,
            "is_admin": user.is_admin
        }
    })
