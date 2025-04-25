from flask import Blueprint, jsonify, request
from db import db_session, require_jwt,User
import jwt
import os
import base64

me_routes = Blueprint('me_routes', __name__)
JWT_SECRET = os.getenv("SECRET_KEY")

@me_routes.route("/me", methods=["GET"])
@require_jwt
def get_user_info():
    user = db_session.session.query(User).filter_by(id=request.user_id).first()
    if not user:
        return jsonify({"logged_in": False}), 401

    photo_url = None
    if user.photo:
        photo_data = base64.b64encode(user.photo).decode("utf-8")
        photo_url = f"data:image/jpeg;base64,{photo_data}"
    return jsonify({
        "logged_in": True,
        "user": {
            "id": user.id,
            "email": user.email,
            "firstname": user.firstname,
            "lastname": user.lastname,
            "is_admin": user.is_admin,
            "photo": photo_url
        }
    })
