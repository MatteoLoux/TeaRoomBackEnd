from flask import Blueprint, request, jsonify
from argon2 import PasswordHasher, exceptions
from datetime import datetime, timedelta, timezone
import jwt
import os

from db import db_session, User

login_routes = Blueprint('login_routes', __name__)
JWT_SECRET = os.getenv("SECRET_KEY")  # Utilisé pour signer le token

@login_routes.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    now = datetime.now(timezone.utc)

    user = db_session.session.query(User).filter_by(email=email).first()

    if user is None:
        return jsonify({"success": False, "reason": 0})

    if user.n_password_failures >= 3 and user.last_failed and (now - user.last_failed) < timedelta(minutes=1):
        return jsonify({"success": False, "reason": 1})  # bloqué

    ph = PasswordHasher()
    try:
        ph.verify(user.password, password)

        user.n_password_failures = 0
        user.last_failed = None
        user.last_login = now
        db_session.session.commit()

        # Générer un token JWT
        token = jwt.encode(
            {
                "user_id": user.id,
                "is_admin": user.is_admin,
                "exp": datetime.utcnow() + timedelta(days=1)
            },
            JWT_SECRET,
            algorithm="HS256"
        )

        return jsonify({
            "success": True,
            "token": token,
            "user": {
                "id": user.id,
                "email": user.email,
                "firstname": user.firstname,
                "lastname": user.lastname,
                "is_admin": user.is_admin
            }
        })

    except exceptions.VerifyMismatchError:
        user.n_password_failures += 1
        user.last_failed = now
        db_session.session.commit()
        return jsonify({"success": False, "reason": 2, "failures": user.n_password_failures})
