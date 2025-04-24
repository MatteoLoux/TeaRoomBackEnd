from flask import Blueprint, request, jsonify
from argon2 import PasswordHasher, exceptions
from datetime import datetime, timedelta, timezone
import secrets
import jwt
import os
from db import get_connection

login_routes = Blueprint('login_routes', __name__)


@login_routes.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    now = datetime.now(timezone.utc)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, password, is_admin, firstname, lastname, n_password_failures, last_failed, last_login FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if user is None:
        cursor.close(); conn.close()
        return jsonify({"success": False, "reason": 0})

    user_id, email, hashed_pw, is_admin, firstname, lastname, n_failures, last_failed, last_login = user

    if n_failures >= 3 and last_failed and (now - last_failed) < timedelta(minutes=1):
        cursor.close(); conn.close()
        return jsonify({"success": False, "reason": 1})

    ph = PasswordHasher()
    try:
        ph.verify(hashed_pw, password)
        token = secrets.token_hex(32)
        token = jwt.encode(
            {"user_id": user_id, "exp": datetime.now(timezone.utc) + timedelta(days=1)},
            os.getenv("SECRET_KEY"),
            algorithm="HS256"
        )
        if isinstance(token, bytes):
            token = token.decode("utf-8")

        cursor.execute("""
            UPDATE users
            SET n_password_failures = 0, last_failed = NULL, last_login = %s
            WHERE id = %s
        """, (now, user_id))
        conn.commit(); 
        cursor.close(); 
        conn.close() 
        return jsonify({
            "success": True,
            "token": token,
            "user": {
                "id": user_id,
                "email": email,
                "firstname": firstname,
                "lastname": lastname,
                "is_admin": is_admin
            }
        })

    except exceptions.VerifyMismatchError:
        n_failures += 1
        cursor.execute(
            "UPDATE users SET n_password_failures = %s, last_failed = %s WHERE id = %s",
            (n_failures, now, user_id)
        )
        conn.commit(); 
        cursor.close(); 
        conn.close() 
        return jsonify({"success": False, "reason": 2, "failures": n_failures})
