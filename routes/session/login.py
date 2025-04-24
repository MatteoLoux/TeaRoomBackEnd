from flask import Blueprint, request, jsonify, session, make_response
from argon2 import PasswordHasher, exceptions
from datetime import datetime, timedelta, timezone

from db import db_session, User

login_routes = Blueprint('login_routes', __name__)


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
        return jsonify({"success": False, "reason": 1}) # Compte bloqué temporairement

    ph = PasswordHasher()
    try:
        ph.verify(user.password, password)
        
        #mdp correct
        user.n_password_failures = 0
        user.last_failed = None
        user.last_login = now
        db_session.session.commit()
        
        session.clear()
        session['user_id'] = user.id
        session['is_admin'] = user.is_admin
        session.permanent = True
        print(session,flush=True)
        response = make_response(jsonify({
            "success": True
        }))

        return response

    except exceptions.VerifyMismatchError:
        user.n_password_failures +=1
        user.last_failed = now
        db_session.session.commit()
        return jsonify({"success": False, "reason": 2, "failures": user.n_password_failures})
