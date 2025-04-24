from flask import Blueprint, jsonify, session
from db import get_conn

me_routes = Blueprint('me_routes', __name__)


@me_routes.route("/me", methods=["GET"])
def get_user_info():
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"error": "Utilisateur non connecté"}), 401

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, email, firstname, lastname, is_admin
        FROM users
        WHERE id = %s
    """, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user is None:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    user_id, email, firstname, lastname, is_admin = user

    return jsonify({
        "id": user_id,
        "email": email,
        "firstname": firstname,
        "lastname": lastname,
        "is_admin": is_admin
    })