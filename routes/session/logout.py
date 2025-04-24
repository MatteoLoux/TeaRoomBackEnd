from flask import Blueprint, session, jsonify, make_response

logout_routes = Blueprint("logout_routes", __name__)

@logout_routes.route("/logout", methods=["POST"])
def logout():
    session.clear()  # ✅ Supprime toutes les données de session

    response = make_response(jsonify({"success": True}))
    response.set_cookie("session", "", max_age=0, httponly=True, secure=True, samesite="Lax")
    return response