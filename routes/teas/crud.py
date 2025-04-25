import base64
from flask import Blueprint, request, jsonify
from db import db_session,require_jwt, Tea
from sqlalchemy.exc import IntegrityError
from datetime import datetime

teas_crud = Blueprint("teas_crud", __name__)

# GET /teas — route publique
@teas_crud.route("/", methods=["GET"])
def list_teas():
    teas = Tea.query.all()
    return jsonify([
        {
            "id": tea.id,
            "name": tea.name,
            "description": tea.description,
            "price": float(tea.price),
            "quantity": tea.quantity,
            "image": f"data:image/jpeg;base64,{base64.b64encode(tea.image).decode()}" if tea.image else None
        }
        for tea in teas
    ])

# GET /teas/<int:tea_id> — route publique
@teas_crud.route("/<int:tea_id>", methods=["GET"])
def get_tea(tea_id):

    tea = Tea.query.get(tea_id)
    if not tea:
        return jsonify({"error": "Thé introuvable"}), 404

    return jsonify({
        "id": tea.id,
        "name": tea.name,
        "description": tea.description,
        "price": float(tea.price),
        "quantity": tea.quantity,
        "image": f"data:image/jpeg;base64,{base64.b64encode(tea.image).decode()}" if tea.image else None
    })

# POST /teas — création (admin uniquement)
@teas_crud.route("/", methods=["POST"])
@require_jwt
def create_tea():
    if not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403

    data = request.get_json()

    try:
        tea = Tea(
            name=data["name"],
            description=data.get("description", ""),
            price=data["price"],
            quantity=data.get("quantity", 0),
            image=base64.b64decode(data["image"].split(",")[1]) if data.get("image") else None
        )
        db_session.session.add(tea)
        db_session.session.commit()
        return jsonify({"id": tea.id}), 201

    except IntegrityError:
        db_session.session.rollback()
        return jsonify({"error": "Nom déjà utilisé"}), 400

# PUT /teas/<id> — modification (admin uniquement)
@teas_crud.route("/<int:tea_id>", methods=["PUT"])
@require_jwt
def update_tea(tea_id):
    if not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403

    tea = Tea.query.get(tea_id)
    if not tea:
        return jsonify({"error": "Thé introuvable"}), 404

    data = request.get_json()
    tea.name = data.get("name", tea.name)
    tea.description = data.get("description", tea.description)
    tea.price = data.get("price", tea.price)
    tea.quantity = data.get("quantity", tea.quantity)
    if data.get("image"):
        tea.image = base64.b64decode(data["image"].split(",")[1])

    db_session.session.commit()
    return jsonify({"message": "Thé mis à jour"})

# DELETE /teas/<id> — suppression (admin uniquement)
@teas_crud.route("/<int:tea_id>", methods=["DELETE"])
@require_jwt
def delete_tea(tea_id):
    if not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403

    tea = Tea.query.get(tea_id)
    if not tea:
        return jsonify({"error": "Thé introuvable"}), 404

    db_session.session.delete(tea)
    db_session.session.commit()
    return jsonify({"message": "Thé supprimé"})
