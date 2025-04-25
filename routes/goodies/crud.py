import base64
from flask import Blueprint, request, jsonify
from db import db_session, require_jwt, Goodie
from sqlalchemy.exc import IntegrityError

goodies_crud = Blueprint("goodies_crud", __name__)

# GET /goodies — route publique
@goodies_crud.route("/", methods=["GET"])
def list_goodies():
    goodies = Goodie.query.all()
    return jsonify([
        {
            "id": goodie.id,
            "name": goodie.name,
            "description": goodie.description,
            "price": float(goodie.price),
            "quantity": goodie.quantity,
            "image": f"data:image/jpeg;base64,{base64.b64encode(goodie.image).decode()}" if goodie.image else None
        }
        for goodie in goodies
    ])

# GET /goodies/<int:goodie_id> — route publique
@goodies_crud.route("/<int:goodie_id>", methods=["GET"])
def get_goodie(goodie_id):

    goodie = Goodie.query.get(goodie_id)
    if not goodie:
        return jsonify({"error": "Goodie introuvable"}), 404

    return jsonify({
        "id": goodie.id,
        "name": goodie.name,
        "description": goodie.description,
        "price": float(goodie.price),
        "quantity": goodie.quantity,
        "image": f"data:image/jpeg;base64,{base64.b64encode(goodie.image).decode()}" if goodie.image else None
    })

# POST /goodies — création (admin uniquement)
@goodies_crud.route("/", methods=["POST"])
@require_jwt
def create_goodie():
    if not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403

    data = request.get_json()

    try:
        goodie = Goodie(
            name=data["name"],
            description=data.get("description", ""),
            price=data["price"],
            quantity=data.get("quantity", 0),
            image=base64.b64decode(data["image"].split(",")[1]) if data.get("image") else None
        )
        db_session.session.add(goodie)
        db_session.session.commit()
        return jsonify({"id": goodie.id}), 201

    except IntegrityError:
        db_session.session.rollback()
        return jsonify({"error": "Nom déjà utilisé"}), 400

# PUT /goodies/<id> — modification (admin uniquement)
@goodies_crud.route("/<int:goodie_id>", methods=["PUT"])
@require_jwt
def update_goodie(goodie_id):
    if not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403

    goodie = Goodie.query.get(goodie_id)
    if not goodie:
        return jsonify({"error": "Goodie introuvable"}), 404

    data = request.get_json()
    goodie.name = data.get("name", goodie.name)
    goodie.description = data.get("description", goodie.description)
    goodie.price = data.get("price", goodie.price)
    goodie.quantity = data.get("quantity", goodie.quantity)
    if data.get("image"):
        goodie.image = base64.b64decode(data["image"].split(",")[1])

    db_session.session.commit()
    return jsonify({"message": "Goodie mis à jour"})

# DELETE /goodies/<id> — suppression (admin uniquement)
@goodies_crud.route("/<int:goodie_id>", methods=["DELETE"])
@require_jwt
def delete_goodie(goodie_id):
    if not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403

    goodie = Goodie.query.get(goodie_id)
    if not goodie:
        return jsonify({"error": "Goodie introuvable"}), 404

    db_session.session.delete(goodie)
    db_session.session.commit()
    return jsonify({"message": "Goodie supprimé"})
