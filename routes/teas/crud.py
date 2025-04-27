import base64
from flask import Blueprint, request, jsonify
from db import db_session,require_jwt, Tea
from sqlalchemy.exc import IntegrityError
from datetime import datetime

teas_crud = Blueprint("teas_crud", __name__)

# GET /teas — route publique
@teas_crud.route("/", methods=["GET"], strict_slashes=False)
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
        return jsonify({"error": "Thé introuvable"})

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
        # Traitement de l'image
        image_data = None
        if data.get("image"):
            try:
                image_data = process_image(data["image"])
            except Exception:
                # Continuer sans image en cas d'erreur
                pass
                
        tea = Tea(
            name=data["name"],
            description=data.get("description", ""),
            price=data["price"],
            quantity=data.get("quantity", 0),
            image=image_data
        )
        db_session.session.add(tea)
        db_session.session.commit()
        return jsonify({"id": tea.id}), 201

    except IntegrityError:
        db_session.session.rollback()
        return jsonify({"error": "Nom déjà utilisé"})

# PUT /teas/<id> — modification (admin uniquement)
@teas_crud.route("/<int:tea_id>", methods=["PUT"])
@require_jwt
def update_tea(tea_id):
    if not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403

    tea = Tea.query.get(tea_id)
    if not tea:
        return jsonify({"error": "Thé introuvable"})

    data = request.get_json()
    tea.name = data.get("name", tea.name)
    tea.description = data.get("description", tea.description)
    tea.price = data.get("price", tea.price)
    tea.quantity = data.get("quantity", tea.quantity)
    
    # Traitement de l'image si présente
    if "image" in data:
        try:
            tea.image = process_image(data["image"])
        except Exception:
            # Continuer sans modifier l'image en cas d'erreur
            pass

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
        return jsonify({"error": "Thé introuvable"})

    db_session.session.delete(tea)
    db_session.session.commit()
    return jsonify({"message": "Thé supprimé"})

# Fonction utilitaire pour traiter les images dans différents formats
def process_image(image_data):
    # Cas 1: L'image est None (suppression)
    if image_data is None:
        return None
    
    # Cas 2: L'image est une chaîne (format data URL ou base64)
    if isinstance(image_data, str):
        if "," in image_data:
            base64_part = image_data.split(",")[1]
            return base64.b64decode(base64_part)
        else:
            return base64.b64decode(image_data)
    
    # Cas 3: Tableau d'octets reçu directement (bytes ou list)
    if isinstance(image_data, (list, bytes, bytearray)):
        # Si c'est une liste d'entiers (octets), la convertir en bytes
        if isinstance(image_data, list):
            try:
                return bytes(image_data)
            except Exception:
                # Alternative: essayer list(map(int, image_data))
                return bytes(map(int, image_data))
        else:
            # Déjà au format bytes ou bytearray
            return bytes(image_data)
    
    # Cas 4: Format de type dictionnaire
    if isinstance(image_data, dict):
        if "data" in image_data:
            data_value = image_data["data"]
            
            if isinstance(data_value, list):
                return bytes(data_value)
            elif isinstance(data_value, str):
                return base64.b64decode(data_value)
        # Dictionnaire avec clés numériques (tableau d'octets serialisé en JSON)
        elif all(k.isdigit() for k in image_data.keys()):
            # Convertir le dictionnaire en liste ordonnée
            byte_list = [image_data[str(i)] for i in range(len(image_data))]
            # Convertir en bytes
            return bytes(byte_list)
    
    # Cas par défaut: si format non reconnu, retourner None
    return None
