import base64
from flask import Blueprint, request, jsonify
from db import db_session, require_jwt, Goodie
from sqlalchemy.exc import IntegrityError

goodies_crud = Blueprint("goodies_crud", __name__)

# GET /goodies — route publique
@goodies_crud.route("/", methods=["GET"], strict_slashes=False)
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
        return jsonify({"error": "Goodie introuvable"})

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
        # Traitement de l'image
        image_data = None
        if data.get("image"):
            try:
                image_data = process_image(data["image"])
            except Exception:
                # Continuer sans image en cas d'erreur
                pass
                
        goodie = Goodie(
            name=data["name"],
            description=data.get("description", ""),
            price=data["price"],
            quantity=data.get("quantity", 0),
            image=image_data
        )
        db_session.session.add(goodie)
        db_session.session.commit()
        return jsonify({"id": goodie.id}), 201

    except IntegrityError:
        db_session.session.rollback()
        return jsonify({"error": "Nom déjà utilisé"})

# PUT /goodies/<id> — modification (admin uniquement)
@goodies_crud.route("/<int:goodie_id>", methods=["PUT"])
@require_jwt
def update_goodie(goodie_id):
    if not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403

    goodie = Goodie.query.get(goodie_id)
    if not goodie:
        return jsonify({"error": "Goodie introuvable"})
    data = request.get_json()
    goodie.name = data.get("name", goodie.name)
    goodie.description = data.get("description", goodie.description)
    goodie.price = data.get("price", goodie.price)
    goodie.quantity = data.get("quantity", goodie.quantity)
    
    # Traitement de l'image si présente
    if "image" in data:
        try:
            goodie.image = process_image(data["image"])
        except Exception:
            # Continuer sans modifier l'image en cas d'erreur
            pass

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
        return jsonify({"error": "Goodie introuvable"})

    db_session.session.delete(goodie)
    db_session.session.commit()
    return jsonify({"message": "Goodie supprimé"})

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
