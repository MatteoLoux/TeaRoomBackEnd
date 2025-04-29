import base64
from flask import Blueprint, request, jsonify
from sqlalchemy.exc import IntegrityError
from db import db_session,require_jwt, User, JWT_SECRET
from sqlalchemy import func
from argon2 import PasswordHasher, exceptions
import jwt
import base64
import json
import time
from PIL import Image
import io
from PIL.PngImagePlugin import PngInfo

users_crud = Blueprint('users_crud', __name__)



# GET /users — admin uniquement
@users_crud.route("/", methods=["GET"], strict_slashes=False)
@require_jwt
def list_users():
    if not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403

    users = User.query.all()
    return jsonify([
        {
            "id": u.id,
            "firstname": u.firstname,
            "lastname": u.lastname,
            "email": u.email,
            "is_admin": u.is_admin,
            "created_at": u.created_at,
            "updated_at": u.updated_at,
            "photo": f"data:image/jpeg;base64,{base64.b64encode(u.photo).decode()}" if u.photo else None
        } for u in users
    ])

# GET /users/<int:user_id> — autorisé aux utilisateurs connectés
@users_crud.route("/<int:user_id>", methods=["GET"])
@require_jwt
def get_user(user_id):
    if user_id != request.user_id or not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Utilisateur non trouvé"}), 404

    return jsonify({
        "id": user.id,
        "firstname": user.firstname,
        "lastname": user.lastname,
        "email": user.email,
        "is_admin": user.is_admin,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
        "photo": f"data:image/jpeg;base64,{base64.b64encode(user.photo).decode()}" if user.photo else None
    })

# POST /users — création admin uniquement
@users_crud.route("/", methods=["POST"], strict_slashes=False)
def create_user():
    data = request.get_json()
    ph = PasswordHasher()
    try:
        user = User(
            firstname=data["firstname"],
            lastname=data["lastname"],
            email=data["email"],
            password=ph.hash(data["password"]),
            is_admin=data.get("is_admin", False),
            photo=None
        )

        if "photo" in data:
            photo_data = data["photo"]
            image_bytes = None  # Initialisation de image_bytes
            
            # Cas 1: La photo est None (suppression de la photo)
            if photo_data is None:
                pass  # user.photo est déjà None
            
            # Format de type dictionnaire (peut arriver avec certaines sérialisations JSON)
            elif isinstance(photo_data, dict):
                if "data" in photo_data:
                    data_value = photo_data["data"]
                    
                    if isinstance(data_value, list):
                        image_bytes = bytes(data_value)
                    elif isinstance(data_value, str):
                        image_bytes = base64.b64decode(data_value)
                # Dictionnaire avec clés numériques (tableau d'octets serialisé en JSON)
                elif all(k.isdigit() for k in photo_data.keys()):
                    # Convertir le dictionnaire en liste ordonnée
                    byte_list = [photo_data[str(i)] for i in range(len(photo_data))]
                    # Convertir en bytes
                    image_bytes = bytes(byte_list)

            # Appliquer la stéganographie pour identifier l'utilisateur
            if image_bytes:
                marked_image = encode_steganography_data(image_bytes, "new_user", int(time.time()))
                user.photo = marked_image

        db_session.session.add(user)
        db_session.session.commit()
        
        # Si l'utilisateur a une photo, mettre à jour le marquage avec l'ID réel
        if user.photo and user.id:
            try:
                marked_image = encode_steganography_data(user.photo, user.id, int(time.time()))
                user.photo = marked_image
                db_session.session.commit()
            except Exception as e:
                print(f"Erreur lors de la mise à jour de la photo avec l'ID réel: {str(e)}",flush=True)
                pass
                
        return jsonify({"id": user.id}), 201

    except IntegrityError:
        db_session.session.rollback()
        return jsonify({"error": "Email déjà utilisé"})
    except Exception as e:
        db_session.session.rollback()
        return jsonify({"error": f"Erreur lors de la création: {str(e)}"}), 500

# PUT /users/<id> — admin ou soi-même
@users_crud.route("/<int:user_id>", methods=["PUT"])
@require_jwt
def update_user(user_id):
    if user_id != request.user_id and not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Utilisateur non trouvé"}), 404

    data = request.get_json()
    
    user.firstname = data.get("firstname", user.firstname)
    user.lastname = data.get("lastname", user.lastname)
    user.email = data.get("email", user.email)
    user.is_admin = data.get("is_admin", user.is_admin)
    
    # Vérifier si photo existe et n'est pas None
    if "photo" in data:
        photo_data = data["photo"]
        image_bytes = None  # Initialisation de image_bytes
        
        try:
            # Cas 1: La photo est None (suppression de la photo)
            if photo_data is None:
                user.photo = None
            
            # Format de type dictionnaire (peut arriver avec certaines sérialisations JSON)
            elif isinstance(photo_data, dict):
                if "data" in photo_data:
                    data_value = photo_data["data"]
                    
                    if isinstance(data_value, list):
                        image_bytes = bytes(data_value)
                    elif isinstance(data_value, str):
                        image_bytes = base64.b64decode(data_value)
                # Dictionnaire avec clés numériques (tableau d'octets serialisé en JSON)
                elif all(k.isdigit() for k in photo_data.keys()):
                    # Convertir le dictionnaire en liste ordonnée
                    byte_list = [photo_data[str(i)] for i in range(len(photo_data))]
                    # Convertir en bytes
                    image_bytes = bytes(byte_list)

            # Appliquer la stéganographie pour identifier l'utilisateur
            if image_bytes:
                marked_image = encode_steganography_data(image_bytes, user_id, int(time.time()))
                user.photo = marked_image
                
        except Exception as e:
            # Continuer l'exécution sans la photo au lieu de renvoyer une erreur
            print(f"Erreur lors du traitement de la photo: {str(e)}",flush=True)
            pass
            
    try:
        # Commit explicite
        db_session.session.commit()
        return jsonify({"message": "Utilisateur mis à jour"})
    except Exception as e:
        db_session.session.rollback()
        return jsonify({"error": f"Erreur lors de la mise à jour: {str(e)}"}), 500

# DELETE /users/<id> — admin uniquement
@users_crud.route("/<int:user_id>", methods=["DELETE"])
@require_jwt
def delete_user(user_id):
    if not request.is_admin and user_id != request.user_id:
        return jsonify({"error": "Accès interdit"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Utilisateur non trouvé"}), 404

    db_session.session.delete(user)
    db_session.session.commit()
    return jsonify({"message": "Utilisateur supprimé"})

@users_crud.route("/verify-password", methods=["POST", "OPTIONS"], strict_slashes=False)
def verify_password():
    """
    POST /users/verify-password — Vérifie si le mot de passe est correct pour un utilisateur donné
    """
    # Gérer les requêtes OPTIONS pour CORS
    if request.method == "OPTIONS":
        return jsonify({}), 200
        
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"valid": False, "message": "Champs manquants"}), 400

    user = User.query.filter_by(email=email).first()

    if user is None:
        return jsonify({"valid": False, "message": "Utilisateur introuvable"}), 404

    ph = PasswordHasher()

    try:
        ph.verify(user.password, password)
        return jsonify({"valid": True})
    except exceptions.VerifyMismatchError:
        return jsonify({"valid": False})

@users_crud.route("/update-password", methods=["POST", "OPTIONS"], strict_slashes=False)
def update_password():
    """
    POST /users/update-password — Met à jour le mot de passe d'un utilisateur
    """
    # Gérer les requêtes OPTIONS pour CORS
    if request.method == "OPTIONS":
        return jsonify({}), 200
        
    # Vérifier le JWT seulement pour les requêtes POST
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization header missing"}), 401

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    user_id = payload["user_id"]
    
    data = request.get_json()
    old_password = data.get("old_password")
    new_password = data.get("new_password")
    
    if not old_password or not new_password:
        return jsonify({"success": False, "message": "Champs manquants"}), 400
        
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "Utilisateur introuvable"}), 404
        
    # Vérifier l'ancien mot de passe
    ph = PasswordHasher()
    try:
        ph.verify(user.password, old_password)
        
        # Hasher et sauvegarder le nouveau mot de passe
        user.password = ph.hash(new_password)
        db_session.session.commit()
        
        return jsonify({"success": True, "message": "Mot de passe mis à jour"})
    except exceptions.VerifyMismatchError:
        return jsonify({"success": False, "message": "Ancien mot de passe incorrect"}), 400
    
def encode_steganography_data(image_bytes, user_id, timestamp=None):
    """Version simplifiée et plus robuste de la stéganographie"""
    if timestamp is None:
        timestamp = int(time.time())
    
    # Créer les données à cacher
    data = {
        "user_id": user_id,
        "timestamp": timestamp,
        "signature": "TeaRoom"
    }
    
    # Convertir en JSON puis en base64 pour éviter les problèmes de caractères
    json_data = json.dumps(data)
    encoded_data = base64.b64encode(json_data.encode()).decode()
    
    # Placer les données dans les métadonnées plutôt que dans les pixels
    # Cette approche est beaucoup plus simple et robuste
    try:
        img = Image.open(io.BytesIO(image_bytes))
        
        # Convertir en RGB si nécessaire
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Créer une nouvelle image avec les mêmes caractéristiques
        output = io.BytesIO()
        
        # Enregistrer l'image avec les métadonnées cachées
        # Utiliser un commentaire EXIF pour cacher les données
        img.save(output, format='PNG', 
                 pnginfo=PngInfo().add_text("TeaRoom", encoded_data))
        
        return output.getvalue()
    except Exception as e:
        print(f"Erreur lors de l'encodage: {str(e)}", flush=True)
        return image_bytes

def decode_steganography_data(image_bytes):
    """Version simplifiée pour la récupération des données"""
    try:
        img = Image.open(io.BytesIO(image_bytes))
        
        # Récupérer les métadonnées
        if "TeaRoom" in img.info:
            encoded_data = img.info["TeaRoom"]
            json_data = base64.b64decode(encoded_data).decode()
            data = json.loads(json_data)
            
            # Vérifier la signature
            if data.get("signature") != "TeaRoom":
                print("Signature invalide", flush=True)
                return None
            
            return data
        else:
            print("Aucune donnée TeaRoom trouvée", flush=True)
            return None
    except Exception as e:
        print(f"Erreur lors du décodage: {str(e)}", flush=True)
        return None

# Fonction utilitaire pour extraire les informations de la photo
@users_crud.route("/verify-photo/<int:user_id>", methods=["GET"])
@require_jwt
def verify_photo_metadata(user_id):
    print(f"Demande de métadonnées pour l'utilisateur {user_id}",flush=True)
    
    # Seuls les administrateurs peuvent vérifier les métadonnées des photos
    if not request.is_admin:
        print("Accès refusé: l'utilisateur n'est pas administrateur",flush=True)
        return jsonify({"error": "Accès interdit"}), 403
    
    user = User.query.get(user_id)
    if not user:
        print(f"Utilisateur {user_id} non trouvé",flush=True)
        return jsonify({"error": "Utilisateur non trouvé"}), 404
    
    if not user.photo:
        print(f"L'utilisateur {user_id} n'a pas de photo",flush=True)
        return jsonify({"message": "Pas de photo"}), 200
    
    try:
        # Essayer de décoder les métadonnées
        print(f"Tentative de décodage des métadonnées pour l'utilisateur {user_id}",flush=True)
        metadata = decode_steganography_data(user.photo)
        
        if metadata:
            print(f"Métadonnées trouvées: {metadata}",flush=True)
            response_data = {
                "metadata": metadata,
                "user_id": metadata.get("user_id"),
                "timestamp": metadata.get("timestamp"),
                "date": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(metadata.get("timestamp", 0)))
            }
            return jsonify(response_data)
        else:
            print(f"Aucune métadonnée trouvée pour l'utilisateur {user_id}",flush=True)
            return jsonify({"message": "Aucune métadonnée trouvée"}), 200
            
    except Exception as e:
        print(f"Erreur lors de l'extraction des métadonnées: {str(e)}",flush=True)
        return jsonify({"error": str(e)}), 200

@users_crud.route("/test-steganography", methods=["GET"])
def test_steganography():
    """
    Route de test pour vérifier que la stéganographie fonctionne
    """
    try:
        # Créer une image test
        img = Image.new('RGB', (100, 100), color=(255, 255, 255))
        
        # Convertir l'image en bytes
        img_bytes_io = io.BytesIO()
        img.save(img_bytes_io, format='PNG')
        img_bytes = img_bytes_io.getvalue()
        
        # Données test à encoder
        test_id = "test_user"
        test_timestamp = int(time.time())
        
        # Encoder les données
        encoded_bytes = encode_steganography_data(img_bytes, test_id, test_timestamp)
        
        # Décoder les données
        decoded_data = decode_steganography_data(encoded_bytes)
        
        # Retourner les résultats
        return jsonify({
            "success": decoded_data is not None,
            "original_data": {
                "user_id": test_id,
                "timestamp": test_timestamp
            },
            "decoded_data": decoded_data
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        })