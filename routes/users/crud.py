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
import numpy as np

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
            
            # Cas 2: La photo est une chaîne (format data URL ou base64)
            elif isinstance(photo_data, str):
                if "," in photo_data:
                    base64_part = photo_data.split(",")[1]
                    image_bytes = base64.b64decode(base64_part)
                else:
                    image_bytes = base64.b64decode(photo_data)
                
                # Appliquer la stéganographie pour identifier l'utilisateur
                if image_bytes:
                    marked_image = encode_steganography_data(image_bytes, user_id, int(time.time()))
                    user.photo = marked_image
            
            # Cas 3: Tableau d'octets reçu directement (bytes ou list)
            elif isinstance(photo_data, (list, bytes, bytearray)):
                if isinstance(photo_data, list):
                    try:
                        # Tenter de convertir en bytes
                        image_bytes = bytes(photo_data)
                    except Exception:
                        # Alternative: essayer list(map(int, photo_data))
                        try:
                            image_bytes = bytes(map(int, photo_data))
                        except Exception:
                            raise ValueError("Impossible de convertir la liste en bytes")
                else:
                    # Déjà au format bytes ou bytearray
                    image_bytes = bytes(photo_data)
                
                # Appliquer la stéganographie pour identifier l'utilisateur
                if image_bytes:
                    marked_image = encode_steganography_data(image_bytes, user_id, int(time.time()))
                    user.photo = marked_image
            
            # Cas 4: Format de type dictionnaire (peut arriver avec certaines sérialisations JSON)
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
            
            # Cas 5: Format inconnu
            else:
                raise ValueError(f"Format de photo non pris en charge: {type(photo_data)}")
                
        except Exception as e:
            # Continuer l'exécution sans la photo au lieu de renvoyer une erreur
            print(f"Erreur lors du traitement de la photo: {str(e)}")
            pass
            
    try:
        # Commit explicite
        db_session.session.commit()
        return jsonify({"message": "Utilisateur mis à jour"})
    except Exception as e:
        db_session.session.rollback()
        return jsonify({"error": f"Erreur lors de la mise à jour: {str(e)}"}), 500

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
        
        try:
            # Cas 1: La photo est None (suppression de la photo)
            if photo_data is None:
                user.photo = None
            
            # Cas 2: La photo est une chaîne (format data URL ou base64)
            elif isinstance(photo_data, str):
                image_bytes = None
                if "," in photo_data:
                    base64_part = photo_data.split(",")[1]
                    image_bytes = base64.b64decode(base64_part)
                else:
                    image_bytes = base64.b64decode(photo_data)
                
                # Appliquer la stéganographie pour identifier l'utilisateur
                if image_bytes:
                    marked_image = encode_steganography_data(image_bytes, user_id, int(time.time()))
                    user.photo = marked_image
            
            # Cas 3: Tableau d'octets reçu directement (bytes ou list)
            elif isinstance(photo_data, (list, bytes, bytearray)):
                if isinstance(photo_data, list):
                    try:
                        image_bytes = bytes(photo_data)
                    except Exception:
                        try:
                            image_bytes = bytes(map(int, photo_data))
                        except Exception:
                            raise ValueError("Impossible de convertir la liste en bytes")
                else:
                    image_bytes = bytes(photo_data)
                
                # Appliquer la stéganographie pour identifier l'utilisateur
                if image_bytes:
                    marked_image = encode_steganography_data(image_bytes, user_id, int(time.time()))
                    user.photo = marked_image
            
            # Cas 4: Format de type dictionnaire (peut arriver avec certaines sérialisations JSON)
            elif isinstance(photo_data, dict):
                image_bytes = None
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
            
            # Cas 5: Format inconnu
            else:
                raise ValueError(f"Format de photo non pris en charge: {type(photo_data)}")
                
        except Exception as e:
            # Continuer l'exécution sans la photo au lieu de renvoyer une erreur
            print(f"Erreur lors du traitement de la photo: {str(e)}")
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
    # Utiliser le timestamp actuel si non fourni
    if timestamp is None:
        timestamp = int(time.time())
    
    # Créer les données à cacher (identifiant utilisateur et timestamp)
    data = {
        "user_id": user_id,
        "timestamp": timestamp,
        "signature": "TeaRoom"  # Marque pour identifier nos images modifiées
    }
    data_str = json.dumps(data)
    
    # Convertir les données en format binaire
    binary_data = ''.join(format(ord(char), '08b') for char in data_str)
    
    # Convertir les bytes de l'image en objet PIL
    img = Image.open(io.BytesIO(image_bytes))
    
    # Convertir l'image en tableau NumPy
    img_array = np.array(img)
    
    # Vérifier si l'image a suffisamment d'espace pour cacher les données
    height, width = img_array.shape[:2]
    channels = 3 if len(img_array.shape) == 3 else 1
    max_bytes = (height * width * channels) // 8
    
    if len(binary_data) > max_bytes:
        raise ValueError(f"L'image est trop petite pour cacher ces données. Besoin de {len(binary_data)} bits, disponible: {max_bytes*8} bits")
    
    # Ajouter la longueur des données en binaire (32 bits)
    binary_data_length = format(len(binary_data), '032b')
    binary_data = binary_data_length + binary_data
    
    # Cacher les données dans l'image
    data_index = 0
    for i in range(height):
        for j in range(width):
            for k in range(channels):
                if data_index < len(binary_data):
                    # Modifier le bit le moins significatif
                    if channels == 1:
                        # Image en niveaux de gris
                        pixel_value = img_array[i, j]
                        # Définir le LSB selon notre donnée binaire
                        img_array[i, j] = (pixel_value & ~1) | int(binary_data[data_index])
                    else:
                        # Image RGB/RGBA
                        pixel_value = img_array[i, j, k]
                        # Définir le LSB selon notre donnée binaire
                        img_array[i, j, k] = (pixel_value & ~1) | int(binary_data[data_index])
                    data_index += 1
                else:
                    break
            if data_index >= len(binary_data):
                break
        if data_index >= len(binary_data):
            break
    
    # Convertir le tableau modifié en image
    modified_img = Image.fromarray(img_array)
    
    # Sauvegarder l'image en mémoire
    output = io.BytesIO()
    modified_img.save(output, format=img.format)
    
    return output.getvalue()

def decode_steganography_data(image_bytes):
    # Convertir les bytes de l'image en objet PIL
    img = Image.open(io.BytesIO(image_bytes))
    
    # Convertir l'image en tableau NumPy
    img_array = np.array(img)
    
    # Récupérer les dimensions de l'image
    height, width = img_array.shape[:2]
    channels = 3 if len(img_array.shape) == 3 else 1
    
    # Extraire d'abord les 32 premiers bits pour connaître la longueur des données
    binary_length = ""
    for i in range(32):
        row = i // (width * channels)
        col = (i // channels) % width
        channel = i % channels
        
        if channels == 1:
            binary_length += str(img_array[row, col] & 1)
        else:
            binary_length += str(img_array[row, col, channel] & 1)
    
    data_length = int(binary_length, 2)
    
    # Extraire les données
    binary_data = ""
    for i in range(32, 32 + data_length):
        row = i // (width * channels)
        col = (i // channels) % width
        channel = i % channels
        
        if channels == 1:
            binary_data += str(img_array[row, col] & 1)
        else:
            binary_data += str(img_array[row, col, channel] & 1)
    
    # Convertir les données binaires en chaîne de caractères
    chars = []
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        chars.append(chr(int(byte, 2)))
    
    data_str = ''.join(chars)
    
    try:
        data = json.loads(data_str)
        # Vérifier la signature pour s'assurer que c'est bien notre image modifiée
        if data.get("signature") != "TeaRoom":
            return None
        return data
    except:
        return None
    
# Fonction utilitaire pour extraire les informations de la photo
@users_crud.route("/verify-photo/<int:user_id>", methods=["GET"])
@require_jwt
def verify_photo_metadata(user_id):
    # Seuls les administrateurs peuvent vérifier les métadonnées des photos
    if not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Utilisateur non trouvé"}), 404
    
    if not user.photo:
        return jsonify({"error": "Cet utilisateur n'a pas de photo de profil"}), 404
    
    try:
        metadata = decode_steganography_data(user.photo)
        if not metadata:
            return jsonify({"error": "Aucune métadonnée trouvée ou image non marquée"}), 404
        
        return jsonify({
            "metadata": metadata,
            "user_id": metadata.get("user_id"),
            "timestamp": metadata.get("timestamp"),
            "date": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(metadata.get("timestamp")))
        })
    except Exception as e:
        return jsonify({"error": f"Erreur lors de l'extraction des métadonnées: {str(e)}"}), 500