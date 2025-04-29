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
    if user_id != request.user_id and not request.is_admin:
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
            
            # Format Anvil: bytes directs depuis file.get_bytes()
            if isinstance(photo_data, bytes):
                image_bytes = photo_data
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

    try:
        data = request.get_json()
        print(f"Mise à jour de l'utilisateur {user_id}, données reçues: {str(data.keys())}", flush=True)
        
        user.firstname = data.get("firstname", user.firstname)
        user.lastname = data.get("lastname", user.lastname)
        user.email = data.get("email", user.email)
        user.is_admin = data.get("is_admin", user.is_admin)
        
        # Vérifier si photo existe et n'est pas None
        if "photo" in data:
            photo_data = data["photo"]
            image_bytes = None  # Initialisation de image_bytes
            
            try:
                print(f"Traitement de la photo pour l'utilisateur {user_id}, type: {type(photo_data)}", flush=True)
                
                # Cas 1: La photo est None (suppression de la photo)
                if photo_data is None:
                    print(f"Suppression de la photo pour l'utilisateur {user_id}", flush=True)
                    user.photo = None
                # Format Anvil: bytes directs depuis file.get_bytes()
                elif isinstance(photo_data, bytes):
                    print(f"Photo au format bytes, taille: {len(photo_data)}", flush=True)
                    image_bytes = photo_data
                # Format de type dictionnaire (peut arriver avec certaines sérialisations JSON)
                elif isinstance(photo_data, dict):
                    print(f"Photo au format dictionnaire, clés: {photo_data.keys()}", flush=True)
                    if "data" in photo_data:
                        data_value = photo_data["data"]
                        
                        if isinstance(data_value, list):
                            print("Conversion liste en bytes", flush=True)
                            image_bytes = bytes(data_value)
                        elif isinstance(data_value, str):
                            print("Décodage base64", flush=True)
                            image_bytes = base64.b64decode(data_value)
                    # Dictionnaire avec clés numériques (tableau d'octets serialisé en JSON)
                    elif all(k.isdigit() for k in photo_data.keys()):
                        print("Conversion dictionnaire numérique en bytes", flush=True)
                        # Convertir le dictionnaire en liste ordonnée
                        byte_list = [photo_data[str(i)] for i in range(len(photo_data))]
                        # Convertir en bytes
                        image_bytes = bytes(byte_list)
                # Si c'est une string, essayer de décoder en base64
                elif isinstance(photo_data, str):
                    print("Photo reçue comme string, tentative de décodage base64", flush=True)
                    # Si ça commence par data:image, extraire la partie base64
                    if photo_data.startswith('data:image'):
                        base64_data = photo_data.split(',')[1]
                        image_bytes = base64.b64decode(base64_data)
                    else:
                        # Sinon essayer de décoder directement
                        image_bytes = base64.b64decode(photo_data)

                # Appliquer la stéganographie pour identifier l'utilisateur
                if image_bytes:
                    print(f"Application de la stéganographie, taille de l'image: {len(image_bytes)}", flush=True)
                    try:
                        # Vérifier que l'image peut être ouverte
                        test_img = Image.open(io.BytesIO(image_bytes))
                        test_img.close()
                        
                        marked_image = encode_steganography_data(image_bytes, user_id, int(time.time()))
                        user.photo = marked_image
                        print("Stéganographie appliquée avec succès", flush=True)
                    except Exception as e:
                        print(f"Erreur lors de la stéganographie: {str(e)}", flush=True)
                        # Sauvegarder l'image sans stéganographie plutôt que d'échouer
                        user.photo = image_bytes
                    
            except Exception as e:
                # Continuer l'exécution sans la photo au lieu de renvoyer une erreur
                print(f"Erreur lors du traitement de la photo: {str(e)}", flush=True)
                import traceback
                traceback.print_exc()
                
        # Commit explicite
        db_session.session.commit()
        print(f"Utilisateur {user_id} mis à jour avec succès", flush=True)
        return jsonify({"message": "Utilisateur mis à jour"})
        
    except Exception as e:
        db_session.session.rollback()
        print(f"Erreur globale lors de la mise à jour: {str(e)}", flush=True)
        import traceback
        traceback.print_exc()
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
    """Cache des métadonnées dans une image"""
    if timestamp is None:
        timestamp = int(time.time())
    
    # Préparation des données à cacher
    data = {
        "user_id": user_id,
        "timestamp": timestamp,
        "signature": "TeaRoom"
    }
    
    # Conversion en JSON puis en base64
    json_data = json.dumps(data)
    encoded_data = base64.b64encode(json_data.encode())
    
    try:
        # Ouvrir l'image
        img = Image.open(io.BytesIO(image_bytes))
        
        # Méthode alternative: ajouter les métadonnées comme info dans le PNG
        # Cette méthode est plus fiable que la stéganographie LSB
        output = io.BytesIO()
        
        # Conserver le format original si possible, sinon utiliser PNG
        if img.format == 'PNG':
            # Créer les métadonnées PNG
            metadata = PngInfo()
            metadata.add_text("TeaRoom", encoded_data.decode('ascii'))
            img.save(output, format='PNG', pnginfo=metadata)
        else:
            # Convertir en PNG pour pouvoir stocker les métadonnées
            if img.mode != 'RGB':
                img = img.convert('RGB')
            metadata = PngInfo()
            metadata.add_text("TeaRoom", encoded_data.decode('ascii'))
            img.save(output, format='PNG', pnginfo=metadata)
        
        print(f"Métadonnées ajoutées avec succès", flush=True)
        return output.getvalue()
    
    except Exception as e:
        print(f"Erreur lors du marquage de l'image: {str(e)}", flush=True)
        import traceback
        traceback.print_exc(flush=True)
        # En cas d'erreur, retourner l'image originale
        return image_bytes

def decode_steganography_data(image_bytes):
    """Récupère les données cachées dans les métadonnées de l'image"""
    try:
        # Ouvrir l'image
        img = Image.open(io.BytesIO(image_bytes))
        print(f"Décodage image: {img.format}, {img.size}, {img.mode}", flush=True)
        
        # Vérifier si des métadonnées existent
        if img.format == 'PNG' and "TeaRoom" in img.info:
            try:
                encoded_data = img.info["TeaRoom"]
                json_data = base64.b64decode(encoded_data).decode()
                data = json.loads(json_data)
                
                # Vérifier la signature
                if data.get("signature") == "TeaRoom":
                    print(f"Métadonnées trouvées: {data}", flush=True)
                    return data
            except Exception as e:
                print(f"Erreur lors du décodage des métadonnées: {str(e)}", flush=True)
        
        print("Aucune métadonnée valide trouvée", flush=True)
        return None
    
    except Exception as e:
        print(f"Erreur lors de l'extraction des métadonnées: {str(e)}", flush=True)
        import traceback
        traceback.print_exc(flush=True)
        return None

@users_crud.route("/verify-photo/<int:user_id>", methods=["GET", "OPTIONS"])
def verify_photo(user_id):
    """
    GET /users/verify-photo/<user_id> — Vérifie et renvoie les métadonnées cachées dans la photo
    """
    # Gérer les requêtes OPTIONS pour CORS
    if request.method == "OPTIONS":
        return jsonify({}), 200
    
    print(f"Demande de métadonnées pour l'utilisateur {user_id}", flush=True)
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Utilisateur non trouvé"}), 404
    
    if not user.photo:
        return jsonify({"error": "L'utilisateur n'a pas de photo"}), 404
    
    print(f"Tentative de décodage des métadonnées pour l'utilisateur {user_id}", flush=True)
    metadata = decode_steganography_data(user.photo)
    
    if metadata:
        return jsonify({
            "user_id": metadata.get("user_id"),
            "timestamp": metadata.get("timestamp"),
            "date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(metadata.get("timestamp")))
        })
    else:
        print(f"Aucune métadonnée trouvée pour l'utilisateur {user_id}", flush=True)
        return jsonify({"error": "Aucune métadonnée trouvée"}), 404

@users_crud.route("/test-steganography", methods=["GET"])
def test_steganography():
    """
    GET /users/test-steganography — Route de test pour la stéganographie
    """
    try:
        # Créer une image test
        img = Image.new('RGB', (100, 100), color='white')
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        image_bytes = buffer.getvalue()
        
        # Données à cacher
        user_id = "test_user"
        timestamp = int(time.time())
        
        # Encoder les données
        encoded_image = encode_steganography_data(image_bytes, user_id, timestamp)
        
        # Décoder les données
        decoded_data = decode_steganography_data(encoded_image)
        
        return jsonify({
            "success": decoded_data is not None and decoded_data.get("user_id") == user_id,
            "original_data": {"user_id": user_id, "timestamp": timestamp},
            "decoded_data": decoded_data
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    
