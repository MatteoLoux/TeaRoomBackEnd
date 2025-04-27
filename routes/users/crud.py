import base64
from flask import Blueprint, request, jsonify
from sqlalchemy.exc import IntegrityError
from db import db_session,require_jwt, User, JWT_SECRET
from sqlalchemy import func
from argon2 import PasswordHasher, exceptions
import jwt

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
@require_jwt
def create_user():
    if not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403

    data = request.get_json()
    try:
        user = User(
            firstname=data["firstname"],
            lastname=data["lastname"],
            email=data["email"],
            password=data["password"],
            is_admin=data.get("is_admin", False),
            photo=base64.b64decode(data["photo"].split(",")[1]) if data.get("photo") else None
        )
        db_session.session.add(user)
        db_session.session.commit()
        return jsonify({"id": user.id}), 201

    except IntegrityError:
        db_session.session.rollback()
        return jsonify({"error": "Email déjà utilisé"}), 400

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
    print(f"Données reçues pour update_user: {list(data.keys())}", flush=True)
    
    user.firstname = data.get("firstname", user.firstname)
    user.lastname = data.get("lastname", user.lastname)
    user.email = data.get("email", user.email)
    user.is_admin = data.get("is_admin", user.is_admin)
    
    # Vérifier si photo existe et n'est pas None
    if "photo" in data:
        photo_data = data["photo"]
        print(f"Photo trouvée dans les données: {type(photo_data)}", flush=True)
        
        try:
            # Cas 1: La photo est None (suppression de la photo)
            if photo_data is None:
                print("Suppression de la photo", flush=True)
                user.photo = None
            
            # Cas 2: La photo est une chaîne (format data URL ou base64)
            elif isinstance(photo_data, str):
                print(f"Photo est une chaîne de longueur {len(photo_data)}", flush=True)
                
                if "," in photo_data:
                    print("Format data URL détecté, extraction partie base64", flush=True)
                    base64_part = photo_data.split(",")[1]
                    user.photo = base64.b64decode(base64_part)
                else:
                    print("Décodage direct de la chaîne base64", flush=True)
                    user.photo = base64.b64decode(photo_data)
            
            # Cas 3: Tableau d'octets reçu directement (bytes ou list)
            elif isinstance(photo_data, (list, bytes, bytearray)):
                print(f"Photo est un tableau d'octets de longueur {len(photo_data)}", flush=True)
                
                # Si c'est une liste d'entiers (octets), la convertir en bytes
                if isinstance(photo_data, list):
                    print(f"Liste d'octets, premier élément: {type(photo_data[0]) if photo_data else 'None'}", flush=True)
                    # Ne pas vérifier chaque octet pour les grandes listes
                    if len(photo_data) < 100:
                        print(f"Échantillon: {photo_data[:20]}", flush=True)
                    
                    try:
                        # Tenter de convertir en bytes (peut lever une exception si format incorrect)
                        user.photo = bytes(photo_data)
                    except Exception as bytes_err:
                        print(f"Erreur conversion en bytes: {bytes_err}", flush=True)
                        # Alternative: essayer list(map(int, photo_data))
                        try:
                            user.photo = bytes(map(int, photo_data))
                        except Exception as map_err:
                            print(f"Erreur conversion avec map: {map_err}", flush=True)
                            raise ValueError("Impossible de convertir la liste en bytes")
                else:
                    # Déjà au format bytes ou bytearray
                    user.photo = bytes(photo_data)
            
            # Cas 4: Format de type dictionnaire (peut arriver avec certaines sérialisations JSON)
            elif isinstance(photo_data, dict):
                print(f"Photo est un dictionnaire avec clés: {list(photo_data.keys())}", flush=True)
                
                if "data" in photo_data:
                    data_value = photo_data["data"]
                    print(f"Utilisation de la clé 'data' du dict: {type(data_value)}", flush=True)
                    
                    if isinstance(data_value, list):
                        print("Conversion de data_value en bytes", flush=True)
                        user.photo = bytes(data_value)
                    elif isinstance(data_value, str):
                        print("Décodage de data_value comme base64", flush=True)
                        user.photo = base64.b64decode(data_value)
                    else:
                        raise ValueError(f"Format de data_value non supporté: {type(data_value)}")
                else:
                    raise ValueError("Dict photo sans clé 'data'")
            
            # Cas 5: Format inconnu
            else:
                print(f"Format de photo non reconnu: {type(photo_data)}", flush=True)
                # Essayer de convertir en chaîne JSON pour diagnostic
                import json
                try:
                    json_str = json.dumps(photo_data)
                    print(f"JSON: {json_str[:100]}...", flush=True)
                except:
                    print("Impossible de convertir en JSON", flush=True)
                
                raise ValueError(f"Format de photo non pris en charge: {type(photo_data)}")
            
            if user.photo:
                print(f"Photo traitée avec succès: {len(user.photo)} bytes", flush=True)
            else:
                print("Photo supprimée ou non définie", flush=True)
                
        except Exception as e:
            print(f"Erreur lors du traitement de la photo: {e}", flush=True)
            # Continuer l'exécution sans la photo au lieu de renvoyer une erreur
            print("Continuons sans modifier la photo", flush=True)
    else:
        print("Clé 'photo' non présente dans les données reçues", flush=True)
        
    try:
        # Commit explicite
        db_session.session.commit()
        print("Commit réussi, utilisateur mis à jour", flush=True)
        return jsonify({"message": "Utilisateur mis à jour"})
    except Exception as e:
        db_session.session.rollback()
        print(f"Erreur lors du commit: {e}", flush=True)
        return jsonify({"error": f"Erreur lors de la mise à jour: {str(e)}"}), 500

# DELETE /users/<id> — admin uniquement
@users_crud.route("/<int:user_id>", methods=["DELETE"])
@require_jwt
def delete_user(user_id):
    if not request.is_admin or user_id != request.user_id:
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