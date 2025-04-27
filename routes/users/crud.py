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
    print(f"Données reçues pour update_user: {list(data.keys())}")
    
    user.firstname = data.get("firstname", user.firstname)
    user.lastname = data.get("lastname", user.lastname)
    user.email = data.get("email", user.email)
    user.is_admin = data.get("is_admin", user.is_admin)
    
    # Vérifier si photo existe et n'est pas None
    if data.get("photo") is not None:
        print(f"Photo trouvée dans les données: {type(data['photo'])}")
        
        try:
            # Cas 1: La photo est None (suppression de la photo)
            if data['photo'] is None:
                print("Suppression de la photo")
                user.photo = None
            
            # Cas 2: La photo est une chaîne (format data URL ou base64)
            elif isinstance(data["photo"], str):
                print(f"Photo est une chaîne de longueur {len(data['photo'])}")
                
                if "," in data["photo"]:
                    print("Format data URL détecté, extraction partie base64")
                    base64_part = data["photo"].split(",")[1]
                    user.photo = base64.b64decode(base64_part)
                else:
                    print("Décodage direct de la chaîne base64")
                    user.photo = base64.b64decode(data["photo"])
            
            # Cas 3: Tableau d'octets reçu directement (bytes ou list)
            elif isinstance(data["photo"], (list, bytes)):
                print(f"Photo est un tableau d'octets de longueur {len(data['photo'])}")
                
                # Si c'est une liste d'entiers (octets), la convertir en bytes
                if isinstance(data["photo"], list):
                    # Vérifier que tous les éléments sont des entiers entre 0 et 255
                    if all(isinstance(b, int) and 0 <= b <= 255 for b in data["photo"]):
                        print("Conversion de la liste d'octets en bytes")
                        user.photo = bytes(data["photo"])
                    else:
                        print("Format de liste invalide pour une photo")
                        raise ValueError("Format de liste invalide pour une photo")
                else:
                    # Déjà au format bytes
                    user.photo = data["photo"]
            
            # Cas 4: Format inconnu
            else:
                print(f"Format de photo non reconnu: {type(data['photo'])}")
                raise ValueError(f"Format de photo non pris en charge: {type(data['photo'])}")
            
            if user.photo:
                print(f"Photo traitée avec succès: {len(user.photo)} bytes")
            else:
                print("Photo supprimée ou non définie")
                
        except Exception as e:
            print(f"Erreur lors du traitement de la photo: {e}")
            return jsonify({"error": f"Erreur lors du traitement de la photo: {str(e)}"}), 400
    else:
        print("Aucune photo trouvée dans les données")
        
    try:
        # Commit explicite
        db_session.session.commit()
        print("Commit réussi, utilisateur mis à jour")
        return jsonify({"message": "Utilisateur mis à jour"})
    except Exception as e:
        db_session.session.rollback()
        print(f"Erreur lors du commit: {e}")
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