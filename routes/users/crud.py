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
    """Cache les données d'identification dans les pixels de l'image en utilisant la technique LSB"""
    if timestamp is None:
        timestamp = int(time.time())
    
    try:
        # Créer les données à cacher
        data = {
            "user_id": user_id,
            "timestamp": timestamp,
            "signature": "TeaRoom"
        }
        
        # Convertir en JSON puis en base64
        json_data = json.dumps(data)
        encoded_data = base64.b64encode(json_data.encode()).decode()
        
        # Convertir les données en bits
        binary_data = ''.join(format(ord(char), '08b') for char in encoded_data)
        
        print(f"Données à cacher: {json_data} ({len(binary_data)} bits)", flush=True)
        
        # Ouvrir l'image et la traiter
        img = Image.open(io.BytesIO(image_bytes))
        original_format = img.format
        print(f"Image ouverte: {img.format}, {img.size}, {img.mode}", flush=True)
        
        # NOUVEAU: Redimensionner l'image si elle est trop grande
        MAX_SIZE = (1200, 1200)  # Taille maximale raisonnable
        if img.width > MAX_SIZE[0] or img.height > MAX_SIZE[1]:
            print(f"Redimensionnement de l'image de {img.size} à {MAX_SIZE}", flush=True)
            img.thumbnail(MAX_SIZE, Image.LANCZOS)
            print(f"Nouvelle taille: {img.size}", flush=True)
        
        # Convertir en RGB si nécessaire
        if img.mode != 'RGB':
            print(f"Conversion de {img.mode} vers RGB", flush=True)
            img = img.convert('RGB')
            
        # SIMPLIFIÉ: Approche plus efficace pour manipuler les pixels
        width, height = img.size
        max_bits = width * height * 3  # 3 canaux (R,G,B) par pixel
        
        if len(binary_data) > max_bits:
            print(f"Image trop petite: {len(binary_data)} bits > {max_bits} disponibles", flush=True)
            # Au lieu de lever une erreur, simplement retourner l'image originale
            return image_bytes
        
        # OPTIMISÉ: Traiter les pixels par petits morceaux pour économiser la mémoire
        data_index = 0
        for y in range(height):
            if data_index >= len(binary_data):
                break
                
            for x in range(width):
                if data_index >= len(binary_data):
                    break
                    
                pixel = list(img.getpixel((x, y)))
                
                # Modifier jusqu'à 3 bits par pixel (un pour chaque canal RGB)
                for i in range(min(3, len(pixel))):
                    if data_index < len(binary_data):
                        # Modifier le bit de poids faible
                        new_bit = int(binary_data[data_index])
                        pixel[i] = (pixel[i] & ~1) | new_bit
                        data_index += 1
                
                img.putpixel((x, y), tuple(pixel))
        
        # Enregistrer l'image modifiée
        output = io.BytesIO()
        save_format = original_format if original_format else 'JPEG'
        
        if save_format == 'JPEG':
            # Utiliser une qualité élevée pour JPEG
            img.save(output, format=save_format, quality=95)
        else:
            img.save(output, format=save_format)
        
        print("Stéganographie terminée avec succès", flush=True)
        return output.getvalue()
        
    except Exception as e:
        print(f"Erreur lors de l'encodage des pixels: {str(e)}", flush=True)
        import traceback
        traceback.print_exc(flush=True)
        # Retourner l'image originale en cas d'erreur
        return image_bytes

def decode_steganography_data(image_bytes):
    """Récupère les données cachées dans les pixels de l'image"""
    try:
        # Vérifier d'abord s'il y a des métadonnées (ancienne méthode)
        img = Image.open(io.BytesIO(image_bytes))
        print(f"Décodage image: {img.format}, {img.size}, {img.mode}", flush=True)
        
        if "TeaRoom" in img.info:
            encoded_data = img.info["TeaRoom"]
            json_data = base64.b64decode(encoded_data).decode()
            data = json.loads(json_data)
            
            if data.get("signature") == "TeaRoom":
                return data
        
        # NOUVEAU: Redimensionner l'image si trop grande avant décodage
        MAX_SIZE = (1200, 1200)
        if img.width > MAX_SIZE[0] or img.height > MAX_SIZE[1]:
            print(f"Redimensionnement pour décodage de {img.size} à {MAX_SIZE}", flush=True)
            img.thumbnail(MAX_SIZE, Image.LANCZOS)
        
        # Convertir en RGB si nécessaire
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # OPTIMISÉ: Traiter les pixels pixel par pixel au lieu de tout charger en mémoire
        width, height = img.size
        binary_data = ""
        
        for y in range(height):
            for x in range(width):
                pixel = img.getpixel((x, y))
                
                for i in range(min(3, len(pixel))):  # Limité à RGB
                    binary_data += str(pixel[i] & 1)  # Récupérer le LSB
                
                # Vérifier périodiquement si nous avons trouvé une chaîne valide
                if len(binary_data) % 8 == 0 and len(binary_data) >= 672:  # Taille approximative des données encodées
                    # Essayer de décoder progressivement
                    try:
                        # Convertir les bits en caractères
                        chars = ''.join([chr(int(binary_data[i:i+8], 2)) for i in range(0, len(binary_data), 8)])
                        # Essayer de décoder en base64 puis en JSON
                        json_data = base64.b64decode(chars).decode('utf-8', errors='ignore')
                        data = json.loads(json_data)
                        
                        # Vérifier la signature
                        if data.get("signature") == "TeaRoom":
                            print(f"Données trouvées après lecture de {x*y} pixels", flush=True)
                            return data
                    except:
                        # Continuer l'extraction si le décodage échoue
                        pass
                
                # Limiter la longueur maximale pour éviter les problèmes de mémoire
                if len(binary_data) > 10000:
                    binary_data = binary_data[-10000:]
        
        print("Aucune donnée valide trouvée dans les pixels", flush=True)
        return None
    except Exception as e:
        print(f"Erreur lors du décodage des pixels: {str(e)}", flush=True)
        import traceback
        traceback.print_exc(flush=True)
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

# Route pour appliquer la stéganographie à toutes les photos existantes
@users_crud.route("/apply-steno", methods=["POST"])
@require_jwt
def apply_steganography_to_all():
    """
    Applique la stéganographie à toutes les photos existantes
    """
    if not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403
    
    print("Début de l'application de stéganographie sur toutes les photos", flush=True)
    users_with_photos = User.query.filter(User.photo != None).all()
    processed_count = 0
    error_count = 0
    
    for user in users_with_photos:
        try:
            print(f"Traitement de la photo de l'utilisateur {user.id}", flush=True)
            # Vérifier si des métadonnées existent déjà
            metadata = decode_steganography_data(user.photo)
            
            if not metadata:
                print(f"Pas de métadonnées trouvées, application de la stéganographie", flush=True)
                marked_image = encode_steganography_data(user.photo, user.id, int(time.time()))
                user.photo = marked_image
                processed_count += 1
            else:
                print(f"Métadonnées existantes: {metadata}", flush=True)
        except Exception as e:
            error_count += 1
            print(f"Erreur pour l'utilisateur {user.id}: {str(e)}", flush=True)
            
    # Sauvegarder les modifications
    db_session.session.commit()
    print(f"Stéganographie appliquée: {processed_count} photos traitées, {error_count} erreurs", flush=True)
    
    return jsonify({
        "success": True,
        "processed": processed_count,
        "errors": error_count,
        "total": len(users_with_photos)
    })