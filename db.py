from flask import request, jsonify
import jwt
import os
from functools import wraps
from flask_sqlalchemy  import SQLAlchemy
from sqlalchemy.sql import func

db_session = SQLAlchemy()


JWT_SECRET = os.getenv("SECRET_KEY")

def require_jwt(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
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

        request.user_id = payload["user_id"]
        request.is_admin = payload.get("is_admin", False)
        return f(*args, **kwargs)

    return decorated_function



class User(db_session.Model):
    __tablename__ = 'users'
    id = db_session.Column(db_session.Integer, primary_key=True)
    firstname = db_session.Column(db_session.String(100), nullable=False)
    lastname = db_session.Column(db_session.String(100), nullable=False)
    email = db_session.Column(db_session.String(255), unique=True, nullable=False)
    # Cette colonne stocke le HASH du mot de passe, pas le mot de passe en clair
    password = db_session.Column(db_session.String(255), nullable=False)
    is_admin = db_session.Column(db_session.Boolean, nullable=False, default=False)

    photo = db_session.Column(db_session.LargeBinary, nullable=True)

    # Timestamps gérés par la base de données
    # server_default indique à SQLAlchemy de laisser la DB gérer la valeur par défaut
    created_at = db_session.Column(db_session.DateTime(timezone=False), server_default=func.now(), nullable=False)
    updated_at = db_session.Column(db_session.DateTime(timezone=False), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Timestamps gérés par l'application 
    last_login = db_session.Column(db_session.DateTime(timezone=False), nullable=True)
    last_failed = db_session.Column(db_session.DateTime(timezone=False), nullable=True)

    n_password_failures = db_session.Column(db_session.Integer, nullable=False, default=0)



    # Optionnel mais recommandé : Intégrer la logique de mot de passe ici
    # Nécessite d'importer PasswordHasher de argon2
    # from argon2 import PasswordHasher, exceptions
    # ph = PasswordHasher()

    # def set_password(self, password_plaintext):
    #     self.password = self.ph.hash(password_plaintext)

    # def check_password(self, password_plaintext):
    #     if not self.password: # S'il n'y a pas de hash (ne devrait pas arriver)
    #         return False
    #     try:
    #         return self.ph.verify(self.password, password_plaintext)
    #     except exceptions.VerifyMismatchError:
    #         return False
    #     except Exception as e: # Autres erreurs potentiel Argon2
    #         # Logguer l'erreur e
    #         print(f"Argon2 verification error: {e}")
    #         return False