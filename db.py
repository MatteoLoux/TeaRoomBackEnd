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

class Cart(db_session.Model):
    __tablename__ = 'carts'

    id = db_session.Column(db_session.Integer, primary_key=True)
    created_at = db_session.Column(db_session.DateTime(timezone=False), server_default=func.now(), nullable=False)
    updated_at = db_session.Column(db_session.DateTime(timezone=False), server_default=func.now(), onupdate=func.now(), nullable=False)

    user_id = db_session.Column(db_session.Integer, db_session.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    content = db_session.Column(db_session.JSON, nullable=False)
    total_amount = db_session.Column(db_session.Numeric(10, 2), nullable=True)


class Tea(db_session.Model):
    __tablename__ = 'teas'

    id = db_session.Column(db_session.Integer, primary_key=True)
    name = db_session.Column(db_session.String, nullable=False)
    price = db_session.Column(db_session.Numeric(10, 2), nullable=False)
    image = db_session.Column(db_session.LargeBinary, nullable=True)
    description = db_session.Column(db_session.Text, nullable=True)
    is_available = db_session.Column(db_session.Boolean, nullable=False, default=False)
    quantity = db_session.Column(db_session.Integer, nullable=False, default=0)


class Goodie(db_session.Model):
    __tablename__ = 'goodies'

    id = db_session.Column(db_session.Integer, primary_key=True)
    name = db_session.Column(db_session.String, nullable=False)
    price = db_session.Column(db_session.Numeric(10, 2), nullable=False)
    image = db_session.Column(db_session.LargeBinary, nullable=True)
    description = db_session.Column(db_session.Text, nullable=True)
    is_available = db_session.Column(db_session.Boolean, nullable=False, default=False)
    quantity = db_session.Column(db_session.Integer, nullable=False, default=0)