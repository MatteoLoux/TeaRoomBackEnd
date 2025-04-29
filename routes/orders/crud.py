from flask import Blueprint, request, jsonify, send_file
from db import db_session, require_jwt, Order, User, Tea, Goodie
import json
import io
import os
from datetime import datetime
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64


orders_crud = Blueprint('orders_crud', __name__)

# Clé AES - À STOCKER DE MANIÈRE SÉCURISÉE (variable d'environnement)
AES_KEY = os.getenv("AES_KEY", "ThisIsA32ByteKeyForAES-256Cipher!").encode()[:32]
# IV (vecteur d'initialisation) - Devrait être différent pour chaque chiffrement dans un système de production
AES_IV = os.getenv("AES_IV", "ThisIsA16BytesIV!").encode()[:16]

def encrypt_pdf(pdf_data):
    """Chiffre les données PDF avec AES"""
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Padding pour AES (multiple de 16 octets)
    pad_length = 16 - (len(pdf_data) % 16)
    padded_data = pdf_data + bytes([pad_length]) * pad_length
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def decrypt_pdf(encrypted_data):
    """Déchiffre les données PDF avec AES"""
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Enlever le padding
    pad_length = decrypted_data[-1]
    return decrypted_data[:-pad_length]

def generate_pdf_from_order(order):
    """Génère un PDF à partir des données de commande"""
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    
    # Récupérer les informations de l'utilisateur
    user = User.query.get(order.user_id)
    client_name = f"{user.firstname} {user.lastname}" if user else f"Client ID: {order.user_id}"
    
    # En-tête
    p.setFont("Helvetica-Bold", 16)
    p.drawString(30, 750, "TeaRoom - Facture")
    
    # Informations client et commande
    p.setFont("Helvetica", 12)
    p.drawString(30, 720, f"Commande #{order.id}")
    p.drawString(30, 700, f"Date: {order.created_at.strftime('%d/%m/%Y %H:%M')}")
    p.drawString(30, 680, f"Client: {client_name}")
    
    # Contenu de la commande
    p.drawString(30, 650, "Détails de la commande:")
    y = 630
    total = 0
    
    # Vérifier si content est une liste directement ou s'il contient une clé 'items'
    items = []
    if isinstance(order.content, list):
        items = order.content
    elif isinstance(order.content, dict) and "items" in order.content:
        items = order.content["items"]
    
    for item in items:
        product_id = item.get("product_id")
        quantity = int(item.get("quantity", 1))
        
        # Récupérer les détails du produit depuis la base de données
        product = Tea.query.get(product_id)
        if not product:
            product = Goodie.query.get(product_id)
        
        if product:
            name = product.name
            price = float(product.price)
        else:
            name = f"Produit #{product_id}"
            price = 0
            
        subtotal = price * quantity
        total += subtotal
        
        p.drawString(30, y, f"{name} x {quantity} = {subtotal:.2f} €")
        y -= 20
    
    # Total
    p.setFont("Helvetica-Bold", 14)
    p.drawString(30, y-20, f"Total: {total:.2f} €")
    
    # Pied de page
    p.setFont("Helvetica-Italic", 10)
    p.drawString(30, 30, "Merci pour votre commande chez TeaRoom!")
    
    p.showPage()
    p.save()
    
    buffer.seek(0)
    return buffer.getvalue()

# GET /orders — admin uniquement
@orders_crud.route("/", methods=["GET"], strict_slashes=False)
@require_jwt
def list_orders():
    if not request.is_admin:
        # Si non admin, retourner uniquement ses propres commandes
        orders = Order.query.filter_by(user_id=request.user_id).all()
    else:
        # Admin peut voir toutes les commandes
        orders = Order.query.all()
    
    return jsonify([
        {
            "id": o.id,
            "user_id": o.user_id,
            "created_at": o.created_at,
            "is_done": o.is_done,
            "content": o.content,
            "has_pdf": o.encrypted_pdf is not None
        } for o in orders
    ])

# GET /orders/<int:order_id> — autorisé à l'utilisateur concerné ou admin
@orders_crud.route("/<int:order_id>", methods=["GET"])
@require_jwt
def get_order(order_id):
    order = Order.query.get(order_id)
    if not order:
        return jsonify({"error": "Commande non trouvée"}), 404
    
    # Vérifier si l'utilisateur a le droit d'accéder à cette commande
    if order.user_id != request.user_id and not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403
    
    return jsonify({
        "id": order.id,
        "user_id": order.user_id,
        "created_at": order.created_at,
        "is_done": order.is_done,
        "content": order.content,
        "has_pdf": order.encrypted_pdf is not None
    })

# POST /orders — création d'une commande
@orders_crud.route("/", methods=["POST"], strict_slashes=False)
@require_jwt
def create_order():
    data = request.get_json()
    try:
        # Validation des données obligatoires
        if not "content" in data:
            return jsonify({"error": "Le contenu de la commande est obligatoire"}), 400
        
        # Créer la commande
        order = Order(
            user_id=request.user_id,
            content=data["content"],
            is_done=data.get("is_done", False)
        )
        
        db_session.session.add(order)
        db_session.session.flush()  # Pour obtenir l'ID avant le commit
        
        # Générer et chiffrer le PDF
        # Commentez temporairement cette section pour tester
        try:
            pdf_data = generate_pdf_from_order(order)
            encrypted_pdf = encrypt_pdf(pdf_data)
            order.encrypted_pdf = encrypted_pdf
            print(f"PDF généré et chiffré pour la commande {order.id}", flush=True)
        except Exception as e:
            print(f"Erreur lors de la génération du PDF: {str(e)}", flush=True)
            # Continue sans PDF plutôt que d'échouer complètement
        
        db_session.session.commit()
        
        return jsonify({"id": order.id}), 201
    
    except Exception as e:
        db_session.session.rollback()
        return jsonify({"error": f"Erreur lors de la création de la commande: {str(e)}"}), 500

# PUT /orders/<int:order_id> — mise à jour d'une commande (admin uniquement)
@orders_crud.route("/<int:order_id>", methods=["PUT"])
@require_jwt
def update_order(order_id):
    if not request.is_admin:
        return jsonify({"error": "Accès interdit, admin uniquement"}), 403
    
    order = Order.query.get(order_id)
    if not order:
        return jsonify({"error": "Commande non trouvée"}), 404
    
    try:
        data = request.get_json()
        content_updated = False
        
        if "content" in data:
            order.content = data["content"]
            content_updated = True
            
        if "is_done" in data:
            order.is_done = data["is_done"]
        
        # Régénérer le PDF si le contenu a été modifié
        if content_updated:
            try:
                pdf_data = generate_pdf_from_order(order)
                encrypted_pdf = encrypt_pdf(pdf_data)
                order.encrypted_pdf = encrypted_pdf
                print(f"PDF régénéré pour la commande {order.id}", flush=True)
            except Exception as e:
                print(f"Erreur lors de la régénération du PDF: {str(e)}", flush=True)
        
        db_session.session.commit()
        return jsonify({"message": "Commande mise à jour"})
    
    except Exception as e:
        db_session.session.rollback()
        return jsonify({"error": f"Erreur lors de la mise à jour: {str(e)}"}), 500

# DELETE /orders/<int:order_id> — suppression d'une commande (admin uniquement)
@orders_crud.route("/<int:order_id>", methods=["DELETE"])
@require_jwt
def delete_order(order_id):
    if not request.is_admin:
        return jsonify({"error": "Accès interdit, admin uniquement"}), 403
    
    order = Order.query.get(order_id)
    if not order:
        return jsonify({"error": "Commande non trouvée"}), 404
    
    db_session.session.delete(order)
    db_session.session.commit()
    return jsonify({"message": "Commande supprimée"})

# GET /orders/user — obtenir les commandes de l'utilisateur connecté
@orders_crud.route("/user", methods=["GET"])
@require_jwt
def get_user_orders():
    orders = Order.query.filter_by(user_id=request.user_id).all()
    
    return jsonify([
        {
            "id": o.id,
            "user_id": o.user_id,
            "created_at": o.created_at,
            "is_done": o.is_done,
            "content": o.content,
            "has_pdf": o.encrypted_pdf is not None
        } for o in orders
    ])

# GET /orders/<int:order_id>/pdf — télécharger le PDF de la commande
@orders_crud.route("/<int:order_id>/pdf", methods=["GET"])
@require_jwt
def get_order_pdf(order_id):
    order = Order.query.get(order_id)
    if not order:
        return jsonify({"error": "Commande non trouvée"}), 404
    
    # Vérifier si l'utilisateur a le droit d'accéder à cette commande
    if order.user_id != request.user_id and not request.is_admin:
        return jsonify({"error": "Accès interdit"}), 403
    
    if not order.encrypted_pdf:
        return jsonify({"error": "Aucun PDF disponible pour cette commande"}), 404
    
    try:
        # Déchiffrer le PDF
        decrypted_pdf = decrypt_pdf(order.encrypted_pdf)
        
        # Créer un objet BytesIO pour renvoyer le PDF
        pdf_buffer = io.BytesIO(decrypted_pdf)
        pdf_buffer.seek(0)
        
        # Générer un nom de fichier
        filename = f"facture_tearoom_{order.id}_{datetime.now().strftime('%Y%m%d')}.pdf"
        
        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({"error": f"Erreur lors du déchiffrement du PDF: {str(e)}"}), 500
