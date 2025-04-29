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
import sys
import traceback


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
    print("  DÉBUT generate_pdf_from_order", flush=True)
    
    try:
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        
        # Récupérer les informations de l'utilisateur
        print("  RECHERCHE UTILISATEUR", flush=True)
        user = User.query.get(order.user_id)
        print(f"  UTILISATEUR TROUVÉ: {user is not None}", flush=True)
        client_name = f"{user.firstname} {user.lastname}" if user else f"Client ID: {order.user_id}"
        
        # En-tête
        print("  CRÉATION EN-TÊTE", flush=True)
        p.setFont("Helvetica-Bold", 16)
        p.drawString(30, 750, "TeaRoom - Facture")
        
        # Informations client et commande
        p.setFont("Helvetica", 12)
        p.drawString(30, 720, f"Commande #{order.id}")
        p.drawString(30, 700, f"Date: {order.created_at.strftime('%d/%m/%Y %H:%M')}")
        p.drawString(30, 680, f"Client: {client_name}")
        
        # Contenu de la commande
        print("  TRAITEMENT CONTENU", flush=True)
        p.drawString(30, 650, "Détails de la commande:")
        y = 630
        total = 0
        
        # Vérifier si content est une liste directement ou s'il contient une clé 'items'
        items = []
        if isinstance(order.content, list):
            print("  CONTENU EST UNE LISTE", flush=True)
            items = order.content
        elif isinstance(order.content, dict) and "items" in order.content:
            print("  CONTENU EST UN DICT AVEC ITEMS", flush=True)
            items = order.content["items"]
        else:
            print(f"  FORMAT CONTENU NON RECONNU: {type(order.content)}", flush=True)
        
        print(f"  NOMBRE D'ITEMS: {len(items)}", flush=True)
        
        for i, item in enumerate(items):
            print(f"  TRAITEMENT ITEM {i}", flush=True)
            product_id = item.get("product_id")
            quantity = int(item.get("quantity", 1))
            print(f"  - PRODUCT_ID: {product_id}, QUANTITY: {quantity}", flush=True)
            
            # Récupérer les détails du produit depuis la base de données
            product = Tea.query.get(product_id)
            if not product:
                print(f"  - PAS UN THÉ, RECHERCHE GOODIE", flush=True)
                product = Goodie.query.get(product_id)
            
            if product:
                print(f"  - PRODUIT TROUVÉ: {product.name}", flush=True)
                name = product.name
                price = float(product.price)
            else:
                print(f"  - PRODUIT NON TROUVÉ", flush=True)
                name = f"Produit #{product_id}"
                price = 0
                
            subtotal = price * quantity
            total += subtotal
            
            p.drawString(30, y, f"{name} x {quantity} = {subtotal:.2f} €")
            y -= 20
        
        # Total
        print("  FINALISATION PDF", flush=True)
        p.setFont("Helvetica-Bold", 14)
        p.drawString(30, y-20, f"Total: {total:.2f} €")
        
        # Pied de page
        p.setFont("Helvetica", 10)
        p.drawString(30, 30, "Merci pour votre commande chez TeaRoom!")
        
        p.showPage()
        p.save()
        
        buffer.seek(0)
        print("  PDF GÉNÉRÉ AVEC SUCCÈS", flush=True)
        return buffer.getvalue()
    
    except Exception as e:
        print(f"  ERREUR GÉNÉRATION PDF: {str(e)}", flush=True)
        traceback.print_exc(file=sys.stdout)
        raise

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
            "has_pdf": o.pdf_invoice is not None
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
        "has_pdf": order.pdf_invoice is not None
    })

# POST /orders — création d'une commande
@orders_crud.route("/", methods=["POST"], strict_slashes=False)
@require_jwt
def create_order():
    print("===== DÉBUT CREATE_ORDER =====", flush=True)
    
    try:
        data = request.get_json()
        print(f"DONNÉES REÇUES: {json.dumps(data)}", flush=True)
    except Exception as e:
        print(f"ERREUR PARSING JSON: {str(e)}", flush=True)
        return jsonify({"error": "Données JSON invalides"}), 400
    
    try:
        # Validation des données obligatoires
        if not "content" in data:
            print("ERREUR: Clé 'content' manquante", flush=True)
            return jsonify({"error": "Le contenu de la commande est obligatoire"}), 400
        
        print(f"USER_ID: {request.user_id}", flush=True)
        print(f"CONTENT TYPE: {type(data['content'])}", flush=True)
        
        # Créer la commande
        try:
            order = Order(
                user_id=request.user_id,
                content=data["content"],
                is_done=data.get("is_done", False)
            )
            print("COMMANDE CRÉÉE EN MÉMOIRE", flush=True)
        except Exception as e:
            print(f"ERREUR CRÉATION OBJET: {str(e)}", flush=True)
            traceback.print_exc(file=sys.stdout)
            return jsonify({"error": f"Erreur lors de la création de l'objet commande: {str(e)}"}), 500
        
        try:
            db_session.session.add(order)
            print("COMMANDE AJOUTÉE À LA SESSION", flush=True)
            db_session.session.flush()
            print(f"COMMANDE FLUSH, ID: {order.id}", flush=True)
        except Exception as e:
            print(f"ERREUR DB FLUSH: {str(e)}", flush=True)
            traceback.print_exc(file=sys.stdout)
            db_session.session.rollback()
            return jsonify({"error": f"Erreur base de données: {str(e)}"}), 500
        
        # Générer et chiffrer le PDF
        try:
            print("DÉBUT GÉNÉRATION PDF", flush=True)
            
            # Déboguer le contenu de la commande
            print(f"CONTENU COMMANDE: {json.dumps(order.content)}", flush=True)
            
            # Afficher details des produits
            if isinstance(order.content, list):
                for i, item in enumerate(order.content):
                    print(f"PRODUIT {i}: {json.dumps(item)}", flush=True)
                    product_id = item.get('product_id')
                    tea = Tea.query.get(product_id)
                    goodie = Goodie.query.get(product_id)
                    print(f"  - TEA TROUVÉ: {tea is not None}", flush=True)
                    print(f"  - GOODIE TROUVÉ: {goodie is not None}", flush=True)
            
            pdf_data = generate_pdf_from_order(order)
            print(f"PDF GÉNÉRÉ, TAILLE: {len(pdf_data)} OCTETS", flush=True)
            
            encrypted_pdf = encrypt_pdf(pdf_data)
            print(f"PDF CHIFFRÉ, TAILLE: {len(encrypted_pdf)} OCTETS", flush=True)
            
            order.pdf_invoice = encrypted_pdf
            print(f"PDF ASSIGNÉ À LA COMMANDE", flush=True)
            
        except Exception as e:
            print(f"ERREUR PDF: {str(e)}", flush=True)
            traceback.print_exc(file=sys.stdout)
            # Continuer sans PDF
        
        try:
            db_session.session.commit()
            print(f"COMMANDE SAUVEGARDÉE, ID: {order.id}", flush=True)
        except Exception as e:
            print(f"ERREUR COMMIT: {str(e)}", flush=True)
            traceback.print_exc(file=sys.stdout)
            db_session.session.rollback()
            return jsonify({"error": f"Erreur lors de l'enregistrement: {str(e)}"}), 500
        
        print("===== FIN CREATE_ORDER =====", flush=True)
        return jsonify({"id": order.id}), 201
    
    except Exception as e:
        print(f"ERREUR GLOBALE: {str(e)}", flush=True)
        traceback.print_exc(file=sys.stdout)
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
                order.pdf_invoice = encrypted_pdf
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
            "has_pdf": o.pdf_invoice is not None
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
    
    if not order.pdf_invoice:
        return jsonify({"error": "Aucun PDF disponible pour cette commande"}), 404
    
    try:
        # Convertir en bytes si ce n'est pas déjà le bon type
        pdf_invoice_bytes = bytes(order.pdf_invoice) if hasattr(order.pdf_invoice, '__bytes__') else order.pdf_invoice
        
        # Log pour debug
        print(f"TYPE AVANT CONVERSION: {type(order.pdf_invoice)}", flush=True)
        print(f"TYPE APRÈS CONVERSION: {type(pdf_invoice_bytes)}", flush=True)
        
        # Déchiffrer le PDF
        decrypted_pdf = decrypt_pdf(pdf_invoice_bytes)
        
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
        print(f"ERREUR PDF: {str(e)}", flush=True)
        traceback.print_exc(file=sys.stdout)
        return jsonify({"error": f"Erreur lors du déchiffrement du PDF: {str(e)}"}), 500
