from flask import Blueprint, request, jsonify
from datetime import datetime, timezone
from db import db_session, require_jwt, Cart, Goodie, Tea
import decimal

cart_crud = Blueprint("cart_crud", __name__)

def get_total_amount(content):
    total = decimal.Decimal("0.00")
    for item in content:
        product_id = item["product_id"]
        quantity = item["quantity"]

        product = Tea.query.get(product_id)
        if product is None:
            product = Goodie.query.get(product_id)

        if product:
            total += product.price * quantity

    return round(total, 2)

# GET /cart — retourne le panier complet de l'utilisateur
@cart_crud.route("/", methods=["GET"], strict_slashes=False)
@require_jwt
def get_cart():
    user_id = request.user_id
    cart = Cart.query.filter_by(user_id=user_id).first()

    if not cart:
        return jsonify({"cart": None})

    return jsonify({
        "id": cart.id,
        "user_id": cart.user_id,
        "created_at": cart.created_at.isoformat(),
        "updated_at": cart.updated_at.isoformat(),
        "total_amount": float(cart.total_amount),
        "content": cart.content
    })

# POST /cart — ajoute un produit dans le panier
@cart_crud.route("/", methods=["POST"], strict_slashes=False)
@require_jwt
def add_to_cart():
    data = request.get_json()
    product_id = data["product_id"]
    quantity = data.get("quantity", 1)
    user_id = request.user_id

    product = Tea.query.get(product_id)
    if product is None:
        product = Goodie.query.get(product_id)

    if product is None or product.quantity < quantity:
        return jsonify({"success": False, "message": "Produit introuvable ou stock insuffisant"})

    cart = Cart.query.filter_by(user_id=user_id).first()
    now = datetime.now(timezone.utc)

    if cart is None:
        content = [{"product_id": product_id, "quantity": quantity}]
        cart = Cart(
            user_id=user_id,
            content=content,
            created_at=now,
            updated_at=now,
            total_amount=product.price * quantity
        )
        db_session.session.add(cart)
    else:
        content = cart.content or []
        item_found = False
        for item in content:
            if item["product_id"] == product_id:
                item["quantity"] += quantity
                item_found = True
                break

        if not item_found:
            content.append({"product_id": product_id, "quantity": quantity})

        cart.content = content
        cart.updated_at = now
        cart.total_amount = get_total_amount(content)

    product.quantity -= quantity
    db_session.session.commit()
    return jsonify({"success": True})

@cart_crud.route("/<int:product_id>", methods=["PUT"])
@require_jwt
def update_cart_quantity(product_id):
    data = request.get_json()
    new_quantity = data.get("quantity")
    user_id = request.user_id

    cart = Cart.query.filter_by(user_id=user_id).first()
    if cart is None:
        return jsonify({"success": False, "message": "Aucun panier trouvé"}), 404

    found = False
    content = cart.content or []
    old_quantity = 0

    for item in content:
        if item["product_id"] == product_id:
            old_quantity = item["quantity"]
            item["quantity"] = new_quantity
            found = True
            break

    if not found:
        return jsonify({"success": False, "message": "Produit non trouvé dans le panier"}), 404

    # Récupérer le produit et ajuster le stock
    product = Tea.query.get(product_id)
    if product is None:
        product = Goodie.query.get(product_id)

    if product:
        # Si new_quantity > old_quantity, on retire du stock
        # Si new_quantity < old_quantity, on ajoute au stock
        quantity_diff = old_quantity - new_quantity
        product.quantity += quantity_diff

    cart.content = content
    cart.updated_at = datetime.now(timezone.utc)
    cart.total_amount = get_total_amount(content)

    db_session.session.commit()
    return jsonify({"success": True})


# DELETE /cart/<product_id> — retire un produit du panier
@cart_crud.route("/<int:product_id>", methods=["DELETE"])
@require_jwt
def remove_product_from_cart(product_id):
    user_id = request.user_id
    cart = Cart.query.filter_by(user_id=user_id).first()

    if cart is None:
        return jsonify({"success": False, "message": "Aucun panier trouvé"}), 404

    content = cart.content or []
    updated_content = []
    product_quantity_removed = 0
    product_found = False

    for item in content:
        if item["product_id"] == product_id:
            product_quantity_removed = item["quantity"]
            product_found = True
        else:
            updated_content.append(item)

    if not product_found:
        return jsonify({"success": False, "message": "Produit non présent dans le panier"}), 404

    # remettre le stock
    product = Tea.query.get(product_id)
    if product is None:
        product = Goodie.query.get(product_id)

    if product:
        product.quantity += product_quantity_removed

    if not updated_content:
        db_session.session.delete(cart)
    else:
        cart.content = updated_content
        cart.updated_at = datetime.now(timezone.utc)
        cart.total_amount = get_total_amount(updated_content)

    db_session.session.commit()
    return jsonify({"success": True})

# DELETE /cart — vide complètement le panier
@cart_crud.route("/", methods=["DELETE"], strict_slashes=False)
@require_jwt
def clear_cart():
    user_id = request.user_id
    cart = Cart.query.filter_by(user_id=user_id).first()

    if not cart:
        return jsonify({"success": False, "message": "Aucun panier trouvé"}), 404

    # Réinjecter les quantités dans le stock
    for item in cart.content:
        product_id = item["product_id"]
        quantity = item["quantity"]
        product = Tea.query.get(product_id) or Goodie.query.get(product_id)
        if product:
            product.quantity += quantity

    db_session.session.delete(cart)
    db_session.session.commit()
    return jsonify({"success": True})
