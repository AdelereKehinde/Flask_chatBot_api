# src/admin.py
import os
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta, datetime
from database import db
from model import User, Chat
from dotenv import load_dotenv

load_dotenv()

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

# Simple in-memory activity & notifications store for admin overview (persist if you want DB)
# NOTE: For production use persistent DB table.
_admin_activity = []       # list of dicts {type, user_id, email, timestamp, detail}
_admin_notifications = []  # list of dicts {id, message, created_at, by_admin}

def _is_admin_identity(identity):
    return identity == "admin"

def _record_activity(entry):
    """Record activity for admin UI. Keep only last N events to avoid memory growth."""
    entry['timestamp'] = datetime.utcnow().isoformat()
    _admin_activity.insert(0, entry)
    # keep last 200
    if len(_admin_activity) > 200:
        _admin_activity.pop()

@admin_bp.route("/login", methods=["POST"])
def admin_login():
    """
    POST /api/admin/login
    body: { "email": "...", "password": "..." }
    Returns admin JWT if credentials match env ADMIN_EMAIL & ADMIN_PASSWORD
    """
    data = request.get_json() or {}
    email = data.get("email", "")
    password = data.get("password", "")

    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if not admin_email or not admin_password:
        return jsonify({"error": "Admin credentials not configured"}), 500

    if email == admin_email and password == admin_password:
        token = create_access_token(identity="admin", expires_delta=timedelta(hours=12))
        return jsonify({"access_token": token}), 200

    return jsonify({"error": "Invalid admin credentials"}), 401

@admin_bp.route("/users", methods=["GET"])
@jwt_required()
def list_users():
    """
    GET /api/admin/users
    Returns list of users for admin
    """
    if not _is_admin_identity(get_jwt_identity()):
        return jsonify({"error": "Not authorized"}), 403

    users = User.query.order_by(User.created_at.desc()).all()
    users_list = []
    for u in users:
        users_list.append({
            "id": u.id,
            "email": u.email,
            "name": u.name,
            "is_verified": u.is_verified,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        })
    return jsonify({"users": users_list}), 200

@admin_bp.route("/user/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):
    if not _is_admin_identity(get_jwt_identity()):
        return jsonify({"error": "Not authorized"}), 403

    u = User.query.get(user_id)
    if not u:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "id": u.id,
        "email": u.email,
        "name": u.name,
        "is_verified": u.is_verified,
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "chats": u.chats and [ {"id": c.id, "title": c.title} for c in u.chats ] or []
    }), 200

@admin_bp.route("/user/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    if not _is_admin_identity(get_jwt_identity()):
        return jsonify({"error": "Not authorized"}), 403

    u = User.query.get(user_id)
    if not u:
        return jsonify({"error": "User not found"}), 404

    # Optionally delete user's chats first (if FK constraints)
    Chat.query.filter_by(user_id=user_id).delete()
    db.session.delete(u)
    db.session.commit()

    _record_activity({"type": "delete_user", "user_id": user_id, "email": u.email, "detail": "deleted by admin"})
    return jsonify({"message": "User deleted"}), 200

@admin_bp.route("/activity", methods=["GET"])
@jwt_required()
def get_activity():
    """
    GET /api/admin/activity
    Recent activity: registration, login, chat events, deletion etc.
    """
    if not _is_admin_identity(get_jwt_identity()):
        return jsonify({"error": "Not authorized"}), 403

    # optional query ?limit=50
    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify({"activity": _admin_activity[:limit]}), 200

@admin_bp.route("/notifications", methods=["GET"])
@jwt_required()
def get_notifications():
    if not _is_admin_identity(get_jwt_identity()):
        return jsonify({"error": "Not authorized"}), 403
    return jsonify({"notifications": _admin_notifications}), 200

@admin_bp.route("/notifications", methods=["POST"])
@jwt_required()
def post_notification():
    """
    POST /api/admin/notifications
    body: { "message": "..." }
    """
    if not _is_admin_identity(get_jwt_identity()):
        return jsonify({"error": "Not authorized"}), 403

    data = request.get_json() or {}
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "Message required"}), 400

    note = {
        "id": len(_admin_notifications) + 1,
        "message": message,
        "created_at": datetime.utcnow().isoformat(),
        "by_admin": True
    }
    _admin_notifications.insert(0, note)
    # keep last 200
    if len(_admin_notifications) > 200:
        _admin_notifications.pop()

    # record activity too
    _record_activity({"type": "notification", "detail": message})

    return jsonify({"notification": note}), 201

def record_admin_activity(entry):
    _record_activity(entry)
