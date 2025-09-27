from datetime import datetime, UTC, timedelta
from database import db


class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)

    otp = db.Column(db.String(6))
    otp_expiry = datetime.now(UTC) + timedelta(minutes=10)

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(UTC)
    )

    chats = db.relationship("Chat", backref="user", lazy=True)


class Chat(db.Model):
    __tablename__ = "chat"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)

    # Store as JSON string of messages
    messages = db.Column(db.Text)

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(UTC)
    )
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC)
    )

class AdminActivity(db.Model):
    __tablename__ = "admin_activities"

    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)   # e.g. "login", "register", "chat", "admin_login"
    user_id = db.Column(db.String(50), nullable=True) # can be "admin" or actual user_id
    email = db.Column(db.String(120), nullable=True)
    detail = db.Column(db.Text, nullable=True)        # extra info like "user registered", chat msg
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<AdminActivity {self.type} by {self.email} at {self.timestamp}>" 
    
class Admin(db.Model):
    __tablename__ = "admins"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Admin {self.email}>"    
