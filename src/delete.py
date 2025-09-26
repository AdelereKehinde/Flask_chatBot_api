from flask_api.src.database import db
from flask_api.src.main import app

with app.app_context():
    db.drop_all()   # deletes all tables
    db.create_all() # recreates empty tables
