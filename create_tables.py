from app import app, db, Admin

with app.app_context():
    # Explicitly reference Admin so it's not skipped
    _ = Admin
    db.create_all()
    print("Tables created successfully.")