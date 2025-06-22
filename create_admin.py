from app import app, db, Admin # Ensure Admin is imported from app.py
from werkzeug.security import generate_password_hash

def create_admin():
    username = input("Medic Adrenaline: ")
    password = input("MedicAdrenaline@123: ")
    password_hash = generate_password_hash(password)

    with app.app_context():
        existing_admin = Admin.query.filter_by(username=username).first()
        if existing_admin:
            print("Admin with this username already exists.")
            return

        new_admin = Admin(username=username, password_hash=password_hash)
        db.session.add(new_admin)
        db.session.commit()
        print("Admin user created successfully!")

if __name__ == "__main__":
    create_admin()