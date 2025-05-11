from app import app, db
from app import Admin  # Ensure Admin is imported from app.py
from werkzeug.security import generate_password_hash

def create_admin():
    username = input("Enter admin username: ")
    password = input("Enter admin password: ")
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