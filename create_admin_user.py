"""
Create an admin user for the SMTP server if none exists
"""
import os
import sys
from werkzeug.security import generate_password_hash

# Add the current directory to the Python path
sys.path.insert(0, os.path.abspath('.'))

# Import the application
from app import app, db
from models import User

def create_admin_user(username="admin", email="admin@example.com", password="password123"):
    """Create an admin user if none exists"""
    with app.app_context():
        # Check if any user exists
        user_count = User.query.count()
        
        if user_count == 0:
            print(f"Creating admin user: {email}")
            
            # Create a new admin user
            admin_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                daily_quota=10000  # Higher quota for admin
            )
            
            db.session.add(admin_user)
            db.session.commit()
            
            print(f"Admin user created with ID: {admin_user.id}")
            return True
        else:
            admin = User.query.filter_by(email=email).first()
            if admin:
                print(f"Admin user already exists with ID: {admin.id}")
                # Update password if needed
                if not admin.password_hash or len(admin.password_hash) < 50:  # Assuming a valid hash is longer
                    admin.password_hash = generate_password_hash(password)
                    db.session.commit()
                    print("Admin password has been updated")
            else:
                print("Users exist, but no admin. You may want to check existing users.")
            return False

if __name__ == "__main__":
    create_admin_user()