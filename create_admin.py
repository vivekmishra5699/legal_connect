import firebase_admin
from firebase_admin import credentials, firestore, auth
import os
import sys
from datetime import datetime

def create_admin(username, email, password):
    """Create an admin user for the Legal Q&A platform using Firebase."""
    
    # Check if Firebase app is already initialized
    if not firebase_admin._apps:
        # Initialize Firebase with credentials
        cred_path = os.path.join(os.path.dirname(__file__), 'firebase.json')
        
        # Validate the file exists
        if not os.path.exists(cred_path):
            print(f"Error: Firebase credentials file not found at {cred_path}")
            return False
            
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
    
    # Initialize Firestore
    db = firestore.client()
    
    try:
        # Check if user already exists in Firestore
        user_query = db.collection('users').where('email', '==', email).limit(1).stream()
        if any(user_query):
            print(f"User with email '{email}' already exists in Firestore!")
            # Return True so we can still use this account
            return True
        
        # Check if user already exists in Auth
        try:
            existing_user = auth.get_user_by_email(email)
            print(f"User with email '{email}' already exists in Auth with ID: {existing_user.uid}")
            
            # Add admin data to Firestore if user exists in Auth but not in Firestore
            admin_data = {
                'username': username,
                'email': email,
                'role': 'admin',
                'is_verified': True,
                'created_at': firestore.SERVER_TIMESTAMP
            }
            
            # Save to Firestore with the auth UID
            db.collection('users').document(existing_user.uid).set(admin_data)
            print(f"Created Firestore profile for existing user '{username}'")
            return True
            
        except auth.UserNotFoundError:
            # User doesn't exist in Auth, create new
            pass
        
        # Create user in Firebase Auth
        user = auth.create_user(
            email=email,
            password=password,
            display_name=username
        )
        
        # Add admin data to Firestore
        admin_data = {
            'username': username,
            'email': email,
            'role': 'admin',
            'is_verified': True,
            'created_at': firestore.SERVER_TIMESTAMP
        }
        
        # Save to Firestore with the auth UID
        db.collection('users').document(user.uid).set(admin_data)
        
        print(f"Admin user '{username}' created successfully!")
        print(f"User ID: {user.uid}")
        
        # Also create a test user
        create_test_user(email.replace("admin", "user"), password)
        create_test_user(email.replace("admin", "lawyer"), password, role="lawyer", is_verified=True)
        
        return True
        
    except Exception as e:
        print(f"Error creating admin user: {str(e)}")
        return False

def create_test_user(email, password, role="user", is_verified=True):
    """Create a test user for quick testing"""
    try:
        username = email.split('@')[0]
        
        # Check if user already exists
        try:
            auth.get_user_by_email(email)
            print(f"Test {role} user '{email}' already exists")
            return True
        except auth.UserNotFoundError:
            # Create new user
            user = auth.create_user(
                email=email,
                password=password,
                display_name=username
            )
            
            # Add user data
            user_data = {
                'username': username,
                'email': email,
                'role': role,
                'is_verified': is_verified,
                'created_at': firestore.SERVER_TIMESTAMP
            }
            
            # Save to Firestore
            db = firestore.client()
            db.collection('users').document(user.uid).set(user_data)
            
            print(f"Test {role} user '{username}' created successfully")
            return True
    except Exception as e:
        print(f"Error creating test user: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python create_admin.py <username> <email> <password>")
        sys.exit(1)
    
    username = sys.argv[1]
    email = sys.argv[2]
    password = sys.argv[3]
    
    create_admin(username, email, password)