import pyrebase
from firebase_config import FIREBASE_CONFIG

def test_firebase_auth():
    """Test Firebase Authentication with Pyrebase"""
    try:
        # Initialize Pyrebase
        firebase = pyrebase.initialize_app(FIREBASE_CONFIG)
        auth = firebase.auth()
        
        # Test credentials
        email = "user@example.com"
        password = "user123"
        
        # Try to login
        user = auth.sign_in_with_email_and_password(email, password)
        print("Authentication successful!")
        print(f"User ID: {user['localId']}")
        print(f"ID Token: {user['idToken'][:20]}...")
        return True
    
    except Exception as e:
        print(f"Authentication failed: {str(e)}")
        return False

if __name__ == "__main__":
    test_firebase_auth()