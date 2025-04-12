import firebase_admin
from firebase_admin import credentials, firestore
import os
import json

# Initialize Firebase Admin SDK with credentials
try:
    cred_path = os.path.join(os.path.dirname(__file__), 'firebase.json')
    
    # Check if the file exists
    if not os.path.exists(cred_path):
        raise FileNotFoundError(f"Firebase credentials file not found at {cred_path}")
    
    cred = credentials.Certificate(cred_path)
    
    # Check if Firebase app is already initialized
    if not firebase_admin._apps:
        firebase_app = firebase_admin.initialize_app(cred)
    else:
        firebase_app = firebase_admin.get_app()
        
    # Initialize Firestore
    db = firestore.client()
    
    print("Firebase Admin SDK initialized successfully")
except Exception as e:
    print(f"Error initializing Firebase Admin SDK: {str(e)}")
    raise

# For client-side authentication (Pyrebase)
FIREBASE_CONFIG = {
    "apiKey": "AIzaSyDqoqBk-I4xhRCz9ZXbD9SJDOMvWimg5CQ",
    "authDomain": "legal-gov.firebaseapp.com",
    "projectId": "legal-gov",
    "storageBucket": "legal-gov.appspot.com",
    "messagingSenderId": "101115587775837658906",
    "appId": "1:101115587775837658906:web:59a536e9d1e8d9704e5203",
    "databaseURL": "https://legal-gov-default-rtdb.firebaseio.com"  # Required for Pyrebase
}

# Validate the config by loading required values from firebase.json
try:
    with open(cred_path, 'r') as f:
        firebase_json = json.load(f)
        
    # Ensure we have project_id in both places
    if FIREBASE_CONFIG.get("projectId") != firebase_json.get("project_id"):
        FIREBASE_CONFIG["projectId"] = firebase_json.get("project_id")
        
    print("Firebase client config loaded and validated")
except Exception as e:
    print(f"Warning: Could not validate Firebase config: {str(e)}")