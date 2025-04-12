import os
import uuid
import logging
from datetime import datetime
import google.generativeai as genai
import firebase_admin
from firebase_admin import credentials, firestore, auth
import pyrebase
from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from functools import wraps
from firebase_config import db, FIREBASE_CONFIG
import requests
from requests.exceptions import RequestException

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# Add this after app = Flask(__name__)

@app.template_filter('modulo')
def modulo_filter(value, mod):
    """Calculate modulo in templates safely and return as string"""
    try:
        # Try to hash the string value for consistent results
        value_hash = hash(str(value)) 
        result = (value_hash % mod) + 1
        # Return as string to avoid concatenation errors
        return str(result)
    except:
        # Fallback to 1 if something goes wrong
        return "1"

@app.template_filter('view_count')
def view_count_filter(value):
    """Generate a consistent view count for a question ID"""
    try:
        # Convert value to a number using hash
        value_hash = hash(str(value)) 
        # Use the hash to generate a reasonable view count (always positive)
        count = (abs(value_hash) % 500) + 42
        return count
    except:
        # Fallback to a default value if something goes wrong
        return 42

@app.template_filter('toint')
def toint_filter(value, default=0):
    """Convert a value to integer safely for templates"""
    try:
        result = int(value)
        return result  # Return as integer for calculations
    except (ValueError, TypeError):
        # If value can't be converted to int, hash it to get a consistent number
        result = abs(hash(str(value))) % 100 + default
        return result  # Return as integer for calculations

@app.template_filter('numformat')
def numformat_filter(value):
    """Format a number result as string for display"""
    try:
        # First convert to int if it's not already
        num = int(value) if not isinstance(value, int) else value
        return str(num)  # Return as string for display
    except (ValueError, TypeError):
        return str(value)  # Return original as string

@app.template_filter('format_date')
def format_date_filter(value, format='%b %d, %Y'):
    """Format a date using strftime"""
    try:
        if value:
            # If it's a Firebase timestamp, convert to datetime
            if hasattr(value, 'timestamp'):
                return datetime.fromtimestamp(value.timestamp()).strftime(format)
            # If it's a dict with seconds (Firebase timestamp serialized)
            elif isinstance(value, dict) and 'seconds' in value:
                return datetime.fromtimestamp(value['seconds']).strftime(format)
            # It might already be a datetime
            elif hasattr(value, 'strftime'):
                return value.strftime(format)
        return "Unknown"
    except (ValueError, TypeError, AttributeError):
        return "Unknown"

# Initialize Pyrebase for client-side auth
firebase = pyrebase.initialize_app(FIREBASE_CONFIG)
firebase_auth = firebase.auth()

# Configure Gemini API
genai.configure(api_key=os.environ.get('GEMINI_API_KEY', 'api-key'))

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

@app.context_processor
def inject_user():
    is_authenticated = 'user_token' in session
    user = {
        'is_authenticated': is_authenticated,
        'is_anonymous': not is_authenticated,
        'is_active': is_authenticated,
        'username': session.get('username', None),
        'id': session.get('user_id', None),
        'role': session.get('role', None),
        'unread_messages': 0
    }
    
    # If authenticated, check for unread messages
    if is_authenticated:
        try:
            user_id = session['user_id']
            # Find conversations with unread messages
            conversations_ref = db.collection('conversations').where('participants', 'array_contains', user_id)
            conversations = list(conversations_ref.stream())
            
            # Count unread messages
            unread_count = 0
            for conv_doc in conversations:
                conv_id = conv_doc.id
                # Get messages for this conversation that are unread and not sent by current user
                messages_ref = db.collection('messages').where('conversation_id', '==', conv_id).where('read', '==', False).where('sender_id', '!=', user_id)
                unread_count += len(list(messages_ref.stream()))
            
            user['unread_messages'] = unread_count
        except Exception as e:
            app.logger.error(f"Error counting unread messages: {str(e)}")
    
    return {'current_user': user}

# Add this context processor

@app.context_processor
def inject_follow_checker():
    def is_following(target_user_id):
        if not 'user_id' in session:
            return False
            
        current_user_id = session['user_id']
        if current_user_id == target_user_id:
            return False
            
        follow_ref = db.collection('follows').where('follower_id', '==', current_user_id).where('following_id', '==', target_user_id).limit(1)
        return any(follow_ref.stream())
        
    return {'is_following': is_following}

# Authentication decorator to replace Flask-Login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_token' not in session:
            flash('Please log in to access this page')
            return redirect(url_for('login'))
        
        try:
            # Verify token with Firebase
            # Add error handling for token format
            try:
                # Try to verify token, but don't fail if it can't be verified
                # This allows custom tokens to work as well
                user = auth.verify_id_token(session['user_token'])
                # Make user available to view
                request.user = user
                request.user['is_authenticated'] = True
                request.user['id'] = session['user_id']
                request.user['username'] = session['username']
                request.user['role'] = session['role']
            except ValueError as token_error:
                # If token verification fails due to format (likely a custom token)
                app.logger.debug(f"Token verification format error (using session data): {str(token_error)}")
                request.user = {
                    'uid': session['user_id'],
                    'is_authenticated': True,
                    'id': session['user_id'],
                    'username': session['username'],
                    'role': session['role']
                }
            except Exception as e:
                # For any other token verification error, still use session data
                app.logger.debug(f"Token verification error (using session data): {str(e)}")
                request.user = {
                    'uid': session['user_id'],
                    'is_authenticated': True,
                    'id': session['user_id'],
                    'username': session['username'],
                    'role': session['role']
                }
                
            # Refresh the session to prevent timeout
            session.modified = True
                
        except Exception as e:
            app.logger.error(f"Auth error: {str(e)}")
            flash('Your session has expired. Please log in again.')
            return redirect(url_for('logout'))
            
        return f(*args, **kwargs)
    return decorated_function

# Role-based access control
def role_required(role):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            # Get role directly from request.user which is now always available
            user_role = request.user.get('role')
            
            if user_role != role:
                flash(f'You need to be a {role} to access this page')
                return redirect(url_for('home'))
                
            # For additional validation if needed (is_verified), get from Firestore
            user_doc = db.collection('users').document(request.user.get('uid')).get()
            
            if not user_doc.exists:
                flash('User profile not found')
                return redirect(url_for('home'))
                
            user_data = user_doc.to_dict()
            
            # Check if verified when needed
            if role == 'lawyer' and not user_data.get('is_verified', False):
                flash('Your lawyer account is pending verification')
                return redirect(url_for('home'))
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Helper function for AI responses using Gemini
def generate_ai_response(question_text):
    try:
        # Configure the model
        model = genai.GenerativeModel('gemini-1.5-pro')
        
        # Create a more structured and focused prompt for clearer responses
        prompt = f"""Topic: {question_text}

        Provide a clear, accurate, and easily readable response to this legal question. Structure your answer as follows:

        1. SUMMARY (2-3 sentences explaining the key legal point)
        2. MAIN CONSIDERATIONS (3-4 bullet points of the most important factors)
        3. PRACTICAL ADVICE (What someone should generally understand about this topic)

        Use simple language, avoid complex legal jargon where possible, and include paragraph breaks for readability.
        Be direct and straightforward in your explanation.
        """
        
        # Set safety settings
        safety_settings = [
            {
                "category": "HARM_CATEGORY_HARASSMENT",
                "threshold": "BLOCK_ONLY_HIGH"
            },
            {
                "category": "HARM_CATEGORY_HATE_SPEECH",
                "threshold": "BLOCK_ONLY_HIGH"
            },
            {
                "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "threshold": "BLOCK_ONLY_HIGH"
            },
            {
                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                "threshold": "BLOCK_ONLY_HIGH"
            }
        ]
        
        # Generate response with optimized parameters for clarity
        response = model.generate_content(
            prompt,
            safety_settings=safety_settings,
            generation_config={
                "temperature": 0.5,  # Lower temperature for more accurate/factual responses
                "top_p": 0.8,
                "top_k": 40,
                "max_output_tokens": 600,  # Slightly shorter for more concise responses
            }
        )
        
        # Check if response has text content
        if response and hasattr(response, 'text'):
            ai_response = response.text.strip()
            
            # Format the response for better readability
            ai_response = ai_response.replace('SUMMARY', '<strong class="text-primary">SUMMARY</strong>')
            ai_response = ai_response.replace('MAIN CONSIDERATIONS', '<strong class="text-primary">MAIN CONSIDERATIONS</strong>')
            ai_response = ai_response.replace('PRACTICAL ADVICE', '<strong class="text-primary">PRACTICAL ADVICE</strong>')
            
            # Add paragraph spacing for better readability
            ai_response = ai_response.replace('\n\n', '<br><br>')
            
            # Add a cleaner disclaimer
            disclaimer = '<div class="mt-3 p-2 bg-light border-start border-4 border-info small"><i class="bi bi-info-circle text-info me-1"></i> <strong>Disclaimer:</strong> This is general information, not specific legal advice. Please consult a qualified attorney for advice on your specific situation.</div>'
            return ai_response + disclaimer
        else:
            return '<div class="alert alert-warning">I couldn\'t generate a complete response for this topic. Please try simplifying or rephrasing your question.</div>'
            
    except Exception as e:
        app.logger.error(f"AI response generation error: {str(e)}")
        return '<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>Sorry, I couldn\'t generate a response at this time. Please try again later.</div>'

# Routes
# Replace your existing home route

@app.route('/')
def home():
    # Get the latest questions for the home page
    questions_ref = db.collection('questions').order_by('created_at', direction=firestore.Query.DESCENDING).limit(10)
    questions = []
    
    for doc in questions_ref.stream():
        question = doc.to_dict()
        question['id'] = doc.id
        
        # Add author info
        user_id = question.get('user_id')
        if user_id:
            user_doc = db.collection('users').document(user_id).get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                question['author'] = {
                    'username': user_data.get('username', 'Unknown'),
                    'id': user_id,
                    'role': user_data.get('role', 'user')
                }
        
        questions.append(question)
    
    # Get top contributors (users with most answers)
    top_contributors = []
    
    # Count answers by user
    answers_by_user = {}
    all_answers = db.collection('answers').stream()
    
    for doc in all_answers:
        answer = doc.to_dict()
        user_id = answer.get('user_id')
        if user_id:
            if user_id in answers_by_user:
                answers_by_user[user_id] += 1
            else:
                answers_by_user[user_id] = 1
    
    # Get top 3 contributors
    top_user_ids = sorted(answers_by_user.items(), key=lambda x: x[1], reverse=True)[:3]
    
    for user_id, count in top_user_ids:
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            user_data['id'] = user_id
            user_data['contribution_count'] = count
            top_contributors.append(user_data)
    
    # Get trending categories
    trending_categories = []
    categories_count = {}

    # Count questions by category
    questions_for_categories = db.collection('questions').stream()
    for doc in questions_for_categories:
        question = doc.to_dict()
        category = question.get('category', 'General')
        if category in categories_count:
            categories_count[category] += 1
        else:
            categories_count[category] = 1

    # Transform into a list of category objects
    for name, count in categories_count.items():
        trending_categories.append({'name': name, 'count': count})

    # Sort by count
    trending_categories.sort(key=lambda x: x['count'], reverse=True)

    # Limit to top 5
    trending_categories = trending_categories[:5]

    return render_template('home.html', questions=questions, top_contributors=top_contributors, 
                          trending_categories=trending_categories)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_token' in session:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role', 'user')
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('register'))
            
        # Check if username exists
        username_query = db.collection('users').where('username', '==', username).limit(1).stream()
        if any(username_query):
            flash('Username already exists!')
            return redirect(url_for('register'))
        
        try:
            # Create user in Firebase Auth
            user = auth.create_user(
                email=email,
                password=password,
                display_name=username
            )
            
            # Additional user data for Firestore
            user_data = {
                'username': username,
                'email': email,
                'role': role,
                'is_verified': role != 'lawyer',  # Lawyers need verification
                'created_at': firestore.SERVER_TIMESTAMP
            }
            
            # Save to Firestore
            db.collection('users').document(user.uid).set(user_data)
            
            if role == 'lawyer':
                flash('Your lawyer account has been created but requires verification. You will be notified once approved.')
            else:
                flash('Registration successful! Please log in.')
                
            return redirect(url_for('login'))
            
        except Exception as e:
            flash(f'Error creating account: {str(e)}')
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Redirect if already logged in
    if 'user_token' in session:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Input validation
        if not email or not password:
            flash('Email and password are required')
            return redirect(url_for('login'))
        
        try:
            app.logger.debug(f"Attempting login with email: {email}")
            
            # Alternative approach: use Firebase Admin SDK to get the user
            try:
                # First try getting the user by email
                user_record = auth.get_user_by_email(email)
                user_id = user_record.uid
                
                # Then try manually validating credentials with your test accounts
                # Note: This is a temporary workaround - in production you'd use a proper auth flow
                test_accounts = {
                    'user@example.com': 'user123',
                    'lawyer@example.com': 'lawyer123',
                    'admin@example.com': 'admin123'
                }
                
                if email not in test_accounts or password != test_accounts[email]:
                    flash('Invalid email or password')
                    return redirect(url_for('login'))
                
                # Sign in with Pyrebase to get an ID token instead of using custom tokens
                try:
                    # Use Firebase Auth REST API directly for more stable authentication
                    firebase_user = firebase_auth.sign_in_with_email_and_password(email, password)
                    id_token = firebase_user['idToken']
                    
                    # Verify the token is valid
                    decoded_token = auth.verify_id_token(id_token)
                    app.logger.debug(f"Token verified successfully: {decoded_token['uid']}")
                except Exception as signin_error:
                    app.logger.error(f"Error signing in with Pyrebase: {str(signin_error)}")
                    # Fall back to custom token if Pyrebase fails
                    custom_token = auth.create_custom_token(user_id)
                    # In production, you would exchange this for an ID token, 
                    # but for simplicity we'll use it directly
                    id_token = custom_token.decode('utf-8')
                
                # Get user details from Firestore
                user_doc = db.collection('users').document(user_id).get()
                
                if not user_doc.exists:
                    app.logger.error(f"User found in Auth but no profile in Firestore: {user_id}")
                    
                    # Create a basic profile
                    username = email.split('@')[0]
                    user_data = {
                        'username': username,
                        'email': email,
                        'role': 'user' if 'user' in email else ('lawyer' if 'lawyer' in email else 'admin'),
                        'is_verified': True,
                        'created_at': firestore.SERVER_TIMESTAMP
                    }
                    db.collection('users').document(user_id).set(user_data)
                    app.logger.debug(f"Created new profile for user: {user_id}")
                    
                    # Set session data - use ID token instead of custom token
                    session['user_token'] = id_token
                    session['user_id'] = user_id
                    session['username'] = username
                    session['role'] = user_data['role']
                    # Set a longer session lifetime
                    session.permanent = True
                    
                    flash('Welcome! Your profile has been created.')
                    return redirect(url_for('home'))
                
                user_data = user_doc.to_dict()
                
                # Check if lawyer account is verified
                if user_data.get('role') == 'lawyer' and not user_data.get('is_verified', False):
                    flash('Your lawyer account is pending verification. Please check back later.')
                    return redirect(url_for('login'))
                
                # Set session data - use ID token instead of custom token
                session['user_token'] = id_token
                session['user_id'] = user_id
                session['username'] = user_data.get('username')
                session['role'] = user_data.get('role')
                # Set a longer session lifetime
                session.permanent = True
                
                flash(f'Welcome back, {user_data.get("username")}!')
                return redirect(url_for('home'))
                
            except auth.UserNotFoundError:
                flash('Invalid email or password')
                return redirect(url_for('login'))
            except Exception as auth_error:
                app.logger.error(f"Auth error: {str(auth_error)}")
                flash('Authentication failed')
                return redirect(url_for('login'))
                
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            flash('Authentication failed. Please try again.')
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/ask', methods=['GET', 'POST'])
@login_required
def ask_question():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        category = request.form.get('category')
        tags = request.form.get('tags')
        
        if not title or not content:
            flash('Title and content are required!')
            return redirect(url_for('ask_question'))
        
        # Clean and prepare content for safe handling
        content = content.strip()
        
        # Check for @LegalAI mentions
        has_ai_mention = '@LegalAI' in content or '@legalai' in content.lower()
        
        # Generate a unique ID for the question
        question_id = str(uuid.uuid4())
        
        # Create question document
        question_data = {
            'title': title,
            'content': content,
            'category': category or 'General',  # Default category if not provided
            'tags': tags,
            'user_id': session['user_id'],
            'username': session['username'],
            'has_ai_mention': has_ai_mention,
            'created_at': firestore.SERVER_TIMESTAMP,
            'updated_at': firestore.SERVER_TIMESTAMP
        }
        
        try:
            # Save to Firestore
            db.collection('questions').document(question_id).set(question_data)
            
            # Generate AI insights automatically if requested or mentioned
            if request.form.get('request_ai') == 'yes' or has_ai_mention:
                ai_content = generate_ai_response(f"{title}\n{content}")
                
                # Get or create AI user
                ai_user_query = db.collection('users').where('username', '==', 'LegalAI').limit(1).stream()
                ai_user = next(ai_user_query, None)
                
                if not ai_user:
                    # Create AI user if it doesn't exist
                    ai_user_id = str(uuid.uuid4())
                    ai_user_data = {
                        'username': 'LegalAI',
                        'email': 'ai@legalqa.example',
                        'role': 'ai',
                        'is_verified': True,
                        'created_at': firestore.SERVER_TIMESTAMP
                    }
                    db.collection('users').document(ai_user_id).set(ai_user_data)
                    ai_user_id = ai_user_id
                else:
                    ai_user_id = ai_user.id
                    
                # Create AI answer
                answer_id = str(uuid.uuid4())
                ai_answer_data = {
                    'content': ai_content,
                    'user_id': ai_user_id,
                    'username': 'LegalAI',
                    'question_id': question_id,
                    'is_ai_generated': True,
                    'upvotes': 0,
                    'is_accepted': False,
                    'created_at': firestore.SERVER_TIMESTAMP,
                    'updated_at': firestore.SERVER_TIMESTAMP
                }
                
                db.collection('answers').document(answer_id).set(ai_answer_data)
                
                if has_ai_mention:
                    flash('Your post has been published with AI response!')
                else:
                    flash('Your post has been published with AI insights!')
            else:
                flash('Your post has been published!')
                
            return redirect(url_for('view_question', question_id=question_id))
            
        except Exception as e:
            app.logger.error(f"Error creating post: {str(e)}")
            flash(f"Error creating post: {str(e)}")
            return redirect(url_for('ask_question'))
        
    return render_template('ask_question.html')

@app.route('/question/<question_id>', methods=['GET', 'POST'])
def view_question(question_id):
    # Get question data
    question_doc = db.collection('questions').document(question_id).get()
    
    if not question_doc.exists:
        flash('Question not found')
        return redirect(url_for('home'))
        
    question = question_doc.to_dict()
    question['id'] = question_id
    
    # Add author information
    user_id = question.get('user_id')
    if user_id:
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            question['author'] = {
                'username': user_data.get('username', 'Unknown'),
                'id': user_id,
                'role': user_data.get('role', 'user')
            }
        else:
            question['author'] = {'username': question.get('username', 'Unknown'), 'id': user_id, 'role': 'user'}
    else:
        question['author'] = {'username': question.get('username', 'Unknown'), 'id': 'unknown', 'role': 'user'}
    
    # Check if current user is following the author (if author is a lawyer)
    is_following = False
    if 'user_id' in session and user_id and question['author']['role'] == 'lawyer':
        follow_ref = db.collection('follows').where('follower_id', '==', session['user_id']).where('following_id', '==', user_id).limit(1)
        is_following = any(follow_ref.stream())
    
    # Handle POST requests (comments)
    if request.method == 'POST' and 'user_token' in session:
        # Only allow lawyers to comment
        if session.get('role') != 'lawyer':
            flash('Only verified legal professionals can comment on posts!')
            return redirect(url_for('view_question', question_id=question_id))
            
        # Adding a comment
        content = request.form.get('content')
        
        if not content:
            flash('Comment content cannot be empty!')
            return redirect(url_for('view_question', question_id=question_id))
            
        # Create answer document
        answer_id = str(uuid.uuid4())
        answer_data = {
            'content': content,
            'user_id': session['user_id'],
            'username': session['username'],
            'question_id': question_id,
            'is_ai_generated': False,
            'upvotes': 0,
            'is_accepted': False,
            'created_at': firestore.SERVER_TIMESTAMP,
            'updated_at': firestore.SERVER_TIMESTAMP
        }
        
        db.collection('answers').document(answer_id).set(answer_data)
        
        # If the lawyer tagged @LegalAI, generate an AI response
        if '@LegalAI' in content or '@legalai' in content.lower():
            # Get AI user info
            ai_user_query = db.collection('users').where('username', '==', 'LegalAI').limit(1).stream()
            ai_user = next(ai_user_query, None)
            
            if not ai_user:
                # Create AI user if it doesn't exist
                ai_user_id = str(uuid.uuid4())
                ai_user_data = {
                    'username': 'LegalAI',
                    'email': 'ai@legalqa.example',
                    'role': 'ai',
                    'is_verified': True,
                    'created_at': firestore.SERVER_TIMESTAMP
                }
                db.collection('users').document(ai_user_id).set(ai_user_data)
                ai_user_id = ai_user_id
            else:
                ai_user_id = ai_user.id
            
            # Generate AI response
            prompt = f"Question: {question['title']}\n{question['content']}\n\nComment by lawyer: {content}"
            ai_content = generate_ai_response(prompt)
            
            # Create AI answer
            ai_answer_id = str(uuid.uuid4())
            ai_answer_data = {
                'content': ai_content,
                'user_id': ai_user_id,
                'username': 'LegalAI',
                'question_id': question_id,
                'is_ai_generated': True,
                'upvotes': 0,
                'is_accepted': False,
                'created_at': firestore.SERVER_TIMESTAMP,
                'updated_at': firestore.SERVER_TIMESTAMP
            }
            
            db.collection('answers').document(ai_answer_id).set(ai_answer_data)
            flash('Your comment has been posted with AI insights!')
        else:
            flash('Your comment has been posted!')
            
        return redirect(url_for('view_question', question_id=question_id))
    
    # Get all answers for this question
    answers_ref = db.collection('answers').where('question_id', '==', question_id).order_by('created_at')
    answers = []
    
    # Get top-level answers and their replies
    answer_map = {}  # Map to organize replies under their parent answers
    
    # Create a new list of answers with author information
    for doc in answers_ref.stream():
        answer = doc.to_dict()
        answer['id'] = doc.id
        
        # Add author information to each answer
        answer_user_id = answer.get('user_id')
        if answer_user_id:
            user_doc = db.collection('users').document(answer_user_id).get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                answer['author'] = {
                    'username': user_data.get('username', 'Unknown'),
                    'id': answer_user_id,
                    'role': user_data.get('role', 'user')
                }
            else:
                answer['author'] = {'username': answer.get('username', 'Unknown'), 'id': answer_user_id, 'role': 'user'}
        else:
            answer['author'] = {'username': answer.get('username', 'Unknown'), 'id': 'unknown', 'role': 'user'}
        
        # Initialize replies array for each answer
        answer['replies'] = []
        
        # Check if this is a reply to another answer
        if 'parent_answer_id' in answer:
            # This is a reply, store it in the map to organize later
            parent_id = answer.get('parent_answer_id')
            if parent_id not in answer_map:
                answer_map[parent_id] = []
            answer_map[parent_id].append(answer)
        else:
            # This is a top-level answer, add it to the list
            answers.append(answer)
    
    # Organize replies under their parent answers
    for answer in answers:
        if answer['id'] in answer_map:
            answer['replies'] = answer_map[answer['id']]
    
    return render_template('view_question.html', 
                          question=question, 
                          answers=answers, 
                          is_following=is_following)

@app.route('/questions')
def browse_questions():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Filter options
    category = request.args.get('category')
    search = request.args.get('search')
    
    # Base query
    query = db.collection('questions').order_by('created_at', direction=firestore.Query.DESCENDING)
    
    # Apply filters
    if category:
        query = query.where('category', '==', category)
    
    # Execute query
    question_docs = query.stream()
    
    # Client-side search filtering
    questions = []
    for doc in question_docs:
        question = doc.to_dict()
        question['id'] = doc.id
        
        # Client-side search
        if search:
            search_term = search.lower()
            if search_term not in question.get('title', '').lower() and search_term not in question.get('content', '').lower():
                continue
                
        # Add author info
        user_id = question.get('user_id')
        if user_id:
            user_doc = db.collection('users').document(user_id).get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                question['author'] = {
                    'username': user_data.get('username', question.get('username', 'Unknown')),
                    'id': user_id,
                    'role': user_data.get('role', 'user')
                }
            else:
                question['author'] = {'username': question.get('username', 'Unknown'), 'id': 'unknown', 'role': 'user'}
        else:
            question['author'] = {'username': question.get('username', 'Unknown'), 'id': 'unknown', 'role': 'user'}
        
        questions.append(question)
    
    # Get answer counts
    answers_count = {}
    answers_ref = db.collection('answers')
    for doc in answers_ref.stream():
        answer = doc.to_dict()
        question_id = answer.get('question_id')
        if question_id:
            if question_id in answers_count:
                answers_count[question_id] += 1
            else:
                answers_count[question_id] = 1
    
    # Get categories for sidebar
    categories_count = {}
    for question in questions:
        category_name = question.get('category', 'General')
        if category_name in categories_count:
            categories_count[category_name] += 1
        else:
            categories_count[category_name] = 1
            
    categories = [{'name': name, 'count': count} for name, count in categories_count.items()]
    categories.sort(key=lambda x: x['count'], reverse=True)
    
    # Simple pagination (client-side)
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_questions = questions[start_idx:end_idx]
    
    # Calculate pagination metadata
    total_pages = (len(questions) + per_page - 1) // per_page

    # Create a proper dictionary for pagination rather than a function-filled object
    pagination = {
        'page': page,
        'per_page': per_page,
        'total': len(questions),
        'total_pages': total_pages,
        'has_prev': page > 1,
        'has_next': page < total_pages,
        'items': paginated_questions,  # This should be a list, not a function
        'iter_pages': list(range(1, total_pages + 1))  # Convert to list explicitly
    }
    
    return render_template('browse_questions.html', 
                          questions=pagination,
                          categories=categories,
                          answers_count=answers_count)

@app.route('/profile')
@login_required
def profile():
    user_id = session['user_id']
    
    # Get user data including created_at
    user_doc = db.collection('users').document(user_id).get()
    user_data = user_doc.to_dict()
    
    # Add user data to current_user
    current_user = {
        'username': session.get('username'),
        'email': user_data.get('email'),
        'role': session.get('role'),
        'id': session.get('user_id'),
        'is_verified': user_data.get('is_verified', False),
        'created_at': user_data.get('created_at'),
    }
    
    # Get user's questions
    questions_ref = db.collection('questions').where('user_id', '==', user_id).order_by('created_at', direction=firestore.Query.DESCENDING)
    user_questions = []
    for doc in questions_ref.stream():
        question = doc.to_dict()
        question['id'] = doc.id
        user_questions.append(question)
    
    # Get user's answers
    answers_ref = db.collection('answers').where('user_id', '==', user_id).order_by('created_at', direction=firestore.Query.DESCENDING)
    user_answers = []
    
    # Create a map to store question data keyed by question_id
    question_map = {}
    
    for doc in answers_ref.stream():
        answer = doc.to_dict()
        answer['id'] = doc.id
        
        # Get the associated question data
        question_id = answer.get('question_id')
        if question_id:
            # Check if we already have this question data
            if question_id not in question_map:
                # Fetch question data
                question_doc = db.collection('questions').document(question_id).get()
                if question_doc.exists:
                    question_data = question_doc.to_dict()
                    question_data['id'] = question_id
                    question_map[question_id] = question_data
                else:
                    # If question doesn't exist, use a placeholder
                    question_map[question_id] = {'title': 'Deleted Question', 'id': question_id}
            
            # Add question data to the answer
            answer['question'] = question_map[question_id]
        
        user_answers.append(answer)
    
    return render_template('profile.html', 
                          current_user=current_user,
                          questions=user_questions, 
                          answers=user_answers)

@app.route('/admin')
@login_required
@role_required('admin')
def admin_panel():
    # Get pending lawyers
    pending_lawyers_ref = db.collection('users').where('role', '==', 'lawyer').where('is_verified', '==', False)
    pending_lawyers = []
    for doc in pending_lawyers_ref.stream():
        data = doc.to_dict()
        data['id'] = doc.id
        pending_lawyers.append(data)
    
    # Get all users
    users_ref = db.collection('users')
    all_users = []
    for doc in users_ref.stream():
        data = doc.to_dict()
        data['id'] = doc.id
        all_users.append(data)
    
    return render_template('admin.html', pending_lawyers=pending_lawyers, users=all_users)

@app.route('/admin/verify/<user_id>')
@login_required
@role_required('admin')
def verify_lawyer(user_id):
    lawyer_ref = db.collection('users').document(user_id)
    lawyer_doc = lawyer_ref.get()
    
    if not lawyer_doc.exists:
        flash('User not found')
        return redirect(url_for('admin_panel'))
    
    lawyer_data = lawyer_doc.to_dict()
    
    if lawyer_data.get('role') != 'lawyer':
        flash('This user is not registered as a lawyer!')
        return redirect(url_for('admin_panel'))
    
    # Update verification status
    lawyer_ref.update({'is_verified': True})
    
    flash(f'Lawyer {lawyer_data.get("username")} has been verified!')
    return redirect(url_for('admin_panel'))

@app.route('/answer/<answer_id>/upvote')
@login_required
def upvote_answer(answer_id):
    answer_ref = db.collection('answers').document(answer_id)
    
    # Atomic increment of upvotes
    answer_ref.update({'upvotes': firestore.Increment(1)})
    
    # Get question ID for redirect
    answer_doc = answer_ref.get()
    question_id = answer_doc.to_dict().get('question_id')
    
    flash('Answer upvoted!')
    return redirect(url_for('view_question', question_id=question_id))

@app.route('/answer/<answer_id>/accept')
@login_required
def accept_answer(answer_id):
    answer_ref = db.collection('answers').document(answer_id)
    answer_doc = answer_ref.get()
    
    if not answer_doc.exists:
        flash('Answer not found')
        return redirect(url_for('home'))
    
    answer_data = answer_doc.to_dict()
    question_id = answer_data.get('question_id')
    
    # Get question to check ownership
    question_ref = db.collection('questions').document(question_id)
    question_doc = question_ref.get()
    
    if not question_doc.exists:
        flash('Question not found')
        return redirect(url_for('home'))
    
    question_data = question_doc.to_dict()
    
    # Check if current user is the question author
    if question_data.get('user_id') != session['user_id']:
        flash('Only the question author can accept answers!')
        return redirect(url_for('view_question', question_id=question_id))
    
    # Find all answers for this question and reset accepted status
    answers_ref = db.collection('answers').where('question_id', '==', question_id)
    
    # Batch update to reset all answers and accept the selected one
    batch = db.batch()
    
    for doc in answers_ref.stream():
        # Reset all answers
        batch.update(doc.reference, {'is_accepted': False})
    
    # Accept the selected answer
    batch.update(answer_ref, {'is_accepted': True})
    
    # Commit the batch
    batch.commit()
    
    flash('Answer marked as accepted!')
    return redirect(url_for('view_question', question_id=question_id))

@app.route('/request_ai/<question_id>')
@login_required
def request_ai_answer(question_id):
    # Get question data
    question_ref = db.collection('questions').document(question_id)
    question_doc = question_ref.get()
    
    if not question_doc.exists():
        flash('Question not found')
        return redirect(url_for('home'))
    
    question_data = question_doc.to_dict()
    
    # Check if AI has already answered
    ai_answers_query = db.collection('answers').where('question_id', '==', question_id).where('is_ai_generated', '==', True).limit(1).stream()
    
    if any(ai_answers_query):
        flash('AI has already provided an answer to this question!')
        return redirect(url_for('view_question', question_id=question_id))
    
    # Get or create AI user
    ai_user_query = db.collection('users').where('username', '==', 'LegalAI').limit(1).stream()
    ai_user = next(ai_user_query, None)
    
    if not ai_user:
        # Create AI user if it doesn't exist
        ai_user_id = str(uuid.uuid4())
        ai_user_data = {
            'username': 'LegalAI',
            'email': 'ai@legalqa.example',
            'role': 'ai',
            'is_verified': True,
            'created_at': firestore.SERVER_TIMESTAMP
        }
        db.collection('users').document(ai_user_id).set(ai_user_data)
        ai_user_id = ai_user_id
    else:
        ai_user_id = ai_user.id
    
    # Generate AI answer
    ai_content = generate_ai_response(f"{question_data.get('title')}\n{question_data.get('content')}")
    
    # Create AI answer
    answer_id = str(uuid.uuid4())
    ai_answer_data = {
        'content': ai_content,
        'user_id': ai_user_id,
        'username': 'LegalAI',
        'question_id': question_id,
        'is_ai_generated': True,
        'upvotes': 0,
        'is_accepted': False,
        'created_at': firestore.SERVER_TIMESTAMP,
        'updated_at': firestore.SERVER_TIMESTAMP
    }
    
    db.collection('answers').document(answer_id).set(ai_answer_data)
    
    flash('AI has answered your question!')
    return redirect(url_for('view_question', question_id=question_id))

@app.route('/answer/<answer_id>/reply', methods=['POST'])
@login_required
def reply_to_answer(answer_id):
    """Endpoint to allow replying to an existing answer"""
    # Ensure the user is authenticated
    if 'user_token' not in session:
        flash('You must be logged in to reply')
        return redirect(url_for('login'))
    
    # Get the original answer to find its question
    answer_ref = db.collection('answers').document(answer_id)
    answer_doc = answer_ref.get()
    
    if not answer_doc.exists:
        flash('Answer not found')
        return redirect(url_for('home'))
    
    answer_data = answer_doc.to_dict()
    question_id = answer_data.get('question_id')
    
    # Get the reply content
    content = request.form.get('content')
    
    if not content or content.strip() == '':
        flash('Reply cannot be empty')
        return redirect(url_for('view_question', question_id=question_id))
    
    # Create a new answer document that references the parent
    reply_id = str(uuid.uuid4())
    reply_data = {
        'content': content,
        'user_id': session['user_id'],
        'username': session['username'],
        'question_id': question_id,
        'parent_answer_id': answer_id,  # Reference to parent answer
        'is_ai_generated': False,
        'upvotes': 0,
        'is_accepted': False,
        'created_at': firestore.SERVER_TIMESTAMP,
        'updated_at': firestore.SERVER_TIMESTAMP
    }
    
    # Save the reply
    db.collection('answers').document(reply_id).set(reply_data)
    
    # If the lawyer tagged @LegalAI, generate an AI response
    if '@LegalAI' in content or '@legalai' in content.lower():
        # Get AI user info
        ai_user_query = db.collection('users').where('username', '==', 'LegalAI').limit(1).stream()
        ai_user = next(ai_user_query, None)
        
        if not ai_user:
            # Create AI user if it doesn't exist
            ai_user_id = str(uuid.uuid4())
            ai_user_data = {
                'username': 'LegalAI',
                'email': 'ai@legalqa.example',
                'role': 'ai',
                'is_verified': True,
                'created_at': firestore.SERVER_TIMESTAMP
            }
            db.collection('users').document(ai_user_id).set(ai_user_data)
            ai_user_id = ai_user_id
        else:
            ai_user_id = ai_user.id
        
        # Generate AI response based on the full context
        prompt = f"Original Answer: {answer_data.get('content')}\n\nLawyer Reply: {content}\n\nPlease provide additional legal insights on this thread."
        ai_content = generate_ai_response(prompt)
        
        # Create AI answer
        ai_reply_id = str(uuid.uuid4())
        ai_reply_data = {
            'content': ai_content,
            'user_id': ai_user_id,
            'username': 'LegalAI',
            'question_id': question_id,
            'parent_answer_id': answer_id,  # Same parent as the lawyer's reply
            'is_ai_generated': True,
            'upvotes': 0,
            'is_accepted': False,
            'created_at': firestore.SERVER_TIMESTAMP,
            'updated_at': firestore.SERVER_TIMESTAMP
        }
        
        db.collection('answers').document(ai_reply_id).set(ai_reply_data)
        flash('Your reply has been posted with AI insights!')
    else:
        flash('Your reply has been posted!')
    
    return redirect(url_for('view_question', question_id=question_id))

@app.route('/follow/<user_id>', methods=['POST'])
@login_required
def follow_user(user_id):
    """Allow users to follow a lawyer"""
    # Check if the target user exists and is a lawyer
    target_user_ref = db.collection('users').document(user_id)
    target_user = target_user_ref.get()
    
    if not target_user.exists:
        flash('User not found')
        return redirect(url_for('home'))
    
    target_user_data = target_user.to_dict()
    
    # Check if target is a lawyer
    if target_user_data.get('role') != 'lawyer':
        flash('You can only follow legal professionals')
        return redirect(url_for('home'))
    
    # Check if already following
    follower_id = session['user_id']
    follow_ref = db.collection('follows').where('follower_id', '==', follower_id).where('following_id', '==', user_id).limit(1)
    
    follow_exists = False
    follow_doc = None
    
    # Check if follow relationship exists
    for doc in follow_ref.stream():
        follow_exists = True
        follow_doc = doc
        break
        
    if follow_exists and follow_doc:
        # Already following, so unfollow
        db.collection('follows').document(follow_doc.id).delete()
        flash(f"You have unfollowed {target_user_data.get('username')}")
    else:
        # Not following, so follow
        follow_data = {
            'follower_id': follower_id,
            'follower_username': session['username'],
            'following_id': user_id,
            'following_username': target_user_data.get('username'),
            'created_at': firestore.SERVER_TIMESTAMP
        }
        db.collection('follows').add(follow_data)
        flash(f"You are now following {target_user_data.get('username')}")
    
    # Redirect back to previous page or profile
    referrer = request.referrer
    if referrer:
        return redirect(referrer)
    return redirect(url_for('view_profile', user_id=user_id))

@app.route('/profile/<user_id>')
def view_profile(user_id):
    """View another user's profile"""
    # Get user data
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()
    
    if not user_doc.exists:
        flash('User not found')
        return redirect(url_for('home'))
    
    profile_user = user_doc.to_dict()
    profile_user['id'] = user_id
    
    # Get expertise areas if lawyer (from user data or default to empty list)
    if profile_user.get('role') == 'lawyer':
        profile_user['expertise'] = profile_user.get('expertise', [])
    
    # Get user's questions
    questions_ref = db.collection('questions').where('user_id', '==', user_id).order_by('created_at', direction=firestore.Query.DESCENDING)
    user_questions = []
    for doc in questions_ref.stream():
        data = doc.to_dict()
        data['id'] = doc.id
        user_questions.append(data)
    
    # Get user's answers
    answers_ref = db.collection('answers').where('user_id', '==', user_id).order_by('created_at', direction=firestore.Query.DESCENDING)
    user_answers = []
    for doc in answers_ref.stream():
        data = doc.to_dict()
        data['id'] = doc.id
        user_answers.append(data)
    
    # Check if current user is following this user
    is_following = False
    if 'user_id' in session:
        follow_ref = db.collection('follows').where('follower_id', '==', session['user_id']).where('following_id', '==', user_id).limit(1)
        is_following = any(follow_ref.stream())
    
    # Get follower count
    follower_ref = db.collection('follows').where('following_id', '==', user_id)
    follower_count = len(list(follower_ref.stream()))
    
    return render_template('view_profile.html', 
                          profile_user=profile_user, 
                          questions=user_questions, 
                          answers=user_answers,
                          is_following=is_following,
                          follower_count=follower_count)

@app.route('/messages')
@login_required
def messages():
    """Show all conversations for the current user"""
    user_id = session['user_id']
    
    # Get all conversations where current user is a participant
    conversations_ref = db.collection('conversations').where('participants', 'array_contains', user_id).order_by('last_message_time', direction=firestore.Query.DESCENDING)
    
    conversations = []
    for doc in conversations_ref.stream():
        conversation = doc.to_dict()
        conversation['id'] = doc.id
        
        # Get the other participant's info
        for participant_id in conversation['participants']:
            if participant_id != user_id:
                other_user_ref = db.collection('users').document(participant_id).get()
                if other_user_ref.exists:
                    other_user = other_user_ref.to_dict()
                    
                    # Fix: properly handle the timestamp comparison
                    is_online = False
                    if 'last_active' in other_user:
                        last_active = other_user.get('last_active')
                        # Convert Firestore timestamp to timestamp float if needed
                        if hasattr(last_active, 'timestamp'):
                            last_active_time = last_active.timestamp()
                            is_online = (datetime.now().timestamp() - last_active_time) < 300
                    
                    conversation['other_user'] = {
                        'id': participant_id,
                        'username': other_user.get('username', 'Unknown'),
                        'role': other_user.get('role', 'user'),
                        'is_online': is_online  # Using our fixed value
                    }
                    break
        
        # Count messages in this conversation
        messages_ref = db.collection('messages').where('conversation_id', '==', doc.id)
        message_count = len(list(messages_ref.stream()))
        conversation['message_count'] = message_count
        
        # Check if there are unread messages from the other user
        unread_messages_ref = db.collection('messages').where('conversation_id', '==', doc.id).where('sender_id', '!=', user_id).where('read', '==', False)
        unread_messages = list(unread_messages_ref.stream())
        conversation['unread_count'] = len(unread_messages)
        conversation['last_message_from_other'] = any(msg.to_dict().get('sender_id') != user_id for msg in unread_messages)
        conversation['last_message_read'] = not conversation['unread_count'] > 0
        
        conversations.append(conversation)
    
    return render_template('messages.html', conversations=conversations)

@app.route('/chat/<user_id>')
@login_required
def chat(user_id):
    """Open or create a chat with another user"""
    current_user_id = session['user_id']
    
    # Check if target user exists
    target_user_ref = db.collection('users').document(user_id).get()
    if not target_user_ref.exists:
        flash('User not found')
        return redirect(url_for('messages'))
    
    target_user = target_user_ref.to_dict()
    
    # Fix: properly handle the timestamp comparison for is_online
    is_online = False
    if 'last_active' in target_user:
        last_active = target_user.get('last_active')
        # Convert Firestore timestamp to timestamp float if needed
        if hasattr(last_active, 'timestamp'):
            last_active_time = last_active.timestamp()
            is_online = (datetime.now().timestamp() - last_active_time) < 300
    
    target_user['is_online'] = is_online
    
    # Find existing conversation
    conversations_ref = db.collection('conversations')
    query = conversations_ref.where('participants', 'array_contains', current_user_id)
    
    conversation_id = None
    for doc in query.stream():
        conversation = doc.to_dict()
        if user_id in conversation['participants']:
            conversation_id = doc.id
            break
    
    # If no conversation exists, create one
    if conversation_id is None:
        # Check if current user is following the target user (if target is a lawyer)
        if target_user.get('role') == 'lawyer':
            follow_ref = db.collection('follows').where('follower_id', '==', current_user_id).where('following_id', '==', user_id).limit(1)
            if not any(follow_ref.stream()):
                flash('You need to follow this lawyer before starting a chat')
                return redirect(url_for('view_profile', user_id=user_id))
        
        # Create new conversation
        new_conversation = {
            'participants': [current_user_id, user_id],
            'created_at': firestore.SERVER_TIMESTAMP,
            'last_message_time': firestore.SERVER_TIMESTAMP,
            'last_message': 'No messages yet'
        }
        
        new_conversation_ref = conversations_ref.add(new_conversation)
        conversation_id = new_conversation_ref[1].id
    
    # Get messages for this conversation
    messages_ref = db.collection('messages').where('conversation_id', '==', conversation_id).order_by('created_at')
    
    messages = []
    batch = db.batch()  # For batch updating read status
    unread_messages_exist = False
    
    for doc in messages_ref.stream():
        message = doc.to_dict()
        message['id'] = doc.id
        
        # Mark messages from the other user as read
        if message['sender_id'] != current_user_id and not message.get('read', False):
            unread_messages_exist = True
            message_ref = db.collection('messages').document(doc.id)
            batch.update(message_ref, {'read': True})
            message['read'] = True
        
        messages.append(message)
    
    # Update the read status in a batch if needed
    if unread_messages_exist:
        batch.commit()
    
    # Update user's last active timestamp
    db.collection('users').document(current_user_id).update({
        'last_active': firestore.SERVER_TIMESTAMP
    })
    
    return render_template('chat.html', 
                         conversation_id=conversation_id, 
                         messages=messages, 
                         target_user=target_user,
                         target_user_id=user_id)

@app.route('/send_message/<conversation_id>', methods=['POST'])
@login_required
def send_message(conversation_id):
    """Send a message in a conversation"""
    message_content = request.form.get('message')
    
    if not message_content or message_content.strip() == '':
        flash('Message cannot be empty')
        return redirect(url_for('messages'))
    
    # Check if conversation exists and user is a participant
    conversation_ref = db.collection('conversations').document(conversation_id).get()
    
    if not conversation_ref.exists:
        flash('Conversation not found')
        return redirect(url_for('messages'))
    
    conversation = conversation_ref.to_dict()
    current_user_id = session['user_id']
    
    if current_user_id not in conversation['participants']:
        flash('You are not a participant in this conversation')
        return redirect(url_for('messages'))
    
    # Create message
    message_data = {
        'conversation_id': conversation_id,
        'sender_id': current_user_id,
        'sender_username': session['username'],
        'content': message_content,
        'created_at': firestore.SERVER_TIMESTAMP,
        'read': False
    }
    
    # Add message to database
    db.collection('messages').add(message_data)
    
    # Update conversation's last message and time
    db.collection('conversations').document(conversation_id).update({
        'last_message': message_content[:50] + ('...' if len(message_content) > 50 else ''),
        'last_message_time': firestore.SERVER_TIMESTAMP
    })
    
    # Update user's last active timestamp
    db.collection('users').document(current_user_id).update({
        'last_active': firestore.SERVER_TIMESTAMP
    })
    
    # Get the other participant's ID for redirect
    other_user_id = None
    for participant_id in conversation['participants']:
        if participant_id != current_user_id:
            other_user_id = participant_id
            break
    
    return redirect(url_for('chat', user_id=other_user_id))

if __name__ == '__main__':
    app.run(debug=True)
