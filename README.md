
# 🏛️ Legal_Connect - Interactive Legal Question & Answer Platform

![LegalQA Banner](https://img.shields.io/badge/Legal-QA-blue?style=for-the-badge)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Flask](https://img.shields.io/badge/Flask-2.0+-green)
![Firebase](https://img.shields.io/badge/Firebase-9.0+-orange)
![Gemini AI](https://img.shields.io/badge/Gemini-AI-purple)

---

**Legal_Connect** is a comprehensive platform connecting users with legal questions to verified legal professionals and AI-powered guidance. The platform facilitates community discussions around legal topics, provides AI insights, and enables direct communication between users and lawyers.

---

## ✨ Features

### 👥 User Roles & Authentication
- 🔐 Secure registration and authentication via **Firebase**
- 🧑‍⚖️ Role-based access: Users, Lawyers, and Admins
- ✅ Admin-verified legal professional profiles

### 💬 Core Functionality
- ❓ Ask & Answer: Users post legal questions and receive answers
- 🤖 AI-Powered Guidance: Smart replies via **@LegalAI** using **Gemini API**
- 💬 Threaded Discussions: Nested replies and comments
- 👍 Upvoting system: Highlight the most helpful responses
- ✅ Answer acceptance: Mark official answers

### 👨‍⚖️ Lawyer-Centric Tools
- 🧾 Public Profiles: Showcase expertise and past answers
- 🫂 Follow Lawyers: Get updates on your favorite legal experts
- ✉️ Direct Messaging: Communicate 1:1 with professionals
- 🔔 Notifications: Alerts for messages, replies, and follows

### 🔍 Discovery & Navigation
- 📂 Browse by Category: Filter and search legal topics
- 📈 Trending Tags: Auto-highlighted hot topics
- 🌟 Top Contributors: Recognize active legal professionals

---

## 🏗️ Architecture

- ⚙️ **Flask**: Backend server logic and routing
- 🔥 **Firebase**: Authentication, Firestore DB, Storage
- 🧠 **Google Gemini AI**: NLP & smart reply generation
- 🎨 **Bootstrap**: Responsive frontend framework

---

## 🚀 Getting Started

### ✅ Prerequisites
- Python 3.8+
- Firebase Project & Service Account Key
- Gemini AI API Key

### 🔧 Installation

```bash
# 1. Clone the repository
git clone https://github.com/vivekmishra5699/legal_connect.git
cd legal_connect

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set environment variables
export SECRET_KEY="your-secret-key"
export GEMINI_API_KEY="your-gemini-api-key"
```

### 🔥 Firebase Setup

Create a `firebase_config.py` file:

```python
import firebase_admin
from firebase_admin import credentials, firestore

cred = credentials.Certificate('path/to/serviceAccountKey.json')
firebase_admin.initialize_app(cred)
db = firestore.client()

FIREBASE_CONFIG = {
    "apiKey": "your-api-key",
    "authDomain": "your-project.firebaseapp.com",
    "databaseURL": "https://your-project.firebaseio.com",
    "projectId": "your-project-id",
    "storageBucket": "your-project.appspot.com",
    "messagingSenderId": "your-messaging-id",
    "appId": "your-app-id"
}
```

### 🏃 Run the App

```bash
python app.py
```

Open your browser and go to:  
➡️ `http://localhost:5000`

---

## 🗂️ Database Structure

| Collection    | Description                                   |
|---------------|-----------------------------------------------|
| `Users`       | Profile data, roles, verification             |
| `Questions`   | User-submitted legal questions                |
| `Answers`     | Lawyer and AI answers                         |
| `Conversations` | Direct chat threads                        |
| `Messages`    | Chat messages                                 |
| `Follows`     | User-lawyer follow relationships              |

---

## 🔐 Security & Best Practices

- 🔒 Firebase Auth & token-based session management
- 🔐 Role-Based Access Control (RBAC)
- 🧼 Input sanitization to prevent XSS/SQL injection
- ⏳ Session management with expiry handling

---

## 📱 Responsive Design

Built with **mobile-first** principles using **Bootstrap**. Compatible with:
- 💻 Desktop
- 📱 Mobile
- 📱 Tablets

---

## 🛣️ Roadmap

- ✅ Advanced AI Models for specific legal domains
- 🔐 Enhanced verification for legal credentials
- 💳 Payment gateway for premium consultations
- 📄 Legal document AI analysis
- 📱 Native mobile apps (iOS + Android)

---

## 🤝 Contributing

We welcome contributions! 🎉  
Follow these steps:

```bash
# 1. Fork the repository
# 2. Create your branch
git checkout -b feature/amazing-feature

# 3. Commit your changes
git commit -m "Add some amazing feature"

# 4. Push to your fork
git push origin feature/amazing-feature

# 5. Open a Pull Request
```



## 🙏 Acknowledgements

- [Flask](https://flask.palletsprojects.com/)
- [Firebase](https://firebase.google.com/)
- [Google Gemini AI](https://ai.google.dev/)
- [Bootstrap](https://getbootstrap.com/)
- [Font Awesome](https://fontawesome.com/)

---

> © 2025 **LegalQA** — Revolutionizing legal assistance with AI and community expertise.
