import os
import re
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
from google import genai
import PyPDF2
import base64
import mimetypes
from dotenv import load_dotenv
import hashlib
import secrets

# ========== FIREBASE IMPORTS ==========
import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
from firebase_admin import auth

# Load environment variables from .env file
env_path = Path('.') / '.env'
loaded = load_dotenv(dotenv_path=env_path, override=True)

print(f"=== Environment Debug ===")
print(f".env file exists: {env_path.exists()}")
print(f".env loaded successfully: {loaded}")
api_key = os.environ.get('GEMINI_API_KEY', '')
print(f"API Key found: {'Yes' if api_key else 'No'}")
if api_key:
    print(f"API Key preview: {api_key[:20]}...{api_key[-4:]}")
print(f"========================\n")

# ========== INITIALIZE FIREBASE ==========
# Initialize Firebase with proper error handling
# Supports both file-based (local) and environment variable (Render) credentials
import json

def get_firebase_credentials():
    """Get Firebase credentials from file or environment variables"""
    # First try environment variable (for Render deployment)
    firebase_creds_json = os.environ.get('FIREBASE_CREDENTIALS')
    if firebase_creds_json:
        try:
            creds_dict = json.loads(firebase_creds_json)
            # Fix: Replace escaped newlines with actual newlines in private key
            if 'private_key' in creds_dict:
                creds_dict['private_key'] = creds_dict['private_key'].replace('\\n', '\n')
            print("[OK] Using Firebase credentials from environment variable")
            return credentials.Certificate(creds_dict)
        except Exception as e:
            print(f"[WARN] Failed to parse FIREBASE_CREDENTIALS: {e}")
    
    # Fall back to file (for local development)
    if os.path.exists('serviceAccountKey.json'):
        print("[OK] Using Firebase credentials from serviceAccountKey.json")
        return credentials.Certificate('serviceAccountKey.json')
    
    return None

try:
    firebase_admin.get_app()
    print("[OK] Firebase app already initialized")
except ValueError:
    # Firebase app doesn't exist, initialize it
    cred = get_firebase_credentials()
    if cred:
        try:
            firebase_admin.initialize_app(cred, {
                'databaseURL': 'https://zonezero-b4967-default-rtdb.firebaseio.com'
            })
            print("[OK] Firebase initialized successfully")
        except Exception as e:
            print(f"[ERROR] Firebase initialization failed: {str(e)}")
            print(f"Current directory: {os.getcwd()}")
            exit(1)
    else:
        print("[ERROR] No Firebase credentials found!")
        print("Set FIREBASE_CREDENTIALS env var or add serviceAccountKey.json")
        exit(1)

# ========== FLASK INITIALIZATION ==========
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB file limit

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ========== FIREBASE HELPER FUNCTIONS ==========

def hash_password(password):
    """Hash password using SHA256"""
    salt = secrets.token_hex(16)
    hash_obj = hashlib.sha256((salt + password).encode())
    return f"{salt}${hash_obj.hexdigest()}"

def verify_password(password, password_hash):
    """Verify password against hash"""
    try:
        salt, hash_val = password_hash.split('$')
        new_hash = hashlib.sha256((salt + password).encode()).hexdigest()
        return new_hash == hash_val
    except:
        return False

def generate_token():
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

def get_user_by_email(email):
    """Get user data from Firebase by email"""
    try:
        ref = db.reference('users')
        users = ref.get()
        
        if not users:
            return None
        
        for user_id, user_data in users.items():
            if user_data.get('email') == email:
                return user_id, user_data
        
        return None
    except Exception as e:
        print(f"[ERROR] get_user_by_email: {str(e)}")
        return None

def get_user_from_token(token):
    """Get user from session token"""
    if not token:
        return None
    
    try:
        ref = db.reference(f'sessions/{token}')
        session = ref.get()
        
        if session:
            # Check if token is expired
            expires_at = session.get('expires_at', 0)
            if expires_at > datetime.now().timestamp():
                return session.get('user_id')
        
        return None
    except Exception as e:
        print(f"[ERROR] get_user_from_token: {str(e)}")
        return None

# ========== AUTHENTICATION ROUTES ==========

@app.route("/api/auth/register", methods=["POST"])
def register():
    """Register new user"""
    data = request.json
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    full_name = data.get("fullName", "")
    
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    try:
        # Check if email already exists
        existing_user = get_user_by_email(email)
        if existing_user:
            return jsonify({"error": "Email already registered"}), 400
        
        # Create user in Firebase
        ref = db.reference('users')
        
        password_hash = hash_password(password)
        new_user = ref.push({
            'email': email,
            'password_hash': password_hash,
            'full_name': full_name,
            'created_at': datetime.now().isoformat()
        })
        
        user_id = new_user.key
        
        # Create session
        token = generate_token()
        expires_at = datetime.now().timestamp() + (30 * 24 * 60 * 60)  # 30 days
        
        session_ref = db.reference(f'sessions/{token}')
        session_ref.set({
            'user_id': user_id,
            'email': email,
            'expires_at': expires_at
        })
        
        return jsonify({
            "status": "success",
            "message": "Account created successfully",
            "token": token,
            "user": {"email": email, "fullName": full_name}
        }), 201
        
    except Exception as e:
        print(f"[ERROR] Register: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/auth/login", methods=["POST"])
def login():
    """Login user"""
    data = request.json
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    
    try:
        # Get user by email
        user_result = get_user_by_email(email)
        
        if not user_result:
            return jsonify({"error": "Invalid email or password"}), 401
        
        user_id, user_data = user_result
        
        # Verify password
        if not verify_password(password, user_data.get('password_hash', '')):
            return jsonify({"error": "Invalid email or password"}), 401
        
        # Create session
        token = generate_token()
        expires_at = datetime.now().timestamp() + (30 * 24 * 60 * 60)
        
        session_ref = db.reference(f'sessions/{token}')
        session_ref.set({
            'user_id': user_id,
            'email': email,
            'expires_at': expires_at
        })
        
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "token": token,
            "user": {
                "email": email,
                "fullName": user_data.get('full_name', '')
            }
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Login: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    """Logout user (optional token)"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        return jsonify({"status": "success", "message": "Logged out"}), 200
    
    try:
        session_ref = db.reference(f'sessions/{token}')
        session_ref.delete()
        return jsonify({"status": "success", "message": "Logged out successfully"}), 200
    except Exception as e:
        print(f"[ERROR] Logout: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/auth/verify", methods=["GET"])
def verify_token():
    """Verify token and get user info (optional)"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        return jsonify({"status": "not_authenticated"}), 200
    
    try:
        user_id = get_user_from_token(token)
        if not user_id:
            return jsonify({"status": "invalid_token"}), 401
        
        # Get user data
        user_ref = db.reference(f'users/{user_id}')
        user_data = user_ref.get()
        
        if user_data:
            return jsonify({
                "status": "success",
                "user": {
                    "email": user_data.get('email'),
                    "fullName": user_data.get('full_name')
                }
            }), 200
        
        return jsonify({"error": "User not found"}), 404
        
    except Exception as e:
        print(f"[ERROR] Verify: {str(e)}")
        return jsonify({"error": str(e)}), 500

# ========== SEARCH HISTORY FUNCTIONS ==========

def save_search_history(user_id, query, search_type):
    """Save search history to Firebase"""
    try:
        if user_id:
            ref = db.reference(f'search_history/{user_id}')
            ref.push({
                'query': query,
                'type': search_type,
                'timestamp': datetime.now().isoformat()
            })
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save history: {str(e)}")
        return False

def check_aribuddin_query(query):
    """Check if query is about MD.Aribuddin and return direct response"""
    if not query:
        return None
    
    query_lower = query.lower().strip()
    keywords = ['md.aribuddin', 'md aribuddin', 'aribuddin', 'md. aribuddin', 'founder', 'creator', 'developer']
    
    if any(keyword in query_lower for keyword in keywords):
        question_words = ['who is', 'about', 'tell me', 'information', 'details', 'creator', 'founder', 'developer', 'made this', 'created this']
        
        if any(word in query_lower for word in question_words) or 'aribuddin' in query_lower:
            return """## About MD.Aribuddin

**Mohammed.Aribuddin** is the **founder of ZoneZero AI Research Assistant**.

### Personal Information
- **Father:** Faizuddin
- **Mother:** Mubeenunnisa
- **Elder Sister:** Asfiya Kouser
- **From:** Nuthankal
- **School:** Vijaya Mary High School
- **Intermediate:** Narayana Junior College
- **Current Education:** Studying CSE at CMREC (CMR Engineering College)

### Contact
You can connect with him on social media:
- **Instagram:** @md_aribuddin_21

---
*He is the creator and visionary behind ZoneZero AI Research Assistant!*"""
    
    return None

# ========== SEARCH ROUTE ==========

@app.route("/api/search", methods=["POST"])
def handle_search():
    query = request.form.get("query", "").strip()
    file = request.files.get("file")
    image = request.files.get("image")
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    if not query and not file and not image:
        return jsonify({"error": "No input provided"}), 400

    report = ""
    citations = []

    # Get user_id if authenticated (optional)
    user_id = get_user_from_token(token) if token else None

    # CHECK FOR ARIBUDDIN QUERY FIRST (BEFORE AI OR FILE PROCESSING)
    aribuddin_response = check_aribuddin_query(query)
    if aribuddin_response and not file and not image:
        report = aribuddin_response
        citations = ["Source: ZoneZero AI Database - Founder Information"]
        usage_counter["reports_generated"] += 1
        
        # Save to database
        save_search_history(user_id, query, "Direct")
        
        return jsonify({
            "status": "success",
            "report": report,
            "citations": citations,
            "usage_count": usage_counter["reports_generated"],
        })

    # FILE / IMAGE MODE
    if file or image:
        content = ""
        
        if file:
            content = extract_content_from_file(file)
            
            if content.startswith("Error"):
                report = content
                citations.append("Source: Uploaded File (Error)")
            else:
                try:
                    print(f"[INFO] Analyzing file with AI: {file.filename}")
                    
                    if query:
                        ai_prompt = f"""Analyze this document and answer the question.

**Document Content:**
{content[:10000]}  

**User Question:** {query}

Please provide a detailed answer based on the document content."""
                    else:
                        ai_prompt = f"""Analyze this document and provide:

**Document Content:**
{content[:10000]}

1. A brief summary (2-3 sentences)
2. Key points or findings
3. If it contains code, explain what the code does
4. Any notable patterns or important information

Please format your response clearly."""
                    
                    report = generate_api_report(ai_prompt, [f"Uploaded File: {file.filename}"])
                    citations.append(f"Source: AI Analysis of {file.filename}")
                    
                except Exception as e:
                    print(f"[ERROR] AI analysis failed: {str(e)}")
                    relevant = content
                    
                    if query and query.lower() in content.lower():
                        index = content.lower().find(query.lower())
                        start = max(0, index - 500)
                        end = min(len(content), index + len(query) + 500)
                        relevant = content[start:end]
                    
                    java_code = extract_java_code(relevant if query else content)
                    
                    if java_code:
                        report = f"""## Local Code Extraction

**Query:** {query if query else "All Java code"}

```java
{java_code}
```

**Note:** Extracted Java code from uploaded file. AI analysis failed: {str(e)}"""
                    else:
                        report = f"""## File Content

**File:** {file.filename}

{content[:1000]}...

**Note:** Showing first 1000 characters. AI analysis failed: {str(e)}"""
                    
                    citations.append(f"Source: Uploaded File ({file.filename})")
        
        if image:
            try:
                print(f"[INFO] Processing uploaded image: {image.filename}")
                image_report = analyze_image_with_ai(image, query)
                
                if report:
                    report += f"\n\n---\n\n## Image Analysis\n\n{image_report}"
                else:
                    report = f"""## Image Analysis

**File:** {image.filename}

{image_report}"""
                
                citations.append(f"Source: AI Analysis of {image.filename}")
                
            except Exception as e:
                print(f"[ERROR] Image processing failed: {str(e)}")
                if not report:
                    report = f"⚠️ Image upload failed: {str(e)}"
                citations.append(f"Source: Uploaded Image (Error)")

    # AI RESEARCH MODE
    else:
        try:
            print(f"[INFO] Starting AI research for query: {query[:50]}...")
            sources = [f"User Query: {query}", get_fresh_data()]
            report = generate_api_report(query, sources)
            citations = ["Source 1: User Query", "Source 2: Live Data"]
            print(f"[SUCCESS] AI research completed")
        except Exception as e:
            print(f"[ERROR] AI research failed: {str(e)}")
            report = f"⚠️ **AI Research Error**\n\n{str(e)}"
            citations = ["Error occurred during AI research"]

    usage_counter["reports_generated"] += 1

    # Save search history to database
    search_type = "Local" if (file or image) else "AI"
    save_search_history(user_id, query or "File Upload", search_type)

    return jsonify({
        "status": "success",
        "report": report,
        "citations": citations,
        "usage_count": usage_counter["reports_generated"],
    })

# ========== HISTORY ROUTES ==========

@app.route("/api/history", methods=["GET"])
def get_history():
    """Get search history - filtered by user if logged in"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user_id = get_user_from_token(token) if token else None
    
    try:
        history = []
        
        if user_id:
            # Get this user's history
            ref = db.reference(f'search_history/{user_id}')
            items = ref.get()
            
            if items:
                for item_id, item_data in items.items():
                    history.append({
                        "id": item_id,
                        "query": item_data.get('query'),
                        "type": item_data.get('type'),
                        "timestamp": item_data.get('timestamp')
                    })
        
        # Sort by timestamp descending (newest first)
        history.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return jsonify({
            "history": history,
            "total": len(history)
        })
        
    except Exception as e:
        print(f"[ERROR] Failed to get history: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/history/clear", methods=["POST"])
def clear_history():
    """Clear search history - only for current user"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user_id = get_user_from_token(token) if token else None
    
    try:
        if user_id:
            ref = db.reference(f'search_history/{user_id}')
            ref.delete()
        
        return jsonify({"status": "success", "message": "History cleared"})
        
    except Exception as e:
        print(f"[ERROR] Clear history: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/history/<history_id>", methods=["DELETE"])
def delete_history_item(history_id):
    """Delete a specific history item - only if it belongs to current user"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user_id = get_user_from_token(token) if token else None
    
    try:
        if user_id:
            ref = db.reference(f'search_history/{user_id}/{history_id}')
            ref.delete()
            return jsonify({"status": "success", "message": "Item deleted"})
        
        return jsonify({"status": "error", "message": "Not authorized"}), 403
            
    except Exception as e:
        print(f"[ERROR] Delete history: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/usage", methods=["GET"])
def get_usage():
    return jsonify(usage_counter)

@app.route("/api/health", methods=["GET"])
def health_check():
    api_key_configured = bool(os.environ.get("GEMINI_API_KEY"))
    firebase_configured = firebase_admin.get_app() is not None
    return jsonify({
        "status": "healthy",
        "gemini_configured": api_key_configured,
        "firebase_configured": firebase_configured,
        "message": "All systems configured" if api_key_configured and firebase_configured else "⚠️ Some services not configured"
    })

# ========== HELPER FUNCTIONS ==================

MODEL_NAME = "gemini-1.5-flash-latest"

_client = None

def get_gemini_client():
    global _client
    if _client is None:
        api_key = os.environ.get("GEMINI_API_KEY") or os.getenv("GEMINI_API_KEY")
        
        if not api_key:
            from dotenv import load_dotenv
            load_dotenv(override=True)
            api_key = os.environ.get("GEMINI_API_KEY")
        
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in environment variables")
        
        print(f"[INFO] Initializing Gemini client with API key: {api_key[:20]}...")
        _client = genai.Client(api_key=api_key)
    return _client

usage_counter = {"reports_generated": 0}

def get_fresh_data():
    return "Live Data Source (Pathway): No new live data retrieved."

def extract_content_from_file(file):
    if not file or not file.filename:
        return "Error: No file provided"
    
    extension = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    
    if extension == "txt":
        try:
            return file.read().decode("utf-8", errors="ignore")
        except Exception as e:
            return f"Error reading TXT: {e}"
    
    if extension == "pdf":
        try:
            file.seek(0)
            reader = PyPDF2.PdfReader(file)
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
            return text if text.strip() else "PDF appears to be empty"
        except Exception as e:
            return f"Error reading PDF: {e}"
    
    return f"Unsupported file type: .{extension}. Upload .txt or .pdf only."

def extract_java_code(text):
    if not text or len(text.strip()) == 0:
        return ""
    
    patterns = [
        r'package\s+[\w\.]+;',
        r'import\s+[\w\.\*]+;',
        r'(?:public|private|protected)?\s*(?:static|final|abstract)?\s*(?:class|interface|enum)\s+\w+(?:<[^>]+>)?(?:\s+extends\s+\w+)?(?:\s+implements\s+[\w\s,]+)?\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}',
        r'(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*[\w<>\[\]]+\s+\w+\s*\([^)]*\)\s*(?:throws\s+[\w\s,]+)?\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}',
        r'(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*[\w<>\[\]]+\s+\w+\s*(?:=\s*[^;]+)?;'
    ]
    
    all_matches = []
    for pattern in patterns:
        matches = re.findall(pattern, text, re.DOTALL | re.MULTILINE)
        all_matches.extend(matches)
    
    return "\n\n".join(all_matches).strip() if all_matches else ""

def analyze_image_with_ai(image_file, query=None):
    try:
        image_file.seek(0)
        image_data = image_file.read()
        base64_image = base64.b64encode(image_data).decode('utf-8')
        
        mime_type = image_file.content_type or 'image/jpeg'
        
        print(f"[INFO] Analyzing image with AI (size: {len(image_data)} bytes, type: {mime_type})")
        
        if query:
            prompt = f"""Analyze this image and answer the following question:

**Question:** {query}

Please provide a detailed answer based on what you see in the image."""
        else:
            prompt = """Analyze this image and provide:

1. A detailed description of what you see
2. Any text visible in the image (OCR)
3. Key elements, objects, or patterns
4. If it contains code, diagrams, or technical content, explain it
5. Any other notable observations

Please be thorough and specific."""
        
        client = get_gemini_client()
        
        vision_models = [
            "models/gemini-2.5-flash",
            "models/gemini-2.0-flash-exp",
            "models/gemini-2.5-pro"
        ]
        
        for model_name in vision_models:
            try:
                print(f"[INFO] Trying vision model: {model_name}")
                
                response = client.models.generate_content(
                    model=model_name,
                    contents=[
                        {
                            "role": "user",
                            "parts": [
                                {"text": prompt},
                                {
                                    "inline_data": {
                                        "mime_type": mime_type,
                                        "data": base64_image
                                    }
                                }
                            ]
                        }
                    ]
                )
                
                print(f"[SUCCESS] Image analysis completed with {model_name}")
                return response.text
                
            except Exception as e:
                print(f"[WARN] Model {model_name} failed: {str(e)[:100]}")
                continue
        
        return "⚠️ Image analysis failed. All vision models returned errors."
        
    except Exception as e:
        print(f"[ERROR] Image analysis error: {str(e)}")
        return f"⚠️ Error analyzing image: {str(e)}"

def generate_api_report(query, sources):
    prompt = f"""You are an AI research assistant.

Generate a clear, structured research report with citations.

Topic:
{query}

Sources:
{chr(10).join(sources)}

Instructions:
- Start with a short summary (2-3 sentences)
- Provide key findings with citations [1], [2]
- Use clear headings and bullet points
- End with a references section

Format the response in Markdown."""

    try:
        client = get_gemini_client()
        
        models_to_try = [
            "models/gemini-2.5-flash",
            "models/gemini-2.0-flash",
            "models/gemini-2.5-pro",
            "models/gemini-2.0-flash-exp",
        ]
        
        for model_name in models_to_try:
            try:
                print(f"[INFO] Trying model: {model_name}")
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                )
                print(f"[SUCCESS] Model {model_name} worked!")
                return response.text
                
            except Exception as e:
                error_msg = str(e)
                print(f"[WARN] Model {model_name} failed: {error_msg[:150]}")
                
                if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
                    return f"""⚠️ **API Rate Limit Exceeded**

The Gemini API has temporarily limited requests.

**Solutions:**
1. Wait 60 seconds and try again
2. Get a new API key from https://aistudio.google.com/apikey

**Your query:** {query}

Please try again in a moment."""
                
                continue
        
        return f"""⚠️ **API Configuration Issue**

Could not connect to Gemini models. Please check:

1. Your GEMINI_API_KEY in .env file
2. API key has proper permissions
3. You haven't exceeded rate limits

**Your query:** {query}"""
        
    except ValueError as e:
        return f"⚠️ **Configuration Error**\n\n{str(e)}"
    except Exception as e:
        return f"⚠️ **Unexpected Error**\n\n{str(e)}"

if __name__ == "__main__":
    if not os.environ.get("GEMINI_API_KEY"):
        print("[WARNING] GEMINI_API_KEY not found!")
        print("AI research features will not work without an API key.")
        print("File upload features will still work.")
        print()
    else:
        print("[OK] GEMINI_API_KEY found")
    
    print(f"Starting Flask server on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)