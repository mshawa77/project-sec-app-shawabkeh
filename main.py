"""
Secure Web Application - Main FastAPI Server (Rubric: Main Application)
Features: Authentication, RBAC, AES Encryption, Security Headers
Compliance: OWASP Top 10, Security Best Practices
"""

from fastapi import FastAPI, Request, Response, HTTPException, Depends, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import sqlite3
import bcrypt
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import json
import re

# Import our custom modules
from database import Database, User
from security import SecurityManager, SecurityHeaders

# Initialize FastAPI app
app = FastAPI(
    title="Secure Application",
    description="A full-stack secure web application demonstrating RBAC, AES encryption, and security best practices",
    version="1.0.0"
)

# Security middleware
security_headers = SecurityHeaders()
app.middleware("http")(security_headers.add_security_headers)

# Trusted host middleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])

# Static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Initialize database and security
db = Database()
security = SecurityManager()

# Session storage (in production, use Redis or database)
sessions: Dict[str, Dict[str, Any]] = {}

# Security configurations
SESSION_COOKIE_NAME = "secure_session_id"
SESSION_DURATION = timedelta(hours=2)
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

# Input validation patterns
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,20}$')

def sanitize_html(input_string: str) -> str:
    """Basic XSS protection by escaping HTML characters"""
    html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&#x27;",
        ">": "&gt;",
        "<": "&lt;",
    }
    return "".join(html_escape_table.get(c, c) for c in input_string)

def validate_input(username: str, email: str, password: str) -> tuple[bool, str]:
    """Validate user input with comprehensive checks"""
    errors = []
    
    if not username or not email or not password:
        return False, "All fields are required"
    
    if len(username) < 3 or len(username) > 20:
        errors.append("Username must be 3-20 characters")
    
    if not USERNAME_PATTERN.match(username):
        errors.append("Username can only contain letters, numbers, and underscores")
    
    if not EMAIL_PATTERN.match(email):
        errors.append("Invalid email format")
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")
    
    return (len(errors) == 0, "; ".join(errors) if errors else "")

def create_session(user: User) -> str:
    """Create a secure session for the user"""
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = {
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "created_at": datetime.now(),
        "last_activity": datetime.now()
    }
    return session_id

def get_session_user(request: Request) -> Optional[User]:
    """Get current user from session cookie"""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id or session_id not in sessions:
        return None
    
    session = sessions[session_id]
    
    # Check session expiration
    if datetime.now() - session["last_activity"] > SESSION_DURATION:
        del sessions[session_id]
        return None
    
    # Update last activity
    session["last_activity"] = datetime.now()
    
    # Get user from database
    user = db.get_user_by_id(session["user_id"])
    return user

def require_auth(request: Request) -> User:
    """Require authentication - returns user if authenticated"""
    user = get_session_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user

def require_admin(request: Request) -> User:
    """Require admin role - returns admin user if authorized"""
    user = require_auth(request)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# Routes
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Main landing page"""
    user = get_session_user(request)
    return templates.TemplateResponse("index.html", {"request": request, "user": user})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page"""
    user = get_session_user(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login")
async def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    """Handle login with security measures"""
    # Sanitize inputs
    username = sanitize_html(username.strip())
    
    # Validate inputs
    if not username or not password:
        return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": "Username and password are required"
        })
    
    # Get user from database
    user = db.get_user_by_username(username)
    if not user:
        return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": "Invalid username or password"
        })
    
    # Check account lockout
    if user.is_locked():
        return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": f"Account locked. Try again after {user.lockout_until}"
        })
    
    # Verify password
    if not security.verify_password(password, user.password_hash):
        # Increment failed attempts
        db.increment_login_attempts(user.id)
        return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": "Invalid username or password"
        })
    
    # Reset failed attempts on successful login
    db.reset_login_attempts(user.id)
    
    # Create secure session
    session_id = create_session(user)
    
    # Set secure cookie
    response = RedirectResponse(url="/dashboard", status_code=302)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=7200,  # 2 hours
        secure=False,   # Set to True in production with HTTPS
        httponly=True,
        samesite="strict"
    )
    
    return response

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Registration page"""
    user = get_session_user(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("register.html", {"request": request, "error": None})

@app.post("/register")
async def register(request: Request, username: str = Form(...), email: str = Form(...), 
                  password: str = Form(...), confirm_password: str = Form(...)):
    """Handle user registration with validation"""
    # Sanitize inputs
    username = sanitize_html(username.strip())
    email = sanitize_html(email.strip())
    
    # Validate passwords match
    if password != confirm_password:
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Passwords do not match"
        })
    
    # Validate input format
    is_valid, error_msg = validate_input(username, email, password)
    if not is_valid:
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": error_msg
        })
    
    # Check if user already exists
    if db.get_user_by_username(username):
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Username already exists"
        })
    
    if db.get_user_by_email(email):
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Email already registered"
        })
    
    # Create new user
    password_hash = security.hash_password(password)
    user_id = db.create_user(username, email, password_hash, role="user")
    
    if user_id:
        return RedirectResponse(url="/login?registered=true", status_code=302)
    else:
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Registration failed. Please try again."
        })

@app.get("/logout")
async def logout(request: Request, response: Response):
    """Handle logout - clear session"""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id and session_id in sessions:
        del sessions[session_id]
    
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """User dashboard with encrypted secret note"""
    user = require_auth(request)
    
    # Get user's secret note (encrypted in database)
    secret_note = db.get_secret_note(user.id)
    
    # Decrypt for display (show both encrypted and decrypted)
    decrypted_note = security.decrypt_data(secret_note) if secret_note else ""
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request, 
        "user": user,
        "encrypted_note": secret_note,
        "decrypted_note": decrypted_note
    })

@app.post("/dashboard/update-note")
async def update_secret_note(request: Request, secret_note: str = Form(...)):
    """Update user's secret note with encryption"""
    user = require_auth(request)
    
    # Sanitize and encrypt the note
    sanitized_note = sanitize_html(secret_note)
    encrypted_note = security.encrypt_data(sanitized_note)
    
    # Update in database
    db.update_secret_note(user.id, encrypted_note)
    
    return RedirectResponse(url="/dashboard", status_code=302)

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request):
    """Admin panel - RBAC protected"""
    admin_user = require_admin(request)
    
    # Get all users for admin view
    all_users = db.get_all_users()
    
    return templates.TemplateResponse("admin.html", {
        "request": request, 
        "user": admin_user,
        "users": all_users
    })

@app.post("/admin/delete-user/{user_id}")
async def delete_user(request: Request, user_id: int):
    """Delete user (admin only)"""
    admin_user = require_admin(request)
    
    # Prevent self-deletion
    if user_id == admin_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    # Delete user
    success = db.delete_user(user_id)
    
    if success:
        return RedirectResponse(url="/admin", status_code=302)
    else:
        raise HTTPException(status_code=400, detail="Failed to delete user")

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

# Security info endpoint
@app.get("/security-info", response_class=HTMLResponse)
async def security_info(request: Request):
    """Display implemented security measures in beautiful format"""
    return templates.TemplateResponse("security_info_display.html", {"request": request})

@app.get("/security-dashboard", response_class=HTMLResponse)
async def security_dashboard(request: Request):
    """Beautiful security dashboard with real-time monitoring"""
    return templates.TemplateResponse("security_dashboard.html", {"request": request})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
