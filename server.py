from fastapi import FastAPI, APIRouter, HTTPException, Depends, Form, Body, File, UploadFile, Response
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from pathlib import Path
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from psycopg2.pool import SimpleConnectionPool
import psycopg2, psycopg2.extras
import os, time, io, json
from PIL import Image, ImageDraw, ImageFont

from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError
from fastapi.exceptions import RequestValidationError
import secrets
import random
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
import base64

# ==================== ENV & APP ====================
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")



SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

app = FastAPI(title="LMS API", version="1.0.0")

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    print(f"Validation Error: {exc.errors()}")
    detail = []
    for error in exc.errors():
        loc = " -> ".join([str(l) for l in error.get("loc", [])])
        msg = error.get("msg")
        detail.append(f"{loc}: {msg}")
    return JSONResponse(
        status_code=422,
        content={"detail": ", ".join(detail), "body": str(exc.body)},
    )

# ==================== CORS ====================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# ==================== MODELS ====================
class ReorderRequest(BaseModel):
    ids: List[str]

api_router = APIRouter(prefix="/api")

security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ==================== DB POOL ====================
pool = SimpleConnectionPool(
    1, 20,
    host=os.getenv("POSTGRES_HOST"),
    port=os.getenv("POSTGRES_PORT"),
    dbname=os.getenv("POSTGRES_DB"),
    user=os.getenv("POSTGRES_USER"),
    password=os.getenv("POSTGRES_PASSWORD")
)

def get_db():
    conn = pool.getconn()
    try:
        yield conn
    finally:
        pool.putconn(conn)

TABLE_SCHEMAS = {
    "lms_users": """
        CREATE TABLE IF NOT EXISTS lms_users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT DEFAULT 'student',
            profile JSONB DEFAULT '{"bio": "", "avatar": null}'::jsonb,
            interests JSONB DEFAULT '[]'::jsonb,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "lms_courses": """
        CREATE TABLE IF NOT EXISTS lms_courses (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            difficulty TEXT,
            tags JSONB,
            thumbnail TEXT,
            created_by TEXT,
            created_at TIMESTAMP,
            is_published BOOLEAN DEFAULT FALSE,
            thumbnail_id TEXT
        )
    """,
    "lms_media_files": """
        CREATE TABLE IF NOT EXISTS lms_media_files (
            id TEXT PRIMARY KEY,
            file_name TEXT NOT NULL,
            file_type TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            file_data BYTEA NOT NULL,
            file_size INTEGER NOT NULL,
            uploaded_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "lms_modules": """
        CREATE TABLE IF NOT EXISTS lms_modules (
            id TEXT PRIMARY KEY,
            course_id TEXT REFERENCES lms_courses(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            order_index INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "lms_sessions": """
        CREATE TABLE IF NOT EXISTS lms_sessions (
            id TEXT PRIMARY KEY,
            course_id TEXT REFERENCES lms_courses(id) ON DELETE CASCADE,
            module_id TEXT NOT NULL,
            name TEXT NOT NULL,
            duration_minutes INTEGER DEFAULT 0,
            content_type TEXT NOT NULL,
            content_url TEXT,
            image_url TEXT,
            content_text TEXT,
            quiz_id TEXT,
            media_id TEXT,
            is_document_available BOOLEAN DEFAULT FALSE,
            session_index INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "lms_notifications": """
        CREATE TABLE IF NOT EXISTS lms_notifications (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT NOT NULL,
            read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "lms_learning_paths": """
        CREATE TABLE IF NOT EXISTS lms_learning_paths (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            course_ids JSONB DEFAULT '[]'::jsonb,
            target_interests JSONB DEFAULT '[]'::jsonb,
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,

    "lms_quizzes": """
        CREATE TABLE IF NOT EXISTS lms_quizzes (
            id TEXT PRIMARY KEY,
            course_id TEXT,
            module_id TEXT,
            session_id TEXT,
            title TEXT NOT NULL,
            questions JSONB DEFAULT '[]'::jsonb,
            passing_score INTEGER DEFAULT 70,
            time_limit_minutes INTEGER DEFAULT 30,
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "lms_quiz_attempts": """
        CREATE TABLE IF NOT EXISTS lms_quiz_attempts (
            id TEXT PRIMARY KEY,
            quiz_id TEXT,
            session_id TEXT,
            user_id TEXT,
            score INTEGER,
            passed BOOLEAN,
            responses JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "lms_discussions": """
        CREATE TABLE IF NOT EXISTS lms_discussions (
            id TEXT PRIMARY KEY,
            course_id TEXT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_id TEXT,
            author_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "lms_replies": """
        CREATE TABLE IF NOT EXISTS lms_replies (
            id TEXT PRIMARY KEY,
            discussion_id TEXT REFERENCES lms_discussions(id) ON DELETE CASCADE,
            content TEXT NOT NULL,
            author_id TEXT,
            author_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "lms_expert_questions": """
        CREATE TABLE IF NOT EXISTS lms_expert_questions (
            id TEXT PRIMARY KEY,
            course_id TEXT,
            question TEXT NOT NULL,
            asked_by TEXT,
            asked_by_name TEXT,
            answer TEXT,
            answered_by TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "lms_certificates": """
        CREATE TABLE IF NOT EXISTS lms_certificates (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            course_id TEXT NOT NULL,
            issue_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            certificate_url TEXT
        )
    """,
    "lms_session_progress": """
        CREATE TABLE IF NOT EXISTS lms_session_progress (
            id TEXT PRIMARY KEY, 
            user_id TEXT, 
            session_id TEXT, 
            course_id TEXT, 
            module_id TEXT, 
            completed BOOLEAN DEFAULT FALSE, 
            time_spent_minutes INTEGER DEFAULT 0, 
            time_taken_seconds INTEGER DEFAULT 0,
            quiz_marks INTEGER,
            last_position_seconds INTEGER DEFAULT 0,
            highest_position_seconds INTEGER DEFAULT 0,
            completed_at TIMESTAMP, 
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
            UNIQUE(user_id, session_id)
        )
    """,
    "lms_user_courses": """
        CREATE TABLE IF NOT EXISTS lms_user_courses (
            user_id TEXT REFERENCES lms_users(id) ON DELETE CASCADE,
            course_id TEXT REFERENCES lms_courses(id) ON DELETE CASCADE,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active',
            progress_percentage INTEGER DEFAULT 0,
            is_completed BOOLEAN DEFAULT FALSE,
            PRIMARY KEY (user_id, course_id)
        )
    """,
    "lms_user_learning_paths": """
        CREATE TABLE IF NOT EXISTS lms_user_learning_paths (
            user_id TEXT REFERENCES lms_users(id) ON DELETE CASCADE,
            path_id TEXT REFERENCES lms_learning_paths(id) ON DELETE CASCADE,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active',
            is_completed BOOLEAN DEFAULT FALSE,
            PRIMARY KEY (user_id, path_id)
        )
    """,
    "lms_certificate_templates": """
        CREATE TABLE IF NOT EXISTS lms_certificate_templates (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            background_media_id TEXT,
            placeholders JSONB,
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "lms_issued_certificates": """
        CREATE TABLE IF NOT EXISTS lms_issued_certificates (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            path_id TEXT,
            course_id TEXT,
            template_id TEXT NOT NULL,
            image_media_id TEXT,
            placeholder_data JSONB,
            issued_by TEXT,
            issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "lms_reset_tokens": """
        CREATE TABLE IF NOT EXISTS lms_reset_tokens (
            email TEXT NOT NULL,
            token TEXT NOT NULL,
            gen_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_used BOOLEAN DEFAULT FALSE
        )
    """,
    "lms_otps": """
        CREATE TABLE IF NOT EXISTS lms_otps (
            email TEXT NOT NULL,
            otp TEXT NOT NULL,
            gen_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_used BOOLEAN DEFAULT FALSE
        )
    """
}

# ==================== DB INIT ====================
def init_db():
    print("🚀 Initializing database tables...")
    conn = pool.getconn()
    try:
        cur = conn.cursor()
        for table_name, schema in TABLE_SCHEMAS.items():
            print(f"  - Ensuring table: {table_name}")
            cur.execute(schema)
            
        # Run migrations for lms_session_progress
        cur.execute("ALTER TABLE lms_session_progress ADD COLUMN IF NOT EXISTS time_taken_seconds INTEGER DEFAULT 0;")
        cur.execute("ALTER TABLE lms_session_progress ADD COLUMN IF NOT EXISTS quiz_marks INTEGER;")
        cur.execute("ALTER TABLE lms_session_progress ADD COLUMN IF NOT EXISTS last_position_seconds INTEGER DEFAULT 0;")
        cur.execute("ALTER TABLE lms_session_progress ADD COLUMN IF NOT EXISTS highest_position_seconds INTEGER DEFAULT 0;")
        
        # Run migrations for lms_user_courses
        cur.execute("ALTER TABLE lms_user_courses ADD COLUMN IF NOT EXISTS progress_percentage INTEGER DEFAULT 0;")
        cur.execute("ALTER TABLE lms_user_courses ADD COLUMN IF NOT EXISTS is_completed BOOLEAN DEFAULT FALSE;")
        
        # Run migrations for lms_issued_certificates
        cur.execute("ALTER TABLE lms_issued_certificates ADD COLUMN IF NOT EXISTS image_media_id TEXT;")
        
        conn.commit()
        print("✅ Database initialization complete.")
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        conn.rollback()
    finally:
        pool.putconn(conn)

@app.on_event("startup")
async def startup_event():
    init_db()

# ==================== HELPERS ====================
def generate_id():
    return str(int(time.time() * 1000))

def update_course_progress(db, user_id, course_id):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Check if user is enrolled
        cur.execute("SELECT * FROM lms_user_courses WHERE user_id=%s AND course_id=%s", (user_id, course_id))
        if not cur.fetchone():
            return
            
        # 1. Total sessions in course
        cur.execute("SELECT count(*) as total FROM lms_sessions WHERE course_id=%s", (course_id,))
        total_sessions_row = cur.fetchone()
        total_sessions = int(total_sessions_row["total"]) if total_sessions_row else 0
        
        if total_sessions == 0:
            cur.execute("UPDATE lms_user_courses SET progress_percentage=0, is_completed=false WHERE user_id=%s AND course_id=%s", (user_id, course_id))
            db.commit()
            return

        # 2. Total modules in course
        cur.execute("SELECT count(*) as total FROM lms_modules WHERE course_id=%s", (course_id,))
        total_modules_row = cur.fetchone()
        total_modules = int(total_modules_row["total"]) if total_modules_row else 0

        # 3. Completed sessions for user
        cur.execute("SELECT count(*) as completed FROM lms_session_progress WHERE user_id=%s AND course_id=%s AND completed=true", (user_id, course_id))
        completed_sessions_row = cur.fetchone()
        completed_sessions = int(completed_sessions_row["completed"]) if completed_sessions_row else 0
        
        # 4. Calc percentage based on sessions (for internal tracking/sorting)
        pct = int((float(completed_sessions) / float(total_sessions)) * 100)
        is_completed = pct >= 100
        
        # 5. Update table (we still use percentage for the progress bar width, but UI will show module count)
        cur.execute("UPDATE lms_user_courses SET progress_percentage=%s, is_completed=%s WHERE user_id=%s AND course_id=%s", (pct, is_completed, user_id, course_id))
        db.commit()
        
        # 6. If course completed, check any learning paths assigned to user that contain this course
        if is_completed:
            cur.execute("""
                SELECT path_id FROM lms_user_learning_paths 
                WHERE user_id=%s
            """, (user_id,))
            assigned_paths = cur.fetchall()
            for p in assigned_paths:
                check_path_completion(db, user_id, p["path_id"])
                
    except Exception as e:
        print(f"Error updating course progress: {e}")
        db.rollback()

def check_path_completion(db, user_id, path_id):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Get learning path courses
        cur.execute("SELECT course_ids FROM lms_learning_paths WHERE id=%s", (path_id,))
        path = cur.fetchone()
        if not path:
            return
            
        course_ids = path["course_ids"]
        if isinstance(course_ids, str):
            course_ids = json.loads(course_ids)
            
        if not course_ids:
            return
            
        # Check if all these courses are completed for this user
        # We only care about courses in the path
        placeholders = ', '.join(['%s'] * len(course_ids))
        cur.execute(f"""
            SELECT count(*) FROM lms_user_courses 
            WHERE user_id=%s AND course_id IN ({placeholders}) AND is_completed=true
        """, (user_id, *course_ids))
        completed_count = cur.fetchone()["count"]
        
        is_completed = completed_count >= len(course_ids)
        
        cur.execute("""
            UPDATE lms_user_learning_paths 
            SET is_completed=%s 
            WHERE user_id=%s AND path_id=%s
        """, (is_completed, user_id, path_id))
        db.commit()
    except Exception as e:
        print(f"Error checking path completion: {e}")
        db.rollback()


# ==================== MODELS ====================
class UserCreate(BaseModel):
    email: str
    password: str
    name: str
    role: str = "student"
    interests: List[str] = []

class CourseCreate(BaseModel):
    title: str
    description: str
    difficulty: str = "beginner"
    tags: List[str] = []
    thumbnail: Optional[str] = None
    is_published: bool = False

class ModuleContent(BaseModel):
    id: str = Field(default_factory=generate_id)
    title: str
    content_type: str
    content_url: Optional[str] = None
    content_text: Optional[str] = None
    duration_minutes: int = 10
    order: int = 0

class LearningPathCreate(BaseModel):
    title: str
    description: str
    course_ids: List[str]
    target_interests: List[str] = []

class CertificateTemplateCreate(BaseModel):
    name: str
    background_media_id: str
    placeholders: List[Dict[str, Any]]

class CertificateIssue(BaseModel):
    user_id: str
    template_id: str
    path_id: Optional[str] = None
    course_id: Optional[str] = None
    placeholder_data: Dict[str, Any] = {}

class ProgressUpdate(BaseModel):
    course_id: str
    module_id: str
    completed: bool
    time_spent: int = 0

class SessionCreate(BaseModel):
    course_id: str
    module_id: str
    name: str
    duration_minutes: int
    content_type: str
    content_text: Optional[str] = None
    quiz_id: Optional[str] = None

# ==================== AUTH HELPERS ====================
def get_password_hash(password): return pwd_context.hash(password)
def verify_password(p, h): return pwd_context.verify(p, h)

def create_access_token(data):
    data["exp"] = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db=Depends(get_db)
):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        uid = payload.get("sub")
        cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(TABLE_SCHEMAS["lms_users"])
        cur.execute("SELECT * FROM lms_users WHERE id=%s", (uid,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(401, "User not found")
        return user
    except JWTError:
        raise HTTPException(401, "Invalid token")

def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Admin only")
    return user

# ==================== NOTIFICATIONS & EMAIL ====================
def create_notification(uid, msg, ntype, db):
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["lms_notifications"])
    cur.execute("""
        INSERT INTO lms_notifications
        (id, user_id, message, type, read, created_at)
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (generate_id(), uid, msg, ntype, False, datetime.now()))
    db.commit()

# Brevo Configuration
configuration = sib_api_v3_sdk.Configuration()
configuration.api_key['api-key'] = os.getenv("SENDINBLUE_KEY")
api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))

def get_email_template(content_html, title="LMS-PLSRD"):
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8fafc; margin: 0; padding: 0; color: #1e293b; }}
            .container {{ max-width: 600px; margin: 40px auto; background: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }}
            .header {{ background-color: #6366f1; padding: 32px; text-align: center; }}
            .header h1 {{ margin: 0; color: #ffffff; font-size: 24px; font-weight: 700; }}
            .content {{ padding: 40px; line-height: 1.6; }}
            .item-content {{ font-size: 16px; color: #1e293b; margin-bottom: 24px; }}
            .footer {{ background-color: #f1f5f9; padding: 24px; text-align: center; color: #64748b; font-size: 14px; border-top: 1px solid #e2e8f0; }}
            .button {{ display: inline-block; padding: 14px 28px; background-color: #6366f1; color: #ffffff !important; text-decoration: none; border-radius: 8px; font-weight: 600; margin-top: 10px; }}
            .otp-box {{ background-color: #f1f5f9; padding: 24px; border-radius: 12px; text-align: center; margin: 24px 0; font-size: 32px; font-weight: 700; color: #6366f1; letter-spacing: 4px; }}
            .warning {{ font-size: 13px; color: #94a3b8; margin-top: 32px; border-top: 1px solid #f1f5f9; padding-top: 16px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>{title}</h1>
            </div>
            <div class="content">
                {content_html}
            </div>
            <div class="footer">
                &copy; {datetime.now().year} LMS-PLSRD. All rights reserved.
            </div>
        </div>
    </body>
    </html>
    """

def send_mail(subject, to_email, html_content):
    try:
        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
            to=[{"email": to_email}],
            sender={"email": 'sanketsawant4123@gmail.com', "name": "LMS-PLSRD"},
            subject=subject,
            html_content=html_content
        )
        api_instance.send_transac_email(send_smtp_email)
        return True
    except Exception as e:
        print(f"❌ Error sending email to {to_email}: {e}")
        return False

# ==================== AUTH ROUTES ====================
@api_router.post("/auth/register")
def register(user: UserCreate, db=Depends(get_db)):
    print(f"DEBUG: Registering user: {user.email}")
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["lms_users"])
        cur.execute("SELECT 1 FROM lms_users WHERE email=%s", (user.email.lower(),))
        if cur.fetchone():
            print(f"DEBUG: Email already exists: {user.email}")
            raise HTTPException(400, f"Account with email '{user.email}' already exists.")

        uid = generate_id()
        cur.execute("""
            INSERT INTO lms_users
            (id,email,password_hash,name,role,profile,interests,created_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            uid, user.email.lower(),
            # get_password_hash(user.password),
            user.password,
            user.name, user.role,
            psycopg2.extras.Json({"bio":"", "avatar":None}),
            psycopg2.extras.Json(user.interests),
            datetime.now()
        ))
        db.commit()
        print(f"DEBUG: User created successfully: {uid}")
    except HTTPException:
        raise
    except Exception as e:
        print(f"DEBUG: Registration failed: {e}")
        db.rollback()
        raise HTTPException(500, str(e))
    
    # Fetch the created user to return user data
    cur.execute("SELECT * FROM lms_users WHERE id=%s", (uid,))
    new_user = cur.fetchone()
    user_data = dict(new_user)
    user_data.pop("password_hash", None)
    
    # Send welcome email for students
    if user.role == "student":
        login_link = "http://localhost:8081"
        email_content = f"""
        <div class="item-content">
            <p>Hello <b>{user.name}</b>,</p>
            <p>Your student account has been created successfully for <b>LMS-PLSRD</b>. You can now access your learning dashboard using the credentials below:</p>
            <div class="otp-box" style="font-size: 16px; text-align: left; padding: 20px; letter-spacing: normal;">
                <p style="margin: 0; color: #475569;"><b>Email:</b> {user.email.lower()}</p>
                <p style="margin: 8px 0 0 0; color: #475569;"><b>Password:</b> {user.password}</p>
            </div>
            <p style="text-align: center; margin-top: 30px;">
                <a href="{login_link}" class="button">Login Now</a>
            </p>
            <p>We recommend changing your password after your first login.</p>
        </div>
        """
        send_mail(
            "Welcome to LMS-PLSRD", 
            user.email.lower(), 
            get_email_template(email_content, "Account Created")
        )

    return {
        "access_token": create_access_token({"sub": uid}),
        "user": user_data
    }

@api_router.post("/auth/login")
def login(data: Dict[str,str], db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["lms_users"])
    cur.execute("SELECT * FROM lms_users WHERE email=%s", (data["email"].lower(),))
    user = cur.fetchone()
    if not user:
        raise HTTPException(404, "Account not found")
    if not data["password"] == user["password_hash"]:
        raise HTTPException(401, "Invalid password")
    
    # Remove sensitive data from user object
    user_data = dict(user)
    user_data.pop("password_hash", None)
    
    return {
        "access_token": create_access_token({"sub": user["id"]}),
        "user": user_data
    }

@api_router.post("/auth/forgot-password")
def forgot_password(data: Dict[str, str], db=Depends(get_db)):
    email = data.get("email", "").lower()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM lms_users WHERE email=%s", (email,))
    user = cur.fetchone()
    if not user:
        raise HTTPException(404, "Account not found")

    token = secrets.token_urlsafe(32)
    cur.execute(TABLE_SCHEMAS["lms_reset_tokens"])
    cur.execute("INSERT INTO lms_reset_tokens (email, token) VALUES (%s, %s)", (email, token))
    db.commit()

    # In production, replace with your actual frontend domain
    reset_link = f"http://localhost:8081/reset-password?email={email}&token={token}"
    
    email_content = f"""
    <div class="item-content">
        <p>Hello,</p>
        <p>We received a request to reset your password for your <b>LMS-PLSRD</b> account. Click the button below to set a new password:</p>
        <p style="text-align: center;">
            <a href="{reset_link}" class="button">Reset Password</a>
        </p>
        <p>If you did not request a password reset, please ignore this email.</p>
        <p>This link will expire in 15 minutes.</p>
    </div>
    <div class="warning">
        <p>If you're having trouble clicking the password reset button, copy and paste the URL below into your web browser:<br>
        <small>{reset_link}</small></p>
    </div>
    """
    
    if send_mail("Reset Your Password", email, get_email_template(email_content)):
        return {"message": "Reset email sent"}
    else:
        raise HTTPException(500, "Failed to send email")

@api_router.post("/auth/reset-password")
def reset_password(data: Dict[str, str], db=Depends(get_db)):
    email = data.get("email", "").lower()
    token = data.get("token")
    new_password = data.get("password")

    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT * FROM lms_reset_tokens 
        WHERE email=%s AND token=%s AND is_used=FALSE 
        AND gen_time > NOW() - INTERVAL '15 minutes'
    """, (email, token))
    
    if not cur.fetchone():
        raise HTTPException(400, "Invalid or expired token")

    cur.execute("UPDATE lms_users SET password_hash=%s WHERE email=%s", (new_password, email))
    cur.execute("UPDATE lms_reset_tokens SET is_used=TRUE WHERE email=%s AND token=%s", (email, token))
    db.commit()
    return {"message": "Password updated successfully"}

@api_router.post("/auth/send-otp")
def send_otp(data: Dict[str, str], db=Depends(get_db)):
    email = data.get("email", "").lower()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM lms_users WHERE email=%s", (email,))
    user = cur.fetchone()
    if not user:
        raise HTTPException(404, "Account not found")

    otp = str(random.randint(1000, 9999))
    cur.execute(TABLE_SCHEMAS["lms_otps"])
    cur.execute("INSERT INTO lms_otps (email, otp) VALUES (%s, %s)", (email, otp))
    db.commit()

    email_content = f"""
    <div class="item-content">
        <p>Hello,</p>
        <p>Your one-time password (OTP) for logging into <b>LMS-PLSRD</b> is:</p>
        <div class="otp-box">{otp}</div>
        <p>This code will expire in 5 minutes.</p>
        <p>If you did not request this OTP, please ignore this email.</p>
    </div>
    """
    
    if send_mail("Your Login OTP", email, get_email_template(email_content)):
        return {"message": "OTP sent"}
    else:
        raise HTTPException(500, "Failed to send OTP")

@api_router.post("/auth/login-otp")
def login_otp(data: Dict[str, str], db=Depends(get_db)):
    email = data.get("email", "").lower()
    otp = data.get("otp")

    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT * FROM lms_otps 
        WHERE email=%s AND otp=%s AND is_used=FALSE 
        AND gen_time > NOW() - INTERVAL '5 minutes'
        ORDER BY gen_time DESC LIMIT 1
    """, (email, otp))
    
    if not cur.fetchone():
        raise HTTPException(401, "Invalid or expired OTP")

    cur.execute("UPDATE lms_otps SET is_used=TRUE WHERE email=%s AND otp=%s", (email, otp))
    
    cur.execute("SELECT * FROM lms_users WHERE email=%s", (email,))
    user = cur.fetchone()
    db.commit()

    user_data = dict(user)
    user_data.pop("password_hash", None)

    return {
        "access_token": create_access_token({"sub": user["id"]}),
        "user": user_data
    }

@api_router.get("/auth/me")
def get_me(user=Depends(get_current_user)):
    user_data = dict(user)
    user_data.pop("password_hash", None)
    return user_data

class ProfileUpdate(BaseModel):
    interests: List[str]

@api_router.put("/auth/profile")
def update_profile(
    data: ProfileUpdate,
    name: Optional[str] = None,
    bio: Optional[str] = None,
    user=Depends(get_current_user),
    db=Depends(get_db)
):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["lms_users"])
    profile = user["profile"] or {"bio": "", "avatar": None}
    if bio is not None:
        profile["bio"] = bio
    
    cur.execute("""
        UPDATE lms_users SET 
        name=COALESCE(%s, name),
        profile=%s,
        interests=%s
        WHERE id=%s
    """, (name, psycopg2.extras.Json(profile), psycopg2.extras.Json(data.interests), user["id"]))
    db.commit()
    
    cur.execute("SELECT * FROM lms_users WHERE id=%s", (user["id"],))
    updated_user = cur.fetchone()
    user_data = dict(updated_user)
    user_data.pop("password_hash", None)
    return user_data

# ==================== COURSES ====================
@api_router.post("/courses")
def create_course(
    title: str = Form(...),
    description: str = Form(...),
    difficulty: str = Form("beginner"),
    tags: str = Form("[]"),
    thumbnail: Optional[str] = Form(None),
    thumbnail_id: Optional[str] = Form(None),
    is_published: str = Form("false"),
    admin=Depends(require_admin),
    db=Depends(get_db)
):
    import json
    tags_list = json.loads(tags)
    is_pub_bool = is_published.lower() == "true"
    
    cid = generate_id()
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["lms_courses"])
    cur.execute("""
        INSERT INTO lms_courses (id, title, description, difficulty, tags, thumbnail, thumbnail_id, created_by, created_at, is_published)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        cid, title, description,
        difficulty,
        psycopg2.extras.Json(tags_list),
        thumbnail, thumbnail_id, admin["id"],
        datetime.now(), is_pub_bool
    ))
    db.commit()
    
    # Return the full course object
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM lms_courses WHERE id=%s", (cid,))
    course = cur.fetchone()
    course["modules"] = []
    return course

@api_router.get("/courses")
def get_courses(db=Depends(get_db), user=Depends(get_current_user)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    query = """
        SELECT c.*, 
               COALESCE(SUM(s.duration_minutes), 0) as total_duration,
               COALESCE(COUNT(DISTINCT s.id), 0) as session_count,
                (CASE WHEN uc.user_id IS NOT NULL THEN TRUE ELSE FALSE END) as is_assigned,
               uc.status as access_status
        FROM lms_courses c
        LEFT JOIN lms_sessions s ON c.id = s.course_id
        LEFT JOIN lms_user_courses uc ON c.id = uc.course_id AND uc.user_id = %s
    """
    
    params = [user["id"]]
    if user["role"] != "admin":
        query += " WHERE c.is_published=true"
        
    query += " GROUP BY c.id, uc.user_id, uc.status"
    
    cur.execute(query, tuple(params))
    courses = cur.fetchall()
    
    cur.execute("SELECT * FROM lms_modules ORDER BY order_index ASC")
    all_modules = cur.fetchall()
    modules_by_course = {}
    for m in all_modules:
        cid = m["course_id"]
        if cid not in modules_by_course:
            modules_by_course[cid] = []
        modules_by_course[cid].append(m)
    
    # Also add module count if not apparent from modules json
    for course in courses:
        modules = modules_by_course.get(course["id"], [])
        course["modules"] = modules
        course["module_count"] = len(modules)
        
    return courses

@api_router.get("/courses/{cid}")
def get_course(cid: str, db=Depends(get_db), user=Depends(get_current_user)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT c.*, 
               (CASE WHEN uc.user_id IS NOT NULL THEN TRUE ELSE FALSE END) as is_assigned,
               uc.status as access_status
        FROM lms_courses c
        LEFT JOIN lms_user_courses uc ON c.id = uc.course_id AND uc.user_id = %s
        WHERE c.id=%s
    """, (user["id"], cid))
    course = cur.fetchone()
    if not course:
        raise HTTPException(404, "Course not found")
        
    if user["role"] != "admin" and course["is_assigned"] and course["access_status"] == 'frozen':
        raise HTTPException(403, "This course has been frozen by administration. You cannot access it at this time.")

    # Fetch modules
    cur.execute("SELECT * FROM lms_modules WHERE course_id=%s ORDER BY order_index ASC", (cid,))
    modules = cur.fetchall()
        
    # Fetch all sessions for this course to calculate module stats
    cur.execute("SELECT module_id, duration_minutes FROM lms_sessions WHERE course_id=%s", (cid,))
    all_sessions = cur.fetchall()
    
    # Aggregate stats
    stats = {}
    for s in all_sessions:
        mid = s["module_id"]
        if mid not in stats:
            stats[mid] = {"session_count": 0, "total_duration": 0}
        stats[mid]["session_count"] += 1
        stats[mid]["total_duration"] += s["duration_minutes"]
        
    # Inject stats into modules
    for m in modules:
        m_stats = stats.get(m["id"], {"session_count": 0, "total_duration": 0})
        m["session_count"] = m_stats["session_count"]
        m["total_duration"] = m_stats["total_duration"]

    if user["role"] != "admin" and not course["is_assigned"]:
        # Limited info for unassigned courses but include modules as requested
        return {
            "id": course["id"],
            "title": course["title"],
            "description": course["description"],
            "difficulty": course["difficulty"],
            "tags": course["tags"],
            "thumbnail": course["thumbnail"],
            "is_assigned": False,
            "modules": modules
        }
    
    course["modules"] = modules
    return course

@api_router.put("/courses/{cid}")
def update_course(
    cid: str,
    title: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    difficulty: Optional[str] = Form(None),
    tags: Optional[str] = Form(None),
    thumbnail: Optional[str] = Form(None),
    thumbnail_id: Optional[str] = Form(None),
    is_published: Optional[str] = Form(None),
    admin=Depends(require_admin),
    db=Depends(get_db)
):
    cur = db.cursor()
    
    updates = []
    values = []
    
    if title is not None:
        updates.append("title=%s")
        values.append(title)
    if description is not None:
        updates.append("description=%s")
        values.append(description)
    if difficulty is not None:
        updates.append("difficulty=%s")
        values.append(difficulty)
    if tags is not None:
        import json
        updates.append("tags=%s")
        values.append(psycopg2.extras.Json(json.loads(tags)))
    if thumbnail is not None:
        updates.append("thumbnail=%s")
        values.append(thumbnail)
    if thumbnail_id is not None:
        updates.append("thumbnail_id=%s")
        values.append(thumbnail_id)
    if is_published is not None:
        updates.append("is_published=%s")
        values.append(is_published.lower() == "true")
        
    if not updates:
        # Return the full course object
        cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM lms_courses WHERE id=%s", (cid,))
        course = cur.fetchone()
        cur.execute("SELECT * FROM lms_modules WHERE course_id=%s ORDER BY order_index ASC", (cid,))
        course["modules"] = cur.fetchall()
        return course

    query = "UPDATE lms_courses SET " + ", ".join(updates) + " WHERE id=%s RETURNING *"
    values.append(cid)
    
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(query, tuple(values))
    updated_course = cur.fetchone()
    db.commit()

    # Get modules to complete the course object
    cur.execute("SELECT * FROM lms_modules WHERE course_id=%s ORDER BY order_index ASC", (cid,))
    updated_course["modules"] = cur.fetchall()
    
    return updated_course
    
    # Return the full course object
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM lms_courses WHERE id=%s", (cid,))
    course = cur.fetchone()
    cur.execute("SELECT * FROM lms_modules WHERE course_id=%s ORDER BY order_index ASC", (cid,))
    course["modules"] = cur.fetchall()
    return course

@api_router.put("/courses/{cid}/publish")
def publish_course(cid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["lms_courses"])
    cur.execute("UPDATE lms_courses SET is_published=true WHERE id=%s", (cid,))
    if cur.rowcount == 0:
        raise HTTPException(404, "Not found")
    db.commit()
    return {"message":"Published"}

# ==================== MODULES ====================
@api_router.post("/courses/{cid}/modules")
def add_module(cid: str, module: ModuleContent, admin=Depends(require_admin), db=Depends(get_db)):
    mid = module.id
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["lms_courses"])
    cur.execute("SELECT id FROM lms_courses WHERE id=%s", (cid,))
    if not cur.fetchone():
        raise HTTPException(404, "Course not found")
        
    cur.execute(TABLE_SCHEMAS["lms_modules"])
    cur.execute("SELECT MAX(order_index) as max_ord FROM lms_modules WHERE course_id=%s", (cid,))
    max_order = cur.fetchone()["max_ord"]
    next_order = (max_order + 1) if max_order is not None else 0
    
    cur.execute("""
        INSERT INTO lms_modules (id, course_id, title, order_index)
        VALUES (%s, %s, %s, %s)
    """, (mid, cid, module.title, next_order))
    db.commit()
    
    return get_course(cid, db=db, user=admin)

@api_router.put("/courses/{cid}/modules/reorder")
def reorder_modules(cid: str, req: ReorderRequest, admin=Depends(require_admin), db=Depends(get_db)):
    module_ids = req.ids
    cur = db.cursor()
    for i, mid in enumerate(module_ids):
        cur.execute("UPDATE lms_modules SET order_index=%s WHERE id=%s AND course_id=%s", (i, mid, cid))
    db.commit()
    return get_course(cid, db=db, user=admin)

@api_router.put("/courses/{cid}/modules/{mid}")
def update_module(cid: str, mid: str, module: ModuleContent, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("UPDATE lms_modules SET title=%s WHERE id=%s AND course_id=%s RETURNING id", (module.title, mid, cid))
    if not cur.fetchone():
        raise HTTPException(404, "Module not found")
    db.commit()
    return get_course(cid, db=db, user=admin)

@api_router.delete("/courses/{cid}/modules/{mid}")
def delete_module(cid: str, mid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("DELETE FROM lms_modules WHERE id=%s AND course_id=%s RETURNING id", (mid, cid))
    if not cur.fetchone():
        raise HTTPException(404, "Module not found")
    db.commit()
    return get_course(cid, db=db, user=admin)

# ==================== ADMIN ====================
@api_router.get("/admin/analytics")
def get_analytics(admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["lms_users"])
    cur.execute("SELECT count(*) FROM lms_users")
    user_count = cur.fetchone()[0]
    
    cur.execute(TABLE_SCHEMAS["lms_courses"])
    cur.execute("SELECT count(*) FROM lms_courses")
    course_count = cur.fetchone()[0]
    
    cur.execute(TABLE_SCHEMAS["lms_quizzes"])
    cur.execute("SELECT count(*) FROM lms_quizzes")
    quiz_count = cur.fetchone()[0]
        
    cur.execute(TABLE_SCHEMAS["lms_certificates"])
    cur.execute("SELECT count(*) FROM lms_certificates")
    cert_count = cur.fetchone()[0]
        
    return {
        "users": {"total": user_count},
        "courses": {"total": course_count},
        "quizzes": {"total": quiz_count},
        "certificates": cert_count
    }

@api_router.get("/admin/users")
def get_admin_users(
    search: Optional[str] = None,
    role: Optional[str] = None,
    page: int = 1,
    limit: int = 10,
    admin=Depends(require_admin),
    db=Depends(get_db)
):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    offset = (page - 1) * limit
    
    query = "SELECT * FROM lms_users"
    conditions = []
    params = []
    
    if search:
        conditions.append("(name ILIKE %s OR email ILIKE %s)")
        params.extend([f"%{search}%", f"%{search}%"])
    
    if role:
        conditions.append("role = %s")
        params.append(role)
        
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    # Get total count for pagination
    count_query = f"SELECT count(*) FROM ({query}) as sub"
    cur.execute(count_query, tuple(params))
    total_count = cur.fetchone()["count"]
    
    query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])
    
    cur.execute(query, tuple(params))
    users = cur.fetchall()
    
    for u in users:
        u.pop("password_hash", None)
        
    return {
        "users": users,
        "total": total_count,
        "page": page,
        "limit": limit,
        "pages": (total_count + limit - 1) // limit
    }

@api_router.get("/admin/users/{uid}/learning-paths/{pid}/progress")
def get_path_progress_admin(uid: str, pid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Get path courses
    cur.execute("SELECT course_ids FROM lms_learning_paths WHERE id=%s", (pid,))
    path = cur.fetchone()
    if not path:
        raise HTTPException(404, "Learning path not found")
        
    course_ids = path["course_ids"]
    if isinstance(course_ids, str):
        course_ids = json.loads(course_ids)
        
    if not course_ids:
        return []
        
    # Get progress for each course
    placeholders = ', '.join(['%s'] * len(course_ids))
    cur.execute(f"""
        SELECT c.id, c.title, c.difficulty,
               COALESCE(uc.is_completed, FALSE) as is_completed,
               COALESCE(uc.status, 'not_assigned') as access_status,
               (SELECT count(*) FROM lms_sessions s WHERE s.course_id = c.id) as total_sessions,
               (SELECT count(*) FROM lms_session_progress sp WHERE sp.user_id = %s AND sp.course_id = c.id AND sp.completed = TRUE) as completed_sessions
        FROM lms_courses c
        LEFT JOIN lms_user_courses uc ON c.id = uc.course_id AND uc.user_id = %s
        WHERE c.id IN ({placeholders})
    """, (uid, uid, *course_ids))
    
    return cur.fetchall()

@api_router.get("/admin/users/{uid}/courses")
def get_user_courses_admin(uid: str, admin=Depends(require_admin), db=Depends(get_db)):
    print(f"DEBUG: GET user courses for {uid}")
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Courses
    cur.execute("""
        SELECT c.*, 
               (CASE WHEN uc.user_id IS NOT NULL THEN TRUE ELSE FALSE END) as is_assigned,
               uc.status as access_status,
               uc.is_completed
        FROM lms_courses c
        LEFT JOIN lms_user_courses uc ON c.id = uc.course_id AND uc.user_id = %s
    """, (uid,))
    courses = cur.fetchall()
    
    # Paths
    cur.execute(TABLE_SCHEMAS["lms_user_learning_paths"])
    cur.execute("""
        SELECT lp.*, 
               (CASE WHEN ulp.user_id IS NOT NULL THEN TRUE ELSE FALSE END) as is_assigned,
               ulp.status as access_status,
               ulp.is_completed
        FROM lms_learning_paths lp
        LEFT JOIN lms_user_learning_paths ulp ON lp.id = ulp.path_id AND ulp.user_id = %s
    """, (uid,))
    paths = cur.fetchall()
    
    return {
        "courses": courses,
        "learning_paths": paths
    }

@api_router.post("/admin/users/{uid}/courses")
def assign_course_to_user(uid: str, data: Dict[str, str], admin=Depends(require_admin), db=Depends(get_db)):
    cid = data.get("course_id")
    if not cid:
        raise HTTPException(400, "course_id required")
        
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO lms_user_courses (user_id, course_id, status) VALUES (%s, %s, 'active') ON CONFLICT (user_id, course_id) DO UPDATE SET status = 'active'", (uid, cid))
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))
    return {"status": "success"}
    
@api_router.post("/admin/users/{uid}/learning-paths")
def assign_learning_path_to_user(uid: str, data: Dict[str, str], admin=Depends(require_admin), db=Depends(get_db)):
    pid = data.get("path_id")
    if not pid:
        raise HTTPException(400, "path_id required")
        
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Get path courses
        cur.execute("SELECT course_ids FROM lms_learning_paths WHERE id=%s", (pid,))
        path = cur.fetchone()
        if not path:
            raise HTTPException(404, "Learning path not found")
            
        course_ids = path["course_ids"]
        if isinstance(course_ids, str):
            import json
            course_ids = json.loads(course_ids)
            
        # Assign each course
        for cid in course_ids:
            cur.execute("INSERT INTO lms_user_courses (user_id, course_id, status) VALUES (%s, %s, 'active') ON CONFLICT (user_id, course_id) DO UPDATE SET status = 'active'", (uid, cid))
        
        # Also record the path assignment itself
        cur.execute("INSERT INTO lms_user_learning_paths (user_id, path_id, status) VALUES (%s, %s, 'active') ON CONFLICT (user_id, path_id) DO UPDATE SET status = 'active'", (uid, pid))
        
        db.commit()
        # Trigger completion check immediately in case all courses are already done
        check_path_completion(db, uid, pid)
    except Exception as e:
        db.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(500, str(e))
    return {"status": "success"}

@api_router.post("/admin/users/{uid}/learning-paths/{pid}/status")
def update_path_access_status(uid: str, pid: str, data: Dict[str, str], admin=Depends(require_admin), db=Depends(get_db)):
    status = data.get("status")
    if status not in ['active', 'blocked']:
        raise HTTPException(400, "Invalid status. Use 'active' or 'blocked'")
    
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Update path status
        cur.execute("UPDATE lms_user_learning_paths SET status = %s WHERE user_id = %s AND path_id = %s", (status, uid, pid))
        
        # Cascade to courses in this path
        cur.execute("SELECT course_ids FROM lms_learning_paths WHERE id=%s", (pid,))
        path = cur.fetchone()
        if path:
            course_ids = path["course_ids"]
            if isinstance(course_ids, str):
                course_ids = json.loads(course_ids)
            
            if course_ids:
                placeholders = ', '.join(['%s'] * len(course_ids))
                # For path-blocked, we use 'frozen'/'active' in the courses table for now, or maybe 'blocked'?
                # The course table has 'frozen'. Let's stick to 'frozen' for courses but UI can say 'blocked'.
                course_status = 'frozen' if status == 'blocked' else 'active'
                cur.execute(f"UPDATE lms_user_courses SET status = %s WHERE user_id = %s AND course_id IN ({placeholders})", (course_status, uid, *course_ids))
        
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))
    return {"status": "success"}

@api_router.delete("/admin/users/{uid}/learning-paths/{pid}")
def unassign_path_from_user(uid: str, pid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("DELETE FROM lms_user_learning_paths WHERE user_id = %s AND path_id = %s", (uid, pid))
        
        # Optionally unassign courses? The requirement says "assign path... courses automatically get assigned".
        # Usually unassigning path should probably unassign courses too, but strictly speaking "Assign Path" was a batch action.
        # Let's keep courses for now, but delete the path association.
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))
    return {"status": "success"}

@api_router.post("/admin/users/{uid}/courses/{cid}/status")
def update_course_access_status(uid: str, cid: str, data: Dict[str, str], admin=Depends(require_admin), db=Depends(get_db)):
    status = data.get("status")
    if status not in ['active', 'frozen', 'blocked']: # Added blocked for compatibility
        raise HTTPException(400, "Invalid status")
    
    # Internal status is 'frozen' for single course, 'blocked' for path-level
    actual_status = 'frozen' if status in ['frozen', 'blocked'] else 'active'
    
    cur = db.cursor()
    cur.execute("UPDATE lms_user_courses SET status = %s WHERE user_id = %s AND course_id = %s", (actual_status, uid, cid))
    db.commit()
    return {"status": "success"}

@api_router.delete("/admin/users/{uid}/courses/{cid}")
def unassign_course_from_user(uid: str, cid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor()
    # Delete assignment
    cur.execute("DELETE FROM lms_user_courses WHERE user_id = %s AND course_id = %s", (uid, cid))
    # Delete progress data as requested: "all data removed for perticular student"
    cur.execute("DELETE FROM lms_session_progress WHERE user_id = %s AND course_id = %s", (uid, cid))
    db.commit()
    return {"status": "success"}

@api_router.get("/admin/users/{uid}/courses/{cid}/progress")
def get_student_course_progress(uid: str, cid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Get all sessions for this course
    cur.execute("""
        SELECT s.id, s.name, s.module_id, m.title as module_title,
               COALESCE(sp.completed, FALSE) as completed
        FROM lms_sessions s
        JOIN lms_modules m ON s.module_id = m.id
        LEFT JOIN lms_session_progress sp ON s.id = sp.session_id AND sp.user_id = %s
        WHERE s.course_id = %s
        ORDER BY m.order_index, s.session_index
    """, (uid, cid))
    
    sessions = cur.fetchall()
    
    # Group by module
    modules_progress = {}
    for session in sessions:
        mid = session['module_id']
        if mid not in modules_progress:
            modules_progress[mid] = {
                "id": mid,
                "title": session['module_title'],
                "sessions": []
            }
        modules_progress[mid]["sessions"].append({
            "id": session['id'],
            "name": session['name'],
            "completed": session['completed']
        })
        
    return list(modules_progress.values())

@api_router.get("/admin/courses/{cid}/users")
def get_course_users_admin(cid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Get all users and check if enrolled in this course
    # Use a subquery to avoid joins if possible or a left join
    cur.execute("""
        SELECT u.id, u.name, u.email, u.role,
               (CASE WHEN uc.course_id IS NOT NULL THEN TRUE ELSE FALSE END) as is_assigned
        FROM lms_users u
        LEFT JOIN lms_user_courses uc ON u.id = uc.user_id AND uc.course_id = %s
        ORDER BY u.name ASC
    """, (cid,))
    return cur.fetchall()

@api_router.post("/admin/courses/{cid}/users")
def assign_user_to_course(cid: str, data: Dict[str, str], admin=Depends(require_admin), db=Depends(get_db)):
    uid = data.get("user_id")
    if not uid:
        raise HTTPException(400, "user_id required")
        
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO lms_user_courses (user_id, course_id) VALUES (%s, %s) ON CONFLICT DO NOTHING", (uid, cid))
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))
    return {"status": "success"}

@api_router.delete("/admin/courses/{cid}/users/{uid}")
def unassign_user_from_course(cid: str, uid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("DELETE FROM lms_user_courses WHERE user_id = %s AND course_id = %s", (uid, cid))
    db.commit()
    return {"status": "success"}

# ==================== LEARNING PATHS ====================
@api_router.get("/learning-paths")
def get_learning_paths(db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["lms_learning_paths"])
        cur.execute("SELECT * FROM lms_learning_paths")
        return cur.fetchall()
    except:
        db.rollback()
        return []

@api_router.get("/learning-paths/recommended")
def get_recommended_paths(user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["learning_paths"])
        # Simple recommendation based on user interests
        interests = user.get("interests", [])
        if not interests:
            cur.execute("SELECT * FROM lms_learning_paths LIMIT 5")
        else:
            cur.execute("SELECT * FROM lms_learning_paths WHERE target_interests ?| %s", (interests,))
        return cur.fetchall()
    except:
        db.rollback()
        return []

@api_router.post("/learning-paths")
def create_learning_path(path: LearningPathCreate, admin=Depends(require_admin), db=Depends(get_db)):
    pid = generate_id()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["lms_learning_paths"])
    cur.execute("""
        INSERT INTO lms_learning_paths (id, title, description, course_ids, target_interests, created_by, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        RETURNING *
    """, (
        pid, path.title, path.description, 
        json.dumps(path.course_ids), 
        json.dumps(path.target_interests),
        admin["id"], datetime.now()
    ))
    db.commit()
    path_data = cur.fetchone()
    db.commit()
    return path_data

@api_router.get("/learning-paths/{pid}")
def get_learning_path(pid: str, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM lms_learning_paths WHERE id=%s", (pid,))
    path = cur.fetchone()
    if not path:
        raise HTTPException(404, "Learning path not found")
    return path

@api_router.put("/learning-paths/{pid}")
def update_learning_path(pid: str, path: LearningPathCreate, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        UPDATE lms_learning_paths 
        SET title=%s, description=%s, course_ids=%s, target_interests=%s
        WHERE id=%s
        RETURNING *
    """, (path.title, path.description, json.dumps(path.course_ids), json.dumps(path.target_interests), pid))
    updated_path = cur.fetchone()
    if not updated_path:
        raise HTTPException(404, "Learning path not found")
    db.commit()
    return updated_path

@api_router.delete("/learning-paths/{pid}")
def delete_learning_path(pid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("DELETE FROM lms_learning_paths WHERE id=%s", (pid,))
    if cur.rowcount == 0:
        raise HTTPException(404, "Learning path not found")
    db.commit()
    return {"message": "Learning path deleted"}

# ==================== PROGRESS ====================
@api_router.get("/progress")
def get_progress(user=Depends(get_current_user), db=Depends(get_db)):
    return []

@api_router.post("/progress")
def update_progress(data: ProgressUpdate, user=Depends(get_current_user), db=Depends(get_db)):
    return {"status": "deprecated, use sessions"}

@api_router.get("/progress/course/{cid}")
def get_course_progress(cid: str, user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Get total sessions
        cur.execute(TABLE_SCHEMAS["lms_sessions"])
        cur.execute("SELECT count(*) FROM lms_sessions WHERE course_id=%s", (cid,))
        total_sessions = cur.fetchone()["count"]
        
        # Get completed sessions
        cur.execute(TABLE_SCHEMAS["lms_session_progress"])
        cur.execute("SELECT count(DISTINCT session_id) FROM lms_session_progress WHERE user_id=%s AND course_id=%s AND completed=true", (user["id"], cid))
        completed_sessions = cur.fetchone()["count"]
 
        # Get modules for this course
        cur.execute(TABLE_SCHEMAS["lms_modules"])
        cur.execute("SELECT id, title FROM lms_modules WHERE course_id=%s", (cid,))
        modules = cur.fetchall()
        total_modules = len(modules)
        
        # Get total sessions per module
        cur.execute("SELECT module_id, count(*) FROM lms_sessions WHERE course_id=%s GROUP BY module_id", (cid,))
        mod_session_counts = {row["module_id"]: row["count"] for row in cur.fetchall()}
        
        # Get completed sessions per module - join with sessions to be robust against missing module_id in progress table
        cur.execute("""
            SELECT s.module_id, count(*) 
            FROM lms_session_progress p
            JOIN lms_sessions s ON p.session_id = s.id
            WHERE p.user_id=%s AND p.course_id=%s AND p.completed=true 
            GROUP BY s.module_id
        """, (user["id"], cid))
        mod_completed_counts = {row["module_id"]: row["count"] for row in cur.fetchall()}
        
        module_progress = []
        completed_modules = 0
        
        for m in modules:
            m_id = m["id"]
            total_m = mod_session_counts.get(m_id, 0)
            completed_m = mod_completed_counts.get(m_id, 0)
            is_completed = total_m > 0 and completed_m >= total_m
            
            if is_completed:
                completed_modules += 1
                
            module_progress.append({
                "module_id": m_id,
                "module_title": m["title"],
                "total_sessions": total_m,
                "completed_sessions": completed_m,
                "completed": is_completed
            })
            
        pct = (completed_sessions / total_sessions * 100) if total_sessions > 0 else 0
        
        return {
            "total_sessions": total_sessions,
            "completed_sessions": completed_sessions,
            "progress_percentage": pct,
            "total_modules": total_modules,
            "completed_modules": completed_modules,
            "module_progress": module_progress
        }
    except Exception as e:
        print(f"Error in course progress: {e}")
        db.rollback()
        return {
            "total_sessions": 0,
            "completed_sessions": 0,
            "progress_percentage": 0,
            "total_modules": 0,
            "completed_modules": 0,
            "module_progress": []
        }

@api_router.get("/progress/dashboard")
def get_dashboard_stats(user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Get active user courses including progress_percentage and is_completed
        cur.execute(TABLE_SCHEMAS["lms_user_courses"])
        cur.execute("""
            SELECT uc.course_id, uc.progress_percentage, uc.is_completed, c.title
            FROM lms_user_courses uc
            JOIN lms_courses c ON uc.course_id = c.id
            WHERE uc.user_id = %s AND uc.status = 'active'
        """, (user["id"],))
        user_courses = cur.fetchall()
        
        # Calculate stats
        total_courses_enrolled = len(user_courses)
        completed_courses = 0
        course_stats = []
        
        for uc in user_courses:
            if uc["is_completed"]:
                completed_courses += 1
            course_stats.append({
                "course_id": uc["course_id"],
                "course_title": uc["title"],
                "progress_percentage": uc["progress_percentage"] or 0,
                "is_completed": uc["is_completed"]
            })
        
        # Get certificates count
        cur.execute(TABLE_SCHEMAS["lms_certificates"])
        cur.execute("SELECT count(*) FROM lms_certificates WHERE user_id=%s", (user["id"],))
        cert_count = cur.fetchone()["count"]
        
        # Get total time spent
        cur.execute("SELECT sum(time_taken_seconds) as sum FROM lms_session_progress WHERE user_id=%s", (user["id"],))
        time_row = cur.fetchone()
        total_time_seconds = time_row["sum"] if time_row and time_row["sum"] is not None else 0
        total_time = total_time_seconds // 60

        return {
            "total_courses_enrolled": total_courses_enrolled,
            "completed_courses": completed_courses,
            "total_time_spent_minutes": total_time,
            "certificates_earned": cert_count,
            "course_stats": course_stats
        }
    except Exception as e:
        print(f"Error in dashboard stats: {e}")
        db.rollback()
        return {
            "total_courses_enrolled": 0,
            "completed_courses": 0,
            "total_time_spent_minutes": 0,
            "certificates_earned": 0,
            "course_stats": []
        }

@api_router.get("/progress/dashboard/v2")
def get_dashboard_stats_v2(user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Get active user courses
        cur.execute("""
            SELECT uc.course_id, uc.progress_percentage, uc.is_completed, c.title
            FROM lms_user_courses uc
            JOIN lms_courses c ON uc.course_id = c.id
            WHERE uc.user_id = %s AND uc.status = 'active'
        """, (user["id"],))
        user_courses = cur.fetchall()
        
        course_stats = []
        total_modules_completed_global = 0
        
        for uc in user_courses:
            cid = uc["course_id"]
            
            # Total modules in this course
            cur.execute("SELECT count(*) FROM lms_modules WHERE course_id=%s", (cid,))
            total_modules = cur.fetchone()["count"]
            
            # Completed modules logic: modules where all sessions are completed
            cur.execute("""
                SELECT m.id, 
                       (SELECT count(*) FROM lms_sessions s WHERE s.module_id = m.id) as total_s,
                       (SELECT count(*) FROM lms_session_progress sp WHERE sp.module_id = m.id AND sp.user_id = %s AND sp.completed = true) as comp_s
                FROM lms_modules m
                WHERE m.course_id = %s
            """, (user["id"], cid))
            modules = cur.fetchall()
            
            completed_modules = 0
            for m in modules:
                if m["total_s"] > 0 and m["comp_s"] >= m["total_s"]:
                    completed_modules += 1
            
            total_modules_completed_global += completed_modules

            # Also get session counts for fine-grained progress bar if needed
            cur.execute("SELECT count(*) FROM lms_sessions WHERE course_id=%s", (cid,))
            total_sessions = cur.fetchone()["count"]
            cur.execute("SELECT count(*) FROM lms_session_progress WHERE user_id=%s AND course_id=%s AND completed=true", (user["id"], cid))
            completed_sessions = cur.fetchone()["count"]
            
            # Use session-based percentage for the progress bar to show granular progress
            # as requested "reflect same type of progress bar"
            session_pct = int((float(completed_sessions) / float(total_sessions)) * 100) if total_sessions > 0 else 0

            course_stats.append({
                "course_id": cid,
                "course_title": uc["title"],
                "progress_percentage": session_pct, # Session-based for granular bar movement
                "is_completed": completed_modules >= total_modules if total_modules > 0 else False,
                "total_modules": total_modules,
                "completed_modules": completed_modules,
                "total_sessions": total_sessions,
                "completed_sessions": completed_sessions
            })
        
        # Get certificates count
        cur.execute("SELECT count(*) FROM lms_certificates WHERE user_id=%s", (user["id"],))
        cert_count = cur.fetchone()["count"]
        
        # Get total time
        cur.execute("SELECT sum(time_taken_seconds) as sum FROM lms_session_progress WHERE user_id=%s", (user["id"],))
        time_row = cur.fetchone()
        total_time_minutes = (time_row["sum"] // 60) if time_row and time_row["sum"] else 0

        return {
            "total_courses_enrolled": len(user_courses),
            "total_modules_completed": total_modules_completed_global, # Actually global session count in old code was used here
            "total_time_spent_minutes": total_time_minutes,
            "certificates_earned": cert_count,
            "course_stats": course_stats
        }
    except Exception as e:
        print(f"Error in dashboard v2: {e}")
        db.rollback()
        raise HTTPException(500, str(e))

# ==================== QUIZZES ====================
@api_router.get("/quizzes")
def get_quizzes(course_id: Optional[str] = None, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["lms_quizzes"])
        if course_id:
            cur.execute("SELECT * FROM lms_quizzes WHERE course_id=%s", (course_id,))
        else:
            cur.execute("SELECT * FROM lms_quizzes")
        return cur.fetchall()
    except:
        db.rollback()
        return []

@api_router.get("/quizzes/{qid}")
def get_quiz(qid: str, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["lms_quizzes"])
    cur.execute("SELECT * FROM lms_quizzes WHERE id=%s", (qid,))
    quiz = cur.fetchone()
    if not quiz:
        raise HTTPException(404, "Quiz not found")
    return quiz

@api_router.post("/quizzes")
def create_quiz(data: Dict[str, Any], admin=Depends(require_admin), db=Depends(get_db)):
    qid = generate_id()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["lms_quizzes"])
    cur.execute("""
        INSERT INTO lms_quizzes (id, course_id, module_id, title, questions, passing_score, time_limit_minutes, created_by, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING *
    """, (
        qid, data.get("course_id"), data.get("module_id"), data.get("title"),
        psycopg2.extras.Json(data.get("questions", [])),
        data.get("passing_score", 70),
        data.get("time_limit_minutes", 30),
        admin["id"], datetime.now()
    ))
    db.commit()
    return cur.fetchone()




# ==================== DISCUSSIONS ====================

@api_router.get("/discussions")
def get_discussions(course_id: Optional[str] = None, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["lms_discussions"])
        cur.execute(TABLE_SCHEMAS["lms_replies"])
        
        if course_id:
            cur.execute("SELECT * FROM lms_discussions WHERE course_id=%s ORDER BY created_at DESC", (course_id,))
        else:
            cur.execute("SELECT * FROM lms_discussions ORDER BY created_at DESC")
        
        discussions = cur.fetchall()
        
        # Fetch replies for these discussions
        for d in discussions:
            cur.execute("SELECT * FROM lms_replies WHERE discussion_id=%s ORDER BY created_at ASC", (d["id"],))
            d["replies"] = cur.fetchall()
            
        return discussions
    except Exception as e:
        print(f"Error fetching discussions: {e}")
        db.rollback()
        return []

@api_router.post("/discussions/{did}/reply")
def add_reply(did: str, data: Dict[str, Any], user=Depends(get_current_user), db=Depends(get_db)):
    rid = generate_id()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["lms_replies"])
        cur.execute("""
            INSERT INTO lms_replies (id, discussion_id, content, author_id, author_name, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (rid, did, data.get("content"), user["id"], user["name"], datetime.now()))
        reply = cur.fetchone()
        db.commit()
        return reply
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))

@api_router.post("/discussions")
def create_discussion(data: Dict[str, Any], user=Depends(get_current_user), db=Depends(get_db)):
    did = generate_id()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["lms_discussions"])
    cur.execute("""
        INSERT INTO lms_discussions (id, course_id, title, content, author_id, author_name, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        RETURNING *
    """, (
        did, data.get("course_id"), data.get("title"), data.get("content"),
        user["id"], user["name"], datetime.now()
    ))
    db.commit()
    return cur.fetchone()

# ==================== EXPERT Q&A ====================
@api_router.get("/expert-questions")
def get_expert_questions(course_id: Optional[str] = None, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["lms_expert_questions"])
        if course_id:
            cur.execute("SELECT * FROM lms_expert_questions WHERE course_id=%s ORDER BY created_at DESC", (course_id,))
        else:
            cur.execute("SELECT * FROM lms_expert_questions ORDER BY created_at DESC")
        return cur.fetchall()
    except:
        db.rollback()
        return []

@api_router.post("/expert-questions")
def ask_question(data: Dict[str, Any], user=Depends(get_current_user), db=Depends(get_db)):
    qid = generate_id()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["lms_expert_questions"])
    cur.execute("""
        INSERT INTO lms_expert_questions (id, course_id, question, asked_by, asked_by_name, status, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        RETURNING *
    """, (
        qid, data.get("course_id"), data.get("question"),
        user["id"], user["name"], "pending", datetime.now()
    ))
    db.commit()
    return cur.fetchone()

# ==================== CERTIFICATES ====================
@api_router.get("/certificates")
def get_certificates(user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Fetch from the new issued certificates table, joining with paths to get titles
        cur.execute("""
            SELECT c.*, p.title as learning_path_title, t.name as template_name
            FROM lms_issued_certificates c
            LEFT JOIN lms_learning_paths p ON c.path_id = p.id
            LEFT JOIN lms_certificate_templates t ON c.template_id = t.id
            WHERE c.user_id = %s
            ORDER BY c.issued_at DESC
        """, (user["id"],))
        return cur.fetchall()
    except Exception as e:
        print(f"Error fetching certificates: {e}")
        db.rollback()
        return []

# ==================== NOTIFICATIONS ====================
@api_router.get("/notifications")
def get_notifications(user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["lms_notifications"])
        cur.execute("SELECT * FROM lms_notifications WHERE user_id=%s ORDER BY created_at DESC", (user["id"],))
        return cur.fetchall()
    except:
        db.rollback()
        return []

@api_router.put("/notifications/{nid}/read")
def mark_notification_read(nid: str, user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["lms_notifications"])
    cur.execute("UPDATE lms_notifications SET read=true WHERE id=%s AND user_id=%s", (nid, user["id"]))
    db.commit()
    return {"status": "success"}

@api_router.put("/notifications/read-all")
def mark_all_notifications_read(user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["lms_notifications"])
    cur.execute("UPDATE lms_notifications SET read=true WHERE user_id=%s", (user["id"],))
    db.commit()
    return {"status": "success"}

# ==================== CERTIFICATE TEMPLATES ====================
@api_router.get("/admin/certificate-templates")
def get_certificate_templates(admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("SELECT * FROM lms_certificate_templates ORDER BY created_at DESC")
        return cur.fetchall()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))

@api_router.post("/admin/certificate-templates")
def create_certificate_template(temp: CertificateTemplateCreate, admin=Depends(require_admin), db=Depends(get_db)):
    tid = generate_id()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            INSERT INTO lms_certificate_templates (id, name, background_media_id, placeholders, created_by, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (tid, temp.name, temp.background_media_id, psycopg2.extras.Json(temp.placeholders), admin["id"], datetime.now()))
        db.commit()
        return cur.fetchone()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))

@api_router.put("/admin/certificate-templates/{tid}")
def update_certificate_template(tid: str, temp: CertificateTemplateCreate, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            UPDATE lms_certificate_templates 
            SET name=%s, background_media_id=%s, placeholders=%s
            WHERE id=%s
            RETURNING *
        """, (temp.name, temp.background_media_id, psycopg2.extras.Json(temp.placeholders), tid))
        if cur.rowcount == 0:
            raise HTTPException(404, "Template not found")
        db.commit()
        return cur.fetchone()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))

@api_router.delete("/admin/certificate-templates/{tid}")
def delete_certificate_template(tid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Check if template is in use
        cur.execute("SELECT id FROM lms_issued_certificates WHERE template_id=%s LIMIT 1", (tid,))
        if cur.fetchone():
            raise HTTPException(400, "This template cannot be deleted because it has already been used to issue certificates.")

        cur.execute("DELETE FROM lms_certificate_templates WHERE id=%s", (tid,))
        if cur.rowcount == 0:
            raise HTTPException(404, "Template not found")
        db.commit()
        return {"status": "success"}
    except HTTPException as e:
        db.rollback()
        raise e
    except Exception as e:
        db.rollback()
        print(f"Error deleting template {tid}: {e}")
        raise HTTPException(500, str(e))

def generate_certificate_image(db, template_id, placeholder_data):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM lms_certificate_templates WHERE id=%s", (template_id,))
    template = cur.fetchone()
    if not template:
        return None
    
    background_media_id = template["background_media_id"]
    placeholders = template["placeholders"]
    if isinstance(placeholders, str):
        placeholders = json.loads(placeholders)
    if not placeholders:
        placeholders = []
    
    cur.execute("SELECT file_data FROM lms_media_files WHERE id=%s", (background_media_id,))
    media = cur.fetchone()
    if not media:
        return None
        
    img = Image.open(io.BytesIO(bytes(media["file_data"])))
    draw = ImageDraw.Draw(img)
    width, height = img.size
    
    # Try to load a font
    # corrected path: lms_backend/backend/../../lms_frontend/lms_frontend/assets/fonts/SpaceMono-Regular.ttf
    font_path = os.path.join(ROOT_DIR, "..", "..", "lms_frontend", "lms_frontend", "assets", "fonts", "SpaceMono-Regular.ttf")
    
    for p in placeholders:
        p_type = p.get("type", "text")
        p_id = p.get("id", p_type)
        # Support both casing styles
        font_size_val = p.get("fontSize", p.get("font_size", 20))
        value = placeholder_data.get(p_id, placeholder_data.get(p_type, p.get("label", p_type)))
        x_pct, y_pct = p["x"], p["y"]
        
        # Calculate size relative to image width (assuming base width of 400 for sizing)
        # This makes the font size proportional to the image resolution
        size = int((font_size_val / 400.0) * width)
        color = p.get("color", "#000000")
        
        try:
            # Re-load font with correct size for this placeholder
            if os.path.exists(font_path):
                font = ImageFont.truetype(font_path, size)
            else:
                print(f"⚠️ Font not found at {font_path}, falling back to default")
                font = ImageFont.load_default()
        except Exception as e:
            print(f"❌ Error loading font {font_path}: {e}")
            font = ImageFont.load_default()
            
        x, y = int((x_pct / 100) * width), int((y_pct / 100) * height)
        
        # Use anchor='mm' for middle-center alignment (Pillow 8.0.0+)
        # This is more reliable than manual bbox calculation
        try:
            draw.text((x, y), str(value), font=font, fill=color, anchor="mm")
        except:
            # Fallback for very old Pillow versions if anchor is not supported
            bbox = draw.textbbox((x, y), str(value), font=font)
            text_w = bbox[2] - bbox[0]
            text_h = bbox[3] - bbox[1]
            draw.text((x - text_w // 2, y - text_h // 2), str(value), font=font, fill=color)
        
    output = io.BytesIO()
    img.save(output, format="PNG")
    return output.getvalue()

@api_router.post("/admin/certificates/issue")
def issue_certificate(cert: CertificateIssue, admin=Depends(require_admin), db=Depends(get_db)):
    if cert.course_id:
        raise HTTPException(400, "Certificates can only be issued for learning paths, not individual courses.")
    if not cert.path_id:
        raise HTTPException(400, "Learning Path ID is required.")
        
    # Generate the image
    image_data = generate_certificate_image(db, cert.template_id, cert.placeholder_data)
    if not image_data:
        raise HTTPException(500, "Failed to generate certificate image")
        
    image_id = generate_id()
    cid = generate_id()
    
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Save image to media files
        cur.execute("""
            INSERT INTO lms_media_files (id, file_name, file_type, mime_type, file_data, file_size, uploaded_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (image_id, f"cert_{cid}.png", "image", "image/png", psycopg2.Binary(image_data), len(image_data), admin["id"]))
        
        # Save issued certificate
        cur.execute("""
            INSERT INTO lms_issued_certificates (id, user_id, path_id, course_id, template_id, image_media_id, placeholder_data, issued_by, issued_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (cid, cert.user_id, cert.path_id, None, cert.template_id, image_id, psycopg2.extras.Json(cert.placeholder_data), admin["id"], datetime.now()))
        db.commit()
        return cur.fetchone()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))

@api_router.get("/admin/users/{uid}/certificates")
def get_user_certificates(uid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("SELECT * FROM lms_issued_certificates WHERE user_id=%s ORDER BY issued_at DESC", (uid,))
        return cur.fetchall()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))

@api_router.get("/certificates/{cid}")
def get_issued_certificate(cid: str, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            SELECT c.*, t.name as template_name, t.background_media_id, t.placeholders as template_placeholders
            FROM lms_issued_certificates c
            JOIN lms_certificate_templates t ON c.template_id = t.id
            WHERE c.id=%s
        """, (cid,))
        cert = cur.fetchone()
        if not cert:
            raise HTTPException(404, "Certificate not found")
        return cert
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))

# ==================== SESSIONS ====================
@api_router.post("/sessions")
async def create_session(
    course_id: str = Form(...),
    module_id: str = Form(...),
    name: str = Form(...),
    duration_minutes: str = Form(...),
    content_type: str = Form(...),
    content_text: Optional[str] = Form(None),
    quiz_id: Optional[str] = Form(None),
    content_url: Optional[str] = Form(None),
    image_url: Optional[str] = Form(None),
    media_id: Optional[str] = Form(None),
    is_document_available: str = Form("false"),
    admin=Depends(require_admin),
    db=Depends(get_db)
):
    sid = generate_id()
    
    try:
        duration = int(duration_minutes)
    except:
        duration = 0
    
    is_doc_bool = is_document_available.lower() == "true"

    
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["lms_sessions"])
    
    # Validate quiz uniqueness: quiz must not already be assigned to another session
    if quiz_id:
        cur.execute("SELECT id, name FROM lms_sessions WHERE quiz_id=%s", (quiz_id,))
        existing_assignment = cur.fetchone()
        if existing_assignment:
            raise HTTPException(400, f"This quiz is already assigned to session '{existing_assignment['name']}'. A quiz can only be assigned to one session.")
    
    # Get last index for the module
    cur.execute("SELECT MAX(session_index) FROM lms_sessions WHERE module_id=%s", (module_id,))
    max_idx_row = cur.fetchone()
    next_idx = (max_idx_row["max"] + 1) if max_idx_row and max_idx_row["max"] is not None else 0

    cur.execute("""
        INSERT INTO lms_sessions 
        (id, course_id, module_id, name, duration_minutes, content_type, content_url, image_url, media_id, content_text, quiz_id, is_document_available, session_index)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING *
    """, (sid, course_id, module_id, name, duration, content_type, content_url, image_url, media_id, content_text, quiz_id, is_doc_bool, next_idx))
    
    session = cur.fetchone()
    db.commit()
    return session

@api_router.get("/courses/{cid}/modules/{mid}/sessions")
def get_sessions(cid: str, mid: str, user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["lms_sessions"])
    cur.execute("ALTER TABLE lms_sessions ADD COLUMN IF NOT EXISTS session_index INTEGER DEFAULT 0")
    
    cur.execute("""
        SELECT s.*, p.completed, p.quiz_marks, p.time_taken_seconds
        FROM lms_sessions s
        LEFT JOIN lms_session_progress p ON s.id = p.session_id AND p.user_id = %s
        WHERE s.course_id = %s AND s.module_id = %s
        ORDER BY s.session_index ASC, s.created_at ASC
    """, (user["id"], cid, mid))
    sessions = cur.fetchall()
    
    # Ensure completed is a boolean even if NULL from LEFT JOIN
    for s in sessions:
        s["completed"] = bool(s.get("completed", False))
        
    return sessions

@api_router.get("/sessions/{sid}")
def get_session(sid: str, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["lms_sessions"])
    cur.execute("SELECT * FROM lms_sessions WHERE id=%s", (sid,))
    session = cur.fetchone()
    if not session:
        raise HTTPException(404, "Session not found")
    return session

@api_router.put("/sessions/{sid}")
async def update_session(
    sid: str,
    name: Optional[str] = Form(None),
    duration_minutes: Optional[str] = Form(None),
    content_type: Optional[str] = Form(None),
    content_text: Optional[str] = Form(None),
    quiz_id: Optional[str] = Form(None),
    content_url: Optional[str] = Form(None),
    image_url: Optional[str] = Form(None),
    media_id: Optional[str] = Form(None),
    is_document_available: Optional[str] = Form(None),
    admin=Depends(require_admin),
    db=Depends(get_db)
):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Check if session exists
    cur.execute(TABLE_SCHEMAS["lms_sessions"])
    cur.execute("SELECT * FROM lms_sessions WHERE id=%s", (sid,))
    session = cur.fetchone()
    if not session:
        raise HTTPException(404, "Session not found")
        
    updates = []
    values = []
    
    if name is not None:
        updates.append("name=%s")
        values.append(name)
        
    if duration_minutes is not None:
        try:
            duration = int(duration_minutes)
            updates.append("duration_minutes=%s")
            values.append(duration)
        except:
            pass
            
    if content_type is not None:
        updates.append("content_type=%s")
        values.append(content_type)
        
    if content_text is not None:
        updates.append("content_text=%s")
        values.append(content_text)
        
    if quiz_id is not None:
        # Validate quiz uniqueness: quiz must not already be assigned to another session
        if quiz_id:  # non-empty string means assigning a quiz
            cur.execute("SELECT id, name FROM lms_sessions WHERE quiz_id=%s AND id!=%s", (quiz_id, sid))
            existing_assignment = cur.fetchone()
            if existing_assignment:
                raise HTTPException(400, f"This quiz is already assigned to session '{existing_assignment['name']}'. A quiz can only be assigned to one session.")
        updates.append("quiz_id=%s")
        values.append(quiz_id if quiz_id else None)
        
    if content_url is not None:
        updates.append("content_url=%s")
        values.append(content_url)
        
    if image_url is not None:
        updates.append("image_url=%s")
        values.append(image_url)
        
    if media_id is not None:
        updates.append("media_id=%s")
        values.append(media_id)
        
    if is_document_available is not None:
        is_doc = is_document_available.lower() == "true"
        updates.append("is_document_available=%s")
        values.append(is_doc)
        
    if not updates:
        return session
        
    values.append(sid)
    query = f"UPDATE lms_sessions SET {', '.join(updates)} WHERE id=%s RETURNING *"
    
    # Save the old media_id to delete the file later if it changed
    old_media_id = session.get("media_id")
    
    cur.execute(query, tuple(values))
    updated_session = cur.fetchone()
    db.commit()
    
    # Delete old media file if a new one was provided
    if media_id is not None and old_media_id and old_media_id != media_id:
        try:
            cur.execute("DELETE FROM lms_media_files WHERE id=%s", (old_media_id,))
            db.commit()
            print(f"Deleted old media file {old_media_id} for session {sid}")
        except Exception as e:
            print(f"Failed to delete old media {old_media_id}: {e}")
            db.rollback()
    
    return updated_session

@api_router.delete("/sessions/{sid}")
def delete_session(sid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["lms_sessions"])
    cur.execute("DELETE FROM lms_sessions WHERE id=%s", (sid,))
    if cur.rowcount == 0:
        raise HTTPException(404, "Session not found")
    db.commit()
    return {"message": "Session deleted"}

@api_router.put("/courses/{cid}/modules/{mid}/sessions/reorder")
def reorder_sessions(cid: str, mid: str, req: ReorderRequest, admin=Depends(require_admin), db=Depends(get_db)):
    session_ids = req.ids
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["lms_sessions"])
    cur.execute("ALTER TABLE lms_sessions ADD COLUMN IF NOT EXISTS session_index INTEGER DEFAULT 0")
    
    for i, sid in enumerate(session_ids):
        cur.execute("UPDATE lms_sessions SET session_index=%s WHERE id=%s AND module_id=%s", (i, sid, mid))
        
    db.commit()
    return {"message": "Sessions reordered"}

@api_router.post("/sessions/{sid}/complete")
def complete_session(sid: str, data: Optional[Dict[str, Any]] = Body(None), user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["lms_session_progress"])
    
    # Get session details
    cur.execute(TABLE_SCHEMAS["lms_sessions"])
    cur.execute("SELECT course_id, module_id FROM lms_sessions WHERE id=%s", (sid,))
    session = cur.fetchone()
    if not session:
        raise HTTPException(404, "Session not found")
    
    time_taken = data.get("time_taken_seconds") if data else None
    quiz_marks = data.get("quiz_marks") if data else None
    last_pos = data.get("last_position_seconds") if data else None
    highest_pos = data.get("highest_position_seconds") if data else None
    completed = data.get("completed", True) if data else True
    
    # Check if already completed
    cur.execute("SELECT * FROM lms_session_progress WHERE user_id=%s AND session_id=%s", (user["id"], sid))
    existing = cur.fetchone()
    
    completed_at = datetime.now() if completed else (existing["completed_at"] if existing else None)
    
    if existing:
        # Update
        cur.execute("""
            UPDATE lms_session_progress 
                SET completed=%s, 
                    completed_at=%s, 
                    time_taken_seconds=COALESCE(%s, time_taken_seconds), 
                    quiz_marks=COALESCE(%s, quiz_marks), 
                    last_position_seconds=COALESCE(%s, last_position_seconds),
                    highest_position_seconds=GREATEST(highest_position_seconds, COALESCE(%s, 0)),
                    module_id=%s
                WHERE user_id=%s AND session_id=%s
            """, (completed, completed_at, time_taken, quiz_marks, last_pos, highest_pos, session["module_id"], user["id"], sid))
    else:
        # Insert
        progress_id = generate_id()
        cur.execute("""
            INSERT INTO lms_session_progress (id, user_id, session_id, course_id, module_id, completed, completed_at, time_taken_seconds, quiz_marks, last_position_seconds, highest_position_seconds)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (progress_id, user["id"], sid, session["course_id"], session["module_id"], completed, completed_at, time_taken, quiz_marks, last_pos, highest_pos or 0))
    
    db.commit()
    
    # Recalculate and update overall course progress
    update_course_progress(db, user["id"], session["course_id"])
    
    return {"message": "Session completed", "session_id": sid}

@api_router.get("/sessions/{sid}/progress")
def get_session_progress(sid: str, user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["lms_session_progress"])
    cur.execute("SELECT * FROM lms_session_progress WHERE user_id=%s AND session_id=%s", (user["id"], sid))
    progress = cur.fetchone()
    return progress or {"completed": False}



class QuizCreate(BaseModel):
    title: str
    course_id: Optional[str] = None
    module_id: Optional[str] = None
    session_id: Optional[str] = None
    questions: List[Dict[str, Any]] = []
    passing_score: int = 70
    time_limit_minutes: int = 30

class QuizSubmit(BaseModel):
    quiz_id: str
    answers: Dict[str, Any]

# ==================== QUIZZES ====================
@api_router.get("/quizzes")
def get_quizzes(course_id: Optional[str] = None, session_id: Optional[str] = None, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["lms_quizzes"])
    
    if session_id:
        cur.execute("SELECT * FROM lms_quizzes WHERE session_id=%s ORDER BY created_at DESC", (session_id,))
    elif course_id:
        cur.execute("SELECT * FROM lms_quizzes WHERE course_id=%s ORDER BY created_at DESC", (course_id,))
    else:
        cur.execute("SELECT * FROM lms_quizzes ORDER BY created_at DESC")
        
    return cur.fetchall()

@api_router.get("/quizzes/completed")
def get_completed_quizzes(course_id: Optional[str] = None, user=Depends(get_current_user), db=Depends(get_db)):
    """Return quiz IDs that the current user has completed (first attempt exists)."""
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    if course_id:
        cur.execute("""
            SELECT DISTINCT a.quiz_id 
            FROM lms_quiz_attempts a
            JOIN lms_quizzes q ON q.id = a.quiz_id
            WHERE a.user_id = %s AND q.course_id = %s
        """, (user["id"], course_id))
    else:
        cur.execute(
            "SELECT DISTINCT quiz_id FROM lms_quiz_attempts WHERE user_id=%s",
            (user["id"],)
        )
    rows = cur.fetchall()
    return {"completed_quiz_ids": [r["quiz_id"] for r in rows]}

@api_router.get("/quizzes/{qid}")
def get_quiz(qid: str, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM lms_quizzes WHERE id=%s", (qid,))
    quiz = cur.fetchone()
    if not quiz:
        raise HTTPException(404, "Quiz not found")
    return quiz

@api_router.post("/quizzes")
def create_quiz(
    quiz_data: QuizCreate,
    admin=Depends(require_admin),
    db=Depends(get_db)
):
    qid = generate_id()
    
    # Use numbering as question ID
    for idx, q in enumerate(quiz_data.questions):
        q["id"] = str(idx)
            
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    cur.execute("""
        INSERT INTO lms_quizzes (id, title, course_id, module_id, session_id, questions, passing_score, time_limit_minutes, created_by, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING *
    """, (qid, quiz_data.title, quiz_data.course_id, quiz_data.module_id, quiz_data.session_id, psycopg2.extras.Json(quiz_data.questions), quiz_data.passing_score, quiz_data.time_limit_minutes, admin["id"], datetime.now()))
    
    new_quiz = cur.fetchone()
    
    # Also update the session to point to this quiz if provided
    if quiz_data.session_id:
        # Clear any other quiz that might be pointing to this session
        cur.execute("UPDATE lms_quizzes SET session_id=NULL WHERE session_id=%s AND id!=%s", (quiz_data.session_id, qid))
        cur.execute("UPDATE lms_sessions SET quiz_id=%s WHERE id=%s", (qid, quiz_data.session_id))
    
    db.commit()
    return new_quiz

@api_router.put("/quizzes/{qid}")
def update_quiz(
    qid: str,
    quiz_data: QuizCreate,
    admin=Depends(require_admin),
    db=Depends(get_db)
):
    # Use numbering as question ID
    for idx, q in enumerate(quiz_data.questions):
        q["id"] = str(idx)

    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Check if quiz exists
    cur.execute("SELECT id FROM lms_quizzes WHERE id=%s", (qid,))
    if not cur.fetchone():
        raise HTTPException(404, "Quiz not found")
        
    cur.execute("""
        UPDATE lms_quizzes SET 
        title=%s, 
        course_id=%s, 
        module_id=%s, 
        session_id=%s, 
        questions=%s, 
        passing_score=%s, 
        time_limit_minutes=%s
        WHERE id=%s
        RETURNING *
    """, (
        quiz_data.title, 
        quiz_data.course_id, 
        quiz_data.module_id, 
        quiz_data.session_id, 
        psycopg2.extras.Json(quiz_data.questions), 
        quiz_data.passing_score, 
        quiz_data.time_limit_minutes,
        qid
    ))
    
    updated_quiz = cur.fetchone()
    
    # Update the session pointer
    if quiz_data.session_id:
        # If the quiz was previously in a different session, clear that session's quiz_id
        cur.execute("SELECT session_id FROM lms_quizzes WHERE id=%s", (qid,))
        old_session = cur.fetchone()
        if old_session and old_session['session_id'] and old_session['session_id'] != quiz_data.session_id:
            cur.execute("UPDATE lms_sessions SET quiz_id=NULL WHERE id=%s AND quiz_id=%s", (old_session['session_id'], qid))

        # Clear any other quiz that might be pointing to the NEW session
        cur.execute("UPDATE lms_quizzes SET session_id=NULL WHERE session_id=%s AND id!=%s", (quiz_data.session_id, qid))
        # Update the NEW session to point to this quiz
        cur.execute("UPDATE lms_sessions SET quiz_id=%s WHERE id=%s", (qid, quiz_data.session_id))
    else:
        # If the quiz now has no session, clear it from the old session if any
        cur.execute("SELECT session_id FROM lms_quizzes WHERE id=%s", (qid,))
        old_session = cur.fetchone()
        if old_session and old_session['session_id']:
            cur.execute("UPDATE lms_sessions SET quiz_id=NULL WHERE id=%s AND quiz_id=%s", (old_session['session_id'], qid))
    
    db.commit()
    return updated_quiz

@api_router.delete("/quizzes/{qid}")
def delete_quiz(
    qid: str,
    admin=Depends(require_admin),
    db=Depends(get_db)
):
    cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        # Check if quiz is in use in any session
        cursor.execute("SELECT id, name FROM lms_sessions WHERE quiz_id = %s", (qid,))
        session = cursor.fetchone()
        if session:
            return JSONResponse(
                status_code=400,
                content={"detail": f"Quiz is currently in use in session '{session['name']}'. Please remove it from the session before deleting."}
            )

        # Delete the quiz
        cursor.execute("DELETE FROM lms_quizzes WHERE id = %s", (qid,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Quiz not found")
        
        db.commit()
        return {"message": "Quiz deleted successfully"}
    except Exception as e:
        db.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()


@api_router.get("/quizzes/{qid}/result")
def get_quiz_result(qid: str, session_id: Optional[str] = None, user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Assess from session progress if session_id is provided
    if session_id:
        cur.execute(
            "SELECT completed, quiz_marks FROM lms_session_progress WHERE user_id=%s AND session_id=%s",
            (user["id"], session_id)
        )
        prog = cur.fetchone()
        if prog and prog["completed"]:
            # If completed, we can still fetch the attempt for details if we want, 
            # but the user specifically asked to assess completion from session_Progress
            cur.execute(
                "SELECT * FROM lms_quiz_attempts WHERE quiz_id=%s AND session_id=%s AND user_id=%s ORDER BY created_at ASC LIMIT 1",
                (qid, session_id, user["id"])
            )
            attempt = cur.fetchone()
            return {
                "completed": True,
                "score": prog["quiz_marks"] if prog["quiz_marks"] is not None else (attempt["score"] if attempt else 0),
                "passed": bool(attempt["passed"]) if attempt else True, # Default to True if we don't have attempt yet but session says completed
                "attempt": attempt
            }

    # Fallback to attempts table if no session_id or not found in progress
    if session_id:
        cur.execute(
            "SELECT * FROM lms_quiz_attempts WHERE quiz_id=%s AND session_id=%s AND user_id=%s ORDER BY created_at ASC LIMIT 1",
            (qid, session_id, user["id"])
        )
    else:
        cur.execute(
            "SELECT * FROM lms_quiz_attempts WHERE quiz_id=%s AND user_id=%s ORDER BY created_at ASC LIMIT 1",
            (qid, user["id"])
        )
    attempt = cur.fetchone()
    if not attempt:
        return {"completed": False}
    return {
        "completed": True,
        "score": attempt["score"],
        "passed": attempt["passed"],
        "attempt": attempt
    }

@api_router.post("/quizzes/{qid}/submit")
def submit_quiz(qid: str, data: QuizSubmit, user=Depends(get_current_user), db=Depends(get_db)):
    actual_quiz_attempt = None
    # Extract session_id from answers payload if provided by frontend
    session_id = data.answers.pop("session_id", None) if isinstance(data.answers, dict) and "session_id" in data.answers else None
    
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM lms_quizzes WHERE id=%s", (qid,))
    quiz = cur.fetchone()
    if not quiz:
        raise HTTPException(404, "Quiz not found")
        
    responses = data.answers
    questions = quiz.get("questions", [])
    
    correct_count = 0
    total_questions = len(questions)
    results = []
    
    for idx, q in enumerate(questions):
        q_id_raw = q.get("id")
        q_id = str(q_id_raw) if q_id_raw is not None else str(idx)
        
        user_ans = responses.get(q_id)
        if user_ans is None and q_id_raw is None:
            # Fallbacks for existing quizzes without IDs
            user_ans = responses.get("undefined")
            if user_ans is None:
                user_ans = responses.get("None")
                
        # The quiz editor stores the correct option index as "correct_answer"
        correct_ans = q.get("correct_answer")
        if correct_ans is None:
            correct_ans = q.get("correctOption") if q.get("correctOption") is not None else q.get("answer")
        
        # Compare as integers (option index)
        is_correct = False
        if user_ans is not None and correct_ans is not None:
            is_correct = int(user_ans) == int(correct_ans)
        if is_correct:
            correct_count += 1
            
        results.append({
            "question_id": q_id,
            "correct": is_correct,
            "correct_answer": correct_ans
        })
            
    score = int((correct_count / total_questions) * 100) if total_questions > 0 else 0
    passed = score >= (quiz.get("passing_score") or 70)
    
    # Check if user already has a previous attempt for this session (first attempt only saves score)
    if session_id:
        cur.execute(
            "SELECT id FROM lms_quiz_attempts WHERE quiz_id=%s AND session_id=%s AND user_id=%s ORDER BY created_at ASC LIMIT 1",
            (qid, session_id, user["id"])
        )
    else:
        cur.execute(
            "SELECT id FROM lms_quiz_attempts WHERE quiz_id=%s AND user_id=%s ORDER BY created_at ASC LIMIT 1",
            (qid, user["id"])
        )
    existing_attempt = cur.fetchone()
    is_practice = existing_attempt is not None
    
    if not is_practice:
        # First attempt - save score
        attempt_id = generate_id()
        cur.execute("""
            INSERT INTO lms_quiz_attempts (id, quiz_id, session_id, user_id, score, passed, responses)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (attempt_id, qid, session_id, user["id"], score, passed, psycopg2.extras.Json(responses)))
        actual_quiz_attempt = cur.fetchone()
    
    # Robust session_id resolution
    active_session_id = session_id
    if not active_session_id:
        # Fallback 1: Check quiz record for session_id
        active_session_id = quiz.get("session_id")
        
    if not active_session_id:
        # Fallback 2: Find a session that points to this quiz
        cur.execute("SELECT id FROM lms_sessions WHERE quiz_id=%s LIMIT 1", (qid,))
        session_row = cur.fetchone()
        if session_row:
            active_session_id = session_row["id"]

    # Update session progress if we have a session_id (primary or fallback)
    if active_session_id:
        cur.execute("SELECT course_id, module_id FROM lms_sessions WHERE id=%s", (active_session_id,))
        session_info = cur.fetchone()
        if session_info:
            cur.execute("SELECT id FROM lms_session_progress WHERE user_id=%s AND session_id=%s", (user["id"], active_session_id))
            progress_row = cur.fetchone()
            
            if progress_row:
                cur.execute("""
                    UPDATE lms_session_progress 
                    SET completed=true, completed_at=%s, quiz_marks=%s, module_id=%s
                    WHERE user_id=%s AND session_id=%s
                """, (datetime.now(), score, session_info["module_id"], user["id"], active_session_id))
            else:
                curr_time = datetime.now()
                prog_id = generate_id()
                cur.execute("""
                    INSERT INTO lms_session_progress (id, user_id, session_id, course_id, module_id, completed, completed_at, quiz_marks)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (prog_id, user["id"], active_session_id, session_info["course_id"], session_info["module_id"], True, curr_time, score))

    db.commit()
    
    # Update global progress if we figured out a course associated
    if active_session_id and session_info and session_info["course_id"]:
        update_course_progress(db, user["id"], session_info["course_id"])
    elif quiz.get("course_id"):
        update_course_progress(db, user["id"], quiz["course_id"])
        
    return {
        "score": score,
        "passed": passed,
        "correct_answers": correct_count,
        "total_questions": total_questions,
        "results": results,
        "attempt": actual_quiz_attempt,
        "is_practice": is_practice,
        "session_id": active_session_id
    }





# ==================== MEDIA STORAGE ====================
MAX_FILE_SIZE = 50 * 1024 * 1024 # 50MB

@api_router.post("/media/upload")
async def upload_media(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
    db=Depends(get_db)
):
    # Read file data
    file_data = await file.read()
    file_size = len(file_data)
    
    # Validation: Size
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(413, f"File too large. Max size is {MAX_FILE_SIZE/(1024*1024)}MB")
    
    file_id = generate_id()
    
    # Infer file type accurately
    content_type = file.content_type or "application/octet-stream"
    file_type = "other"
    if content_type.startswith("image/"):
        file_type = "image"
    elif content_type.startswith("video/"):
        file_type = "video"
    elif content_type.startswith("audio/"):
        file_type = "audio"
    elif content_type == "application/pdf":
        file_type = "pdf"
        
    cur = db.cursor()
    try:
        cur.execute(TABLE_SCHEMAS["lms_media_files"])
        cur.execute("""
            INSERT INTO lms_media_files (id, file_name, file_type, mime_type, file_data, file_size, uploaded_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (file_id, file.filename, file_type, content_type, psycopg2.Binary(file_data), file_size, user["id"]))
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Database error during upload: {e}")
        raise HTTPException(500, "Failed to store file in database")
    
    return {
        "id": file_id,
        "file_name": file.filename,
        "file_type": file_type,
        "mime_type": content_type,
        "file_size": file_size
    }

@api_router.get("/media/{mid}")
async def get_media(mid: str, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT file_name, mime_type, file_data, file_size FROM lms_media_files WHERE id=%s", (mid,))
    media = cur.fetchone()
    if not media:
        raise HTTPException(404, "Media not found")
        
    # Return directly for small files, or use StreamingResponse if needed
    # Since it's in BYTEA, it's already in memory when fetched.
    return Response(
        content=bytes(media["file_data"]),
        media_type=media["mime_type"],
        headers={
            "Content-Disposition": f"inline; filename=\"{media['file_name']}\"",
            "Cache-Control": "public, max-age=31536000",
            "Accept-Ranges": "bytes"
        }
    )

@api_router.get("/media/stream/{mid}")
async def stream_media(mid: str, db=Depends(get_db)):
    from fastapi import Request
    
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT file_name, mime_type, file_data, file_size FROM lms_media_files WHERE id=%s", (mid,))
    media = cur.fetchone()
    if not media:
        raise HTTPException(404, "Media not found")
        
    file_data = bytes(media["file_data"])
    
    # Simple stream for now, for real streaming we need to handle Range headers manually 
    # if we don't want to load everything into memory. 
    # However, since it's already in a variable from Postgres, it's already in memory.
    
    return StreamingResponse(
        io.BytesIO(file_data),
        media_type=media["mime_type"],
        headers={
            "Content-Disposition": f"inline; filename=\"{media['file_name']}\"",
            "Accept-Ranges": "bytes"
        }
    )

# ==================== STUDENT ANALYTICS ====================
@api_router.get("/admin/student/{uid}/analytics")
def get_student_analytics(uid: str, user=Depends(get_current_user), db=Depends(get_db)):
    if user["role"] != "admin" and user["id"] != uid:
        raise HTTPException(status_code=403, detail="Not authorized to view these analytics")
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # 1. Course Progress
    cur.execute("""
        SELECT count(*) as total_assigned,
               count(*) FILTER (WHERE status = 'active') as total_started,
               count(*) FILTER (WHERE is_completed = true) as total_completed
        FROM lms_user_courses WHERE user_id=%s
    """, (uid,))
    course_stats = cur.fetchone()
    
    cur.execute("""
        SELECT c.id, c.title, c.thumbnail, uc.progress_percentage, uc.is_completed, uc.status
        FROM lms_user_courses uc
        JOIN lms_courses c ON c.id = uc.course_id
        WHERE uc.user_id=%s
    """, (uid,))
    courses = cur.fetchall()

    # 2. Session Progress
    cur.execute("""
        SELECT count(*) as total_completed
        FROM lms_session_progress WHERE user_id=%s AND completed=true
    """, (uid,))
    total_sessions_completed = cur.fetchone()["total_completed"]

    cur.execute("""
        SELECT count(s.id) as total_assigned
        FROM lms_user_courses uc
        JOIN lms_sessions s ON s.course_id = uc.course_id
        WHERE uc.user_id=%s
    """, (uid,))
    total_sessions_assigned = cur.fetchone()["total_assigned"]
    total_sessions_pending = total_sessions_assigned - total_sessions_completed if total_sessions_assigned else 0

    session_stats = {
        "completed": total_sessions_completed,
        "pending": total_sessions_pending,
        "overall_percentage": int((total_sessions_completed / total_sessions_assigned) * 100) if total_sessions_assigned > 0 else 0
    }

    # 3. Quiz Analytics
    cur.execute("""
        SELECT qa.id, qa.score, qa.passed, qa.responses, qa.created_at,
               q.title, q.questions, q.passing_score
        FROM lms_quiz_attempts qa
        JOIN lms_quizzes q ON q.id = qa.quiz_id
        WHERE qa.user_id=%s
        ORDER BY qa.created_at DESC
    """, (uid,))
    quiz_attempts = cur.fetchall()
    
    quizzes_attempted = len(quiz_attempts)
    quizzes_passed = len([q for q in quiz_attempts if q["passed"]])
    
    detailed_quizzes = []
    for q in quiz_attempts:
        responses = q["responses"] or {}
        questions = q["questions"] or []
        details = []
        for qst in questions:
            qid = qst.get("id")
            correct = qst.get("correctOption")
            selected = responses.get(qid)
            details.append({
                "question": qst.get("text"),
                "selected_answer": selected,
                "correct_answer": correct,
                "is_correct": str(selected) == str(correct)
            })
        detailed_quizzes.append({
            "id": q["id"],
            "title": q["title"],
            "score": q["score"],
            "passed": q["passed"],
            "date": q["created_at"].isoformat() if q["created_at"] else None,
            "details": details
        })
        
    quiz_stats = {
        "attempted": quizzes_attempted,
        "passed": quizzes_passed,
        "attempts": detailed_quizzes
    }

    # 4. Learning Path Progress
    cur.execute("""
        SELECT lp.id, lp.title, ulp.is_completed, ulp.status
        FROM lms_user_learning_paths ulp
        JOIN lms_learning_paths lp ON lp.id = ulp.path_id
        WHERE ulp.user_id=%s
    """, (uid,))
    learning_paths = cur.fetchall()

    # 5. Activity & Streak
    cur.execute("""
        SELECT DISTINCT DATE(created_at) as active_date
        FROM lms_session_progress 
        WHERE user_id=%s
        UNION
        SELECT DISTINCT DATE(created_at) as active_date
        FROM lms_quiz_attempts
        WHERE user_id=%s
        ORDER BY active_date DESC
    """, (uid, uid))
    active_dates_rows = cur.fetchall()
    active_dates = [row["active_date"] for row in active_dates_rows] if active_dates_rows else []
    
    total_active_days = len(active_dates)
    last_active_date = active_dates[0].isoformat() if active_dates else None
    
    current_streak = 0
    longest_streak = 0
    if active_dates:
        from datetime import date, timedelta
        today = date.today()
        
        curr_date = today
        if active_dates[0] == today or active_dates[0] == today - timedelta(days=1):
            temp_streak = 0
            check_date = active_dates[0]
            i = 0
            while i < len(active_dates) and active_dates[i] == check_date:
                temp_streak += 1
                check_date -= timedelta(days=1)
                i += 1
            current_streak = temp_streak
            
        longest = 1
        current = 1
        for i in range(1, len(active_dates)):
            if active_dates[i-1] - active_dates[i] == timedelta(days=1):
                current += 1
                longest = max(longest, current)
            else:
                current = 1
        longest_streak = max(longest, longest_streak) if len(active_dates) > 0 else 0
        if longest_streak == 0 and len(active_dates) > 0:
            longest_streak = 1
            
    activity_stats = {
        "total_active_days": total_active_days,
        "last_active_date": last_active_date,
        "current_streak": current_streak,
        "longest_streak": longest_streak
    }

    return {
        "course_progress": {
            "stats": course_stats,
            "courses": courses
        },
        "session_progress": session_stats,
        "quiz_analytics": quiz_stats,
        "learning_paths": learning_paths,
        "activity": activity_stats
    }

@api_router.get("/health")
def health():
    return {"status":"ok","time":datetime.now()}

# ==================== FINAL ====================
app.include_router(api_router) 


if __name__ == "__main__":
    init_db()
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
