import streamlit as st
import pandas as pd
import random
import base64
from datetime import datetime, timedelta
import time
import bcrypt
from uuid import uuid4
import sqlite3
import os
import re
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
from PIL import Image
import io
import math
import logging
from cryptography.fernet import Fernet
import hashlib
import hmac
import json
from streamlit_webrtc import webrtc_streamer, WebRtcMode, RTCConfiguration
import av
import binascii

# Load environment variables
load_dotenv()

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
PEPPER_SECRET = os.getenv("PEPPER_SECRET", "default-pepper-secret")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")

# Initialize encryption
cipher_suite = Fernet(ENCRYPTION_KEY.encode())

# WebRTC configuration
RTC_CONFIGURATION = RTCConfiguration(
    {"iceServers": [{"urls": ["stun:stun.l.google.com:19302"]}]}
)

# Database connection manager
def get_db_connection():
    conn = sqlite3.connect("campus_connect.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database with proper schema
def init_database():
    with get_db_connection() as conn:
        c = conn.cursor()

        # Create users table
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (
                         email TEXT PRIMARY KEY,
                         password TEXT,
                         salt TEXT,
                         verified BOOLEAN DEFAULT 0,
                         otp TEXT,
                         otp_expiry DATETIME,
                         last_active DATETIME,
                         login_attempts INTEGER DEFAULT 0,
                         last_attempt DATETIME,
                         banned BOOLEAN DEFAULT 0
                     )''')

        # Create profiles table
        c.execute('''CREATE TABLE IF NOT EXISTS profiles
                     (
                         email TEXT PRIMARY KEY,
                         name TEXT,
                         age INTEGER,
                         gender TEXT,
                         bio TEXT,
                         interests TEXT,
                         photo BLOB,
                         timestamp DATETIME,
                         intention TEXT DEFAULT 'Not sure yet'
                     )''')

        # Create connections table
        c.execute('''CREATE TABLE IF NOT EXISTS connections
                     (
                         id TEXT PRIMARY KEY,
                         from_email TEXT,
                         to_email TEXT,
                         status TEXT,
                         timestamp DATETIME
                     )''')

        # Create messages table
        c.execute('''CREATE TABLE IF NOT EXISTS messages
                     (
                         id TEXT PRIMARY KEY,
                         chat_id TEXT,
                         sender TEXT,
                         receiver TEXT,
                         message TEXT,
                         time DATETIME,
                         read BOOLEAN DEFAULT 0
                     )''')

        # Create reports table
        c.execute('''CREATE TABLE IF NOT EXISTS reports
                     (
                         id TEXT PRIMARY KEY,
                         reporter_email TEXT,
                         reported_email TEXT,
                         reason TEXT,
                         details TEXT,
                         timestamp DATETIME,
                         status TEXT DEFAULT 'pending'
                     )''')

        # Create password resets table
        c.execute('''CREATE TABLE IF NOT EXISTS password_resets
                     (
                         email TEXT PRIMARY KEY,
                         otp TEXT,
                         expiry DATETIME
                     )''')

        # Create blocked users table
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_users
                     (
                         blocker_email TEXT,
                         blocked_email TEXT,
                         timestamp DATETIME,
                         PRIMARY KEY (blocker_email, blocked_email)
                     )''')
        
        # Create admins table
        c.execute('''CREATE TABLE IF NOT EXISTS admins
                     (
                         email TEXT PRIMARY KEY
                     )''')

        # Add indexes for performance
        c.execute('''CREATE INDEX IF NOT EXISTS idx_connections_from ON connections(from_email)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_connections_to ON connections(to_email)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_profiles_timestamp ON profiles(timestamp)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_users_verified ON users(verified)''')
        
        # Ensure admin exists
        c.execute("INSERT OR IGNORE INTO admins (email) VALUES (?)", (ADMIN_EMAIL,))
        conn.commit()

# Initialize session state
def init_session_state():
    if "current_user" not in st.session_state:
        # Check for session token in URL
        if st.query_params.get("session_token"):
            valid_email = validate_session(st.query_params.get("session_token"))
            if valid_email:
                st.session_state.current_user = valid_email
                st.session_state.session_token = st.query_params.get("session_token")
    
    if "view" not in st.session_state:
        st.session_state.view = "auth"
    if "current_chat" not in st.session_state:
        st.session_state.current_chat = None
    if "current_index" not in st.session_state:
        st.session_state.current_index = 0
    if "notifications" not in st.session_state:
        st.session_state.notifications = []
    if "pending_verification" not in st.session_state:
        st.session_state.pending_verification = False
    if "temp_email" not in st.session_state:
        st.session_state.temp_email = None
    if "temp_password" not in st.session_state:
        st.session_state.temp_password = None
    if "otp_attempts" not in st.session_state:
        st.session_state.otp_attempts = 0
    if "resetting_password" not in st.session_state:
        st.session_state.resetting_password = False
    if "reporting_user" not in st.session_state:
        st.session_state.reporting_user = None
    if "reporting_name" not in st.session_state:
        st.session_state.reporting_name = None
    if "profiles_cache" not in st.session_state:
        st.session_state.profiles_cache = None
    if "cache_timestamp" not in st.session_state:
        st.session_state.cache_timestamp = None
    if "swipe_x" not in st.session_state:
        st.session_state.swipe_x = 0
    if "swipe_y" not in st.session_state:
        st.session_state.swipe_y = 0
    if "swipe_start" not in st.session_state:
        st.session_state.swipe_start = None
    if "swipe_action" not in st.session_state:
        st.session_state.swipe_action = None
    if "reset_otp_verification" not in st.session_state:
        st.session_state.reset_otp_verification = False
    if "reset_otp_attempts" not in st.session_state:
        st.session_state.reset_otp_attempts = 0
    if "temp_reset_email" not in st.session_state:
        st.session_state.temp_reset_email = None
    if "form_errors" not in st.session_state:
        st.session_state.form_errors = {
            "name": False,
            "bio": False,
            "interests": False,
            "photo": False
        }
    if "call_state" not in st.session_state:
        st.session_state.call_state = None
    if "caller" not in st.session_state:
        st.session_state.caller = None
    if "callee" not in st.session_state:
        st.session_state.callee = None
    if "current_call" not in st.session_state:
        st.session_state.current_call = None
    if "login_attempts" not in st.session_state:
        st.session_state.login_attempts = {}
    if "session_token" not in st.session_state:
        st.session_state.session_token = None
    if "csrf_token" not in st.session_state:
        st.session_state.csrf_token = binascii.hexlify(os.urandom(16)).decode()

# Security functions
def encrypt_data(data):
    """Encrypt sensitive data before storage"""
    if isinstance(data, str):
        data = data.encode()
    return cipher_suite.encrypt(data)

def decrypt_data(encrypted_data):
    """Decrypt data for use"""
    return cipher_suite.decrypt(encrypted_data).decode()

def sanitize_input(input_str, max_length=255):
    """Sanitize user input to prevent XSS and injection attacks"""
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\'%;()&]', '', input_str)
    # Truncate to max length
    return sanitized[:max_length]

def create_session(email):
    """Create secure session token"""
    session_data = {
        "email": email,
        "created": datetime.now().isoformat(),
        "expires": (datetime.now() + timedelta(hours=1)).isoformat()
    }
    data_str = json.dumps(session_data)
    signature = hmac.new(
        SECRET_KEY.encode(),
        data_str.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{data_str}|{signature}"

def validate_session(token):
    """Validate session token"""
    if not token:
        return False
        
    try:
        data_str, signature = token.split("|")
        expected_signature = hmac.new(
            SECRET_KEY.encode(),
            data_str.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            return False
            
        session_data = json.loads(data_str)
        if datetime.fromisoformat(session_data["expires"]) < datetime.now():
            return False
            
        return session_data["email"]
    except:
        return False

# Configure security logging
logging.basicConfig(
    filename='security.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_security_event(event_type, details, user=None):
    """Log security events"""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event_type,
        "user": user or st.session_state.get("current_user", "anonymous"),
        "details": details,
        "ip": st.experimental_user.get("ip", "unknown")
    }
    logging.info(json.dumps(entry))

# Email validation
def is_valid_student_email(email):
    if not email:
        return False
    if len(email) < 3 or not email[:3].isdigit():
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Generate random 6-digit OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Email functions
def send_otp_email(receiver_email, otp):
    sender_email = os.getenv("SMTP_EMAIL")
    sender_password = os.getenv("SMTP_PASSWORD")

    if not sender_email or not sender_password:
        st.error("Email configuration error. Please check your .env file")
        return False

    message = MIMEText(f"""Your Campus Connect verification code is: {otp}

This code will expire in 10 minutes.""")
    message['Subject'] = "Verify Your Campus Connect Account"
    message['From'] = sender_email
    message['To'] = receiver_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        return True
    except Exception as e:
        st.error(f"Failed to send OTP: {str(e)}")
        return False

def send_reset_otp_email(receiver_email, otp):
    sender_email = os.getenv("SMTP_EMAIL")
    sender_password = os.getenv("SMTP_PASSWORD")

    if not sender_email or not sender_password:
        st.error("Email configuration error. Please check your .env file")
        return False

    message = MIMEText(f"""You requested a password reset for your Campus Connect account.

Your password reset code is: {otp}

This code will expire in 10 minutes.

If you didn't request this, please ignore this email.""")
    message['Subject'] = "Password Reset OTP - Campus Connect"
    message['From'] = sender_email
    message['To'] = receiver_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        return True
    except Exception as e:
        st.error(f"Failed to send reset OTP: {str(e)}")
        return False

def send_report_notification(reporter, reported, reason, details):
    message = MIMEText(f"""New User Report on Campus Connect:
    
Reporter: {reporter}
Reported User: {reported}
Reason: {reason}
Details: {details}

Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
""")
    message['Subject'] = "⚠️ New User Report - Campus Connect"
    message['From'] = os.getenv("SMTP_EMAIL")
    message['To'] = ADMIN_EMAIL

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(os.getenv("SMTP_EMAIL"), os.getenv("SMTP_PASSWORD"))
            server.sendmail(os.getenv("SMTP_EMAIL"), ADMIN_EMAIL, message.as_string())
        return True
    except Exception as e:
        st.error(f"Failed to send report notification: {str(e)}")
        return False

# Verify OTPs
def verify_otp_in_db(email, user_otp):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT otp, otp_expiry FROM users WHERE email=?", (email,))
        result = c.fetchone()

    if not result or not result["otp"]:
        return False

    stored_otp = result["otp"]
    expiry_str = result["otp_expiry"]
    expiry = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S.%f") if '.' in expiry_str else datetime.strptime(
        expiry_str, "%Y-%m-%d %H:%M:%S")

    return stored_otp == user_otp and datetime.now() < expiry

def verify_reset_otp(email, user_otp):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT otp, expiry FROM password_resets WHERE email=?", (email,))
        result = c.fetchone()

    if not result or not result["otp"]:
        return False

    stored_otp = result["otp"]
    expiry_str = result["expiry"]
    expiry = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S.%f") if '.' in expiry_str else datetime.strptime(
        expiry_str, "%Y-%m-%d %H:%M:%S")

    return stored_otp == user_otp and datetime.now() < expiry

# Authentication system
def auth_system():
    st.title("Campus Connect 🔐😍❤️")
    st.subheader("Student social connection platform")
    
    # Compliance notice
    st.info("""
    **Compliance Notice:**  
    This platform is for social networking purposes only. All users must adhere to their institution's code of conduct.
    """)

    # OTP Verification Screen
    if st.session_state.pending_verification:
        email = st.session_state.temp_email
        st.subheader(f"Verify {email}")

        user_otp = st.text_input("Enter 6-digit OTP", max_chars=6, key="otp_input")

        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("Verify", type="primary"):
                if verify_otp_in_db(email, user_otp):
                    salt = bcrypt.gensalt()
                    # Add pepper to password
                    peppered_password = st.session_state.temp_password + PEPPER_SECRET
                    hashed_pw = bcrypt.hashpw(peppered_password.encode(), salt)

                    with get_db_connection() as conn:
                        conn.execute(
                            "UPDATE users SET password=?, salt=?, verified=1, otp=NULL, otp_expiry=NULL WHERE email=?",
                            (hashed_pw, salt, email)
                        )
                        conn.commit()

                    st.session_state.current_user = email
                    st.session_state.session_token = create_session(email)
                    st.query_params["session_token"] = st.session_state.session_token
                    st.session_state.pending_verification = False
                    st.session_state.view = "profile"
                    st.success("Account verified! Please create your profile.")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.session_state.otp_attempts += 1
                    if st.session_state.otp_attempts >= 3:
                        st.error("Too many failed attempts. Please register again.")
                        with get_db_connection() as conn:
                            conn.execute("DELETE FROM users WHERE email=?", (email,))
                            conn.commit()
                        st.session_state.pending_verification = False
                        time.sleep(2)
                        st.rerun()
                    else:
                        st.error("Invalid OTP. Please try again.")

        with col2:
            if st.button("Resend OTP"):
                new_otp = generate_otp()
                expiry = datetime.now() + timedelta(minutes=10)

                with get_db_connection() as conn:
                    conn.execute(
                        "UPDATE users SET otp=?, otp_expiry=? WHERE email=?",
                        (new_otp, expiry, email)
                    )
                    conn.commit()

                if send_otp_email(email, new_otp):
                    st.success("New OTP sent!")
                else:
                    st.error("Failed to resend OTP")

        with col3:
            if st.button("Cancel"):
                with get_db_connection() as conn:
                    conn.execute("DELETE FROM users WHERE email=?", (email,))
                    conn.commit()

                st.session_state.pending_verification = False
                st.info("Registration cancelled")
                time.sleep(1)
                st.rerun()

        st.caption("Didn't receive OTP? Check spam folder or resend.")
        return

    # Password Reset Screen
    if st.session_state.resetting_password:
        st.subheader("Create New Password")

        with st.form("reset_password_form"):
            new_password = st.text_input("New Password (min 8 characters)", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")

            if st.form_submit_button("Reset Password"):
                if len(new_password) < 8:
                    st.error("Password must be at least 8 characters")
                elif new_password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    # Add pepper to password
                    peppered_password = new_password + PEPPER_SECRET
                    salt = bcrypt.gensalt()
                    hashed_pw = bcrypt.hashpw(peppered_password.encode(), salt)

                    with get_db_connection() as conn:
                        conn.execute(
                            "UPDATE users SET password=?, salt=? WHERE email=?",
                            (hashed_pw, salt, st.session_state.temp_email)
                        )
                        conn.execute(
                            "DELETE FROM password_resets WHERE email=?",
                            (st.session_state.temp_email,)
                        )
                        conn.commit()

                    st.success("Password updated successfully! Please login with your new password.")
                    st.session_state.resetting_password = False
                    time.sleep(2)
                    st.rerun()

        if st.button("Cancel"):
            st.session_state.resetting_password = False
            st.rerun()

        return

    # Reset OTP Verification Screen
    if st.session_state.reset_otp_verification:
        email = st.session_state.temp_reset_email
        st.subheader(f"Reset Password for {email}")
        
        user_otp = st.text_input("Enter 6-digit OTP sent to your email", max_chars=6, key="reset_otp_input")

        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("Verify OTP", type="primary", key="verify_reset_otp"):
                if verify_reset_otp(email, user_otp):
                    st.session_state.reset_otp_verification = False
                    st.session_state.resetting_password = True
                    st.session_state.temp_email = email
                    st.rerun()
                else:
                    st.session_state.reset_otp_attempts += 1
                    if st.session_state.reset_otp_attempts >= 3:
                        st.error("Too many failed attempts. Please start over.")
                        with get_db_connection() as conn:
                            conn.execute("DELETE FROM password_resets WHERE email=?", (email,))
                            conn.commit()
                        st.session_state.reset_otp_verification = False
                        time.sleep(2)
                        st.rerun()
                    else:
                        st.error("Invalid OTP. Please try again.")

        with col2:
            if st.button("Resend OTP", key="resend_reset_otp"):
                new_otp = generate_otp()
                expiry = datetime.now() + timedelta(minutes=10)

                with get_db_connection() as conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO password_resets (email, otp, expiry) VALUES (?, ?, ?)",
                        (email, new_otp, expiry)
                    )
                    conn.commit()

                if send_reset_otp_email(email, new_otp):
                    st.success("New OTP sent!")
                else:
                    st.error("Failed to resend OTP")

        with col3:
            if st.button("Cancel", key="cancel_reset_otp"):
                with get_db_connection() as conn:
                    conn.execute("DELETE FROM password_resets WHERE email=?", (email,))
                    conn.commit()
                st.session_state.reset_otp_verification = False
                st.info("Password reset cancelled")
                time.sleep(1)
                st.rerun()

        st.caption("Didn't receive OTP? Check spam folder or resend.")
        return

    # Normal auth tabs
    login_tab, register_tab = st.tabs(["Login", "Register"])

    with login_tab:
        with st.form("login_form"):
            # CSRF protection
            st.session_state.csrf_token = binascii.hexlify(os.urandom(16)).decode()
            st.hidden_input("csrf_token", value=st.session_state.csrf_token)
            
            email = st.text_input("Student Email (must start with 3 numbers)", key="login_email")
            password = st.text_input("Password", type="password")
            remember_me = st.checkbox("Remember me")

            if st.form_submit_button("Login"):
                # CSRF validation
                if not st.query_params.get("csrf_token") or st.query_params.get("csrf_token") != st.session_state.csrf_token:
                    log_security_event("CSRF_FAILURE", f"Invalid CSRF token from {email}")
                    st.error("Security error. Please try again.")
                    return
                
                # Rate limiting
                ip = st.experimental_user.get("ip", "unknown")
                now = time.time()
                
                if ip not in st.session_state.login_attempts:
                    st.session_state.login_attempts[ip] = {"count": 0, "last_attempt": 0}
                
                attempts = st.session_state.login_attempts[ip]
                
                # Reset counter if last attempt was > 15 min ago
                if now - attempts["last_attempt"] > 900:
                    attempts["count"] = 0
                
                if attempts["count"] >= 5:
                    st.error("Too many login attempts. Please try again later.")
                    log_security_event("RATE_LIMIT", f"Blocked IP {ip} for too many attempts")
                    return
                    
                if not is_valid_student_email(email):
                    st.error("Invalid student email format. Must start with 3 numbers")
                else:
                    with get_db_connection() as conn:
                        c = conn.cursor()
                        c.execute("SELECT password, salt, verified, banned FROM users WHERE email=?", (email,))
                        result = c.fetchone()

                    if result:
                        hashed_pw, salt, verified, banned = result

                        # Check if banned
                        if banned:
                            st.error("This account has been banned")
                            log_security_event("BANNED_ATTEMPT", f"Banned user tried to login: {email}")
                            return
                            
                        # Add security delay to prevent timing attacks
                        time.sleep(random.uniform(0.1, 0.3))
                        
                        # Add pepper to password
                        peppered_password = password + PEPPER_SECRET
                        
                        try:
                            if bcrypt.hashpw(peppered_password.encode(), salt) == hashed_pw:
                                if not verified:
                                    st.error("Account not verified. Please check your email.")
                                else:
                                    st.session_state.current_user = email
                                    st.session_state.session_token = create_session(email)
                                    st.query_params["session_token"] = st.session_state.session_token
                                    
                                    # Check if profile exists
                                    with get_db_connection() as conn:
                                        profile_exists = conn.execute(
                                            "SELECT 1 FROM profiles WHERE email=?",
                                            (email,)
                                        ).fetchone()

                                    st.session_state.view = "profile" if not profile_exists else "discover"
                                    st.rerun()
                            else:
                                st.error("Incorrect password")
                                attempts["count"] += 1
                                attempts["last_attempt"] = now
                                st.session_state.login_attempts[ip] = attempts
                                log_security_event("LOGIN_FAILURE", f"Failed login for {email}")
                        except TypeError as e:
                            st.error(f"Authentication error: {str(e)}")
                    else:
                        st.error("Email not registered")
                        log_security_event("LOGIN_UNKNOWN", f"Attempt to login with unknown email: {email}")

        # Forgot password link
        if st.button("Forgot Password?"):
            st.session_state.view = "forgot_password"
            st.rerun()

    with register_tab:
        with st.form("register_form"):
            # CSRF protection
            st.session_state.csrf_token = binascii.hexlify(os.urandom(16)).decode()
            st.hidden_input("csrf_token", value=st.session_state.csrf_token)
            
            email = st.text_input("Student Email (must start with 3 numbers)", key="register_email")
            password = st.text_input("Create Password (min 8 characters)", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")

            if st.form_submit_button("Create Account"):
                # CSRF validation
                if not st.query_params.get("csrf_token") or st.query_params.get("csrf_token") != st.session_state.csrf_token:
                    log_security_event("CSRF_FAILURE", f"Invalid CSRF token during registration")
                    st.error("Security error. Please try again.")
                    return
                
                if not is_valid_student_email(email):
                    st.error("Invalid student email format. Must start with 3 numbers")
                elif len(password) < 8:
                    st.error("Password must be at least 8 characters")
                elif password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    # Check if email exists
                    with get_db_connection() as conn:
                        c = conn.cursor()
                        c.execute("SELECT 1 FROM users WHERE email=?", (email,))
                        if c.fetchone():
                            st.error("Email already registered")
                        else:
                            # Generate OTP
                            otp = generate_otp()
                            expiry = datetime.now() + timedelta(minutes=10)

                            # Store temporary user record with OTP
                            c.execute(
                                "INSERT INTO users (email, verified, otp, otp_expiry) VALUES (?, ?, ?, ?)",
                                (email, 0, otp, expiry)
                            )
                            conn.commit()

                            if send_otp_email(email, otp):
                                st.session_state.pending_verification = True
                                st.session_state.temp_email = email
                                st.session_state.temp_password = password
                                st.session_state.otp_attempts = 0
                                st.rerun()
                            else:
                                # Rollback if email fails
                                conn.rollback()
                                st.error("Failed to send OTP. Try again.")

# Forgot password flow
def forgot_password():
    st.title("Reset Your Password")

    with st.form("forgot_password_form"):
        email = st.text_input("Enter your student email address")

        if st.form_submit_button("Send OTP"):
            if not is_valid_student_email(email):
                st.error("Invalid student email format")
            else:
                with get_db_connection() as conn:
                    user_exists = conn.execute(
                        "SELECT 1 FROM users WHERE email=?", (email,)
                    ).fetchone()

                if not user_exists:
                    st.error("Email not registered")
                else:
                    # Generate and store reset OTP
                    otp = generate_otp()
                    expiry = datetime.now() + timedelta(minutes=10)

                    with get_db_connection() as conn:
                        conn.execute(
                            "INSERT OR REPLACE INTO password_resets (email, otp, expiry) VALUES (?, ?, ?)",
                            (email, otp, expiry)
                        )
                        conn.commit()

                    if send_reset_otp_email(email, otp):
                        st.session_state.reset_otp_verification = True
                        st.session_state.temp_reset_email = email
                        st.session_state.reset_otp_attempts = 0
                        st.rerun()
                    else:
                        st.error("Failed to send OTP. Please try again.")

    if st.button("Back to Login"):
        st.session_state.view = "auth"
        st.rerun()

# Profile Creation
def create_profile():
    st.title("Create Your Profile")
    st.caption("Complete your profile to start connecting")

    # Initialize form errors
    if "form_errors" not in st.session_state:
        st.session_state.form_errors = {
            "name": False,
            "bio": False,
            "interests": False,
            "photo": False
        }

    # Check if profile already exists
    with get_db_connection() as conn:
        profile_exists = conn.execute(
            "SELECT 1 FROM profiles WHERE email=?",
            (st.session_state.current_user,)
        ).fetchone()
    
    if profile_exists:
        st.warning("You already have a profile. Redirecting to edit page...")
        st.session_state.view = "edit_profile"
        time.sleep(1)
        st.rerun()

    with st.form("profile_form", clear_on_submit=True):
        # CSRF protection
        st.session_state.csrf_token = binascii.hexlify(os.urandom(16)).decode()
        st.hidden_input("csrf_token", value=st.session_state.csrf_token)
        
        email = st.text_input("Student Email", value=st.session_state.current_user, disabled=True)
        
        # Name field with validation
        name_label = "Full Name*"
        if st.session_state.form_errors.get("name", False):
            name_label = f":red[{name_label}]"
        name = st.text_input(name_label)
        
        age = st.slider("Age", 18, 30)
        gender = st.selectbox("Gender", ["Male", "Female", "Non-binary", "Prefer not to say"])
        
        # Bio field with validation
        bio_label = "About Me*"
        if st.session_state.form_errors.get("bio", False):
            bio_label = f":red[{bio_label}]"
        bio = st.text_area(bio_label, placeholder="Tell others about yourself...")
        
        # Interests field with validation
        interests_label = "Interests*"
        if st.session_state.form_errors.get("interests", False):
            interests_label = f":red[{interests_label}]"
        interests = st.multiselect(interests_label, [
            "Sports", "Music", "Gaming", "Academics",
            "Art", "Travel", "Food", "Movies", "Dancing"
        ])

        intention = st.radio("What are you looking for?",
                             ["Relationship", "Friendship", "Hookups", "Not sure yet"],
                             index=3)

        # Photo uploader with validation
        photo_label = "Profile Photo (max 10MB)*"
        if st.session_state.form_errors.get("photo", False):
            photo_label = f":red[{photo_label}]"
        photo = st.file_uploader(photo_label, type=["jpg", "png", "jpeg"],
                                 accept_multiple_files=False)

        # Submit button
        submitted = st.form_submit_button("Save Profile")
        
        if submitted:
            # CSRF validation
            if not st.query_params.get("csrf_token") or st.query_params.get("csrf_token") != st.session_state.csrf_token:
                log_security_event("CSRF_FAILURE", f"Invalid CSRF token during profile creation")
                st.error("Security error. Please try again.")
                return
            
            # Reset form errors
            st.session_state.form_errors = {
                "name": False,
                "bio": False,
                "interests": False,
                "photo": False
            }
            
            # Validate fields
            if not name:
                st.session_state.form_errors["name"] = True
            if not bio:
                st.session_state.form_errors["bio"] = True
            if not interests:
                st.session_state.form_errors["interests"] = True
            if not photo:
                st.session_state.form_errors["photo"] = True
                
            # Check if any errors exist
            if any(st.session_state.form_errors.values()):
                st.error("Please fill in all required fields marked in red")
                st.rerun()
                
            try:
                # Read and verify photo (10MB limit)
                photo_data = photo.read()
                if len(photo_data) > 10 * 1024 * 1024:
                    st.error("Photo exceeds 10MB size limit")
                    return

                with get_db_connection() as conn:
                    # Check if profile exists again to prevent race condition
                    exists = conn.execute(
                        "SELECT 1 FROM profiles WHERE email=?",
                        (st.session_state.current_user,)
                    ).fetchone()
                    
                    if exists:
                        st.warning("Profile already exists. Redirecting to edit page...")
                        st.session_state.view = "edit_profile"
                        time.sleep(1)
                        st.rerun()
                    
                    conn.execute('''INSERT INTO profiles
                                        (email, name, age, gender, bio, interests, photo, timestamp, intention)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                 (st.session_state.current_user, 
                                  sanitize_input(name), 
                                  age, 
                                  sanitize_input(gender), 
                                  sanitize_input(bio),
                                  sanitize_input(", ".join(interests)), 
                                  photo_data, 
                                  datetime.now(), 
                                  sanitize_input(intention)))
                    conn.commit()

                st.success("Profile created successfully!")
                st.session_state.view = "discover"
                time.sleep(1)
                st.rerun()
            except sqlite3.IntegrityError:
                st.error("Profile already exists for this email. Redirecting to edit page...")
                st.session_state.view = "edit_profile"
                time.sleep(2)
                st.rerun()
            except Exception as e:
                st.error(f"Error creating profile: {str(e)}")

# Profile Editing
def edit_profile():
    with get_db_connection() as conn:
        profile = conn.execute(
            "SELECT * FROM profiles WHERE email=?",
            (st.session_state.current_user,)
        ).fetchone()

    if not profile:
        st.warning("No profile found. Redirecting to create profile...")
        st.session_state.view = "profile"
        time.sleep(1)
        st.rerun()

    st.title("Edit Your Profile")
    st.caption("Update your information")

    with st.form("edit_profile_form"):
        # CSRF protection
        st.session_state.csrf_token = binascii.hexlify(os.urandom(16)).decode()
        st.hidden_input("csrf_token", value=st.session_state.csrf_token)
        
        name = st.text_input("Full Name", value=profile["name"])
        age = st.slider("Age", 18, 30, value=profile["age"])
        gender = st.selectbox("Gender",
                              ["Male", "Female", "Non-binary", "Prefer not to say"],
                              index=["Male", "Female", "Non-binary", "Prefer not to say"].index(profile["gender"]))
        bio = st.text_area("About Me", value=profile["bio"])
        current_interests = profile["interests"].split(", ") if profile["interests"] else []
        interests = st.multiselect("Interests", [
            "Sports", "Music", "Gaming", "Academics",
            "Art", "Travel", "Food", "Movies", "Dancing"
        ], default=current_interests)

        # Show current photo if exists
        if profile["photo"]:
            try:
                st.image(Image.open(io.BytesIO(profile["photo"])), width=150, caption="Current Photo")
            except:
                st.image("default_profile.png", width=150, caption="Current Photo")

        photo = st.file_uploader("Update Profile Photo (max 10MB, leave empty to keep current)",
                                 type=["jpg", "png", "jpeg"],
                                 accept_multiple_files=False)

        # Intention field
        intentions = ["Relationship", "Friendship", "Hookups", "Not sure yet"]
        current_intention = profile["intention"] if "intention" in profile else "Not sure yet"
        intention = st.radio("What are you looking for?",
                             intentions,
                             index=intentions.index(current_intention))

        col1, col2 = st.columns(2)
        with col1:
            submit = st.form_submit_button("Update Profile")
        with col2:
            cancel = st.form_submit_button("Cancel")

        if cancel:
            st.session_state.view = "discover"
            st.rerun()

        if submit:
            # CSRF validation
            if not st.query_params.get("csrf_token") or st.query_params.get("csrf_token") != st.session_state.csrf_token:
                log_security_event("CSRF_FAILURE", f"Invalid CSRF token during profile update")
                st.error("Security error. Please try again.")
                return
                
            try:
                # Use new photo if provided, otherwise keep existing
                photo_data = profile["photo"]
                if photo:
                    if photo.size > 10 * 1024 * 1024:  # 10MB limit
                        st.error("Photo size must be less than 10MB")
                        return
                    else:
                        photo_data = photo.read()

                with get_db_connection() as conn:
                    conn.execute('''UPDATE profiles
                                    SET name=?,
                                        age=?,
                                        gender=?,
                                        bio=?,
                                        interests=?,
                                        photo=?,
                                        intention=?
                                    WHERE email = ?''',
                                 (sanitize_input(name), 
                                  age, 
                                  sanitize_input(gender), 
                                  sanitize_input(bio), 
                                  sanitize_input(", ".join(interests)),
                                  photo_data, 
                                  sanitize_input(intention), 
                                  st.session_state.current_user))
                    conn.commit()

                st.success("Profile updated successfully!")
                st.session_state.view = "discover"
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.error(f"Error updating profile: {str(e)}")

# Record like action
def record_like(from_email, to_email):
    with get_db_connection() as conn:
        conn.execute(
            '''INSERT INTO connections (id, from_email, to_email, status, timestamp)
               VALUES (?, ?, ?, ?, ?)''',
            (str(uuid4()), from_email, to_email, "liked", datetime.now())
        )
        conn.commit()

# Record connection request
def record_connection_request(from_email, to_email):
    with get_db_connection() as conn:
        conn.execute(
            '''INSERT INTO connections (id, from_email, to_email, status, timestamp)
               VALUES (?, ?, ?, ?, ?)''',
            (str(uuid4()), from_email, to_email, "requested", datetime.now())
        )
        conn.commit()

# Discover Profiles
def discover_profiles():
    st.title("Discover People 🥰😍")
    current_user = st.session_state.current_user
    
    # Use cached profiles if available and recent (within 5 minutes)
    if st.session_state.profiles_cache and st.session_state.cache_timestamp:
        if (datetime.now() - st.session_state.cache_timestamp).total_seconds() < 300:
            available_profiles = st.session_state.profiles_cache
        else:
            st.session_state.profiles_cache = None
            st.session_state.cache_timestamp = None
            available_profiles = get_profiles(current_user)
    else:
        available_profiles = get_profiles(current_user)
        st.session_state.profiles_cache = available_profiles
        st.session_state.cache_timestamp = datetime.now()

    if not available_profiles:
        st.info("No profiles to show. Try again later.")
        return

    # Get current profile to show
    st.session_state.current_index = st.session_state.get('current_index', 0)
    if st.session_state.current_index >= len(available_profiles):
        st.session_state.current_index = 0

    # Unpack profile data
    profile = available_profiles[st.session_state.current_index]
    email = profile["email"]
    name = profile["name"]
    age = profile["age"]
    gender = profile["gender"]
    bio = profile["bio"]
    interests = profile["interests"]
    photo = profile["photo"]
    intention = profile["intention"] if "intention" in profile else "Not sure yet"

    # Display the profile with swipeable interface
    with st.container():
        # Create swipeable card
        col1, col2 = st.columns([1, 3])
        with col1:
            st.write("")  # Spacer
            
        with col2:
            # Swipe instructions
            st.markdown("""
                <div style="text-align:center; margin-bottom:20px;">
                    <p>Swipe ← to pass, swipe → to like</p>
                    <p>Or use buttons below</p>
                </div>
            """, unsafe_allow_html=True)
            
            # Profile card
            with st.container():
                card = st.empty()
                with card.container():
                    # Display photo
                    if photo:
                        try:
                            st.image(Image.open(io.BytesIO(photo)), width=250, caption=f"{name}, {age}")
                        except:
                            st.image("default_profile.png", width=250, caption=f"{name}, {age}")
                    else:
                        st.image("default_profile.png", width=250, caption=f"{name}, {age}")
                    
                    # Profile info
                    st.caption(f"{gender} • Looking for: {intention}")
                    st.write(bio)
                    st.write(f"**Interests:** {interests}")
            
            # Swipe action indicator
            if st.session_state.swipe_action:
                if st.session_state.swipe_action == "like":
                    st.success(f"Liked {name}!")
                elif st.session_state.swipe_action == "pass":
                    st.info(f"Passed on {name}")
                st.session_state.swipe_action = None
            
            # Action buttons
            col_pass, col_connect, col_like = st.columns([1, 1, 1])
            with col_pass:
                if st.button("👎 Pass", key="pass", use_container_width=True):
                    st.session_state.current_index = (st.session_state.current_index + 1) % len(available_profiles)
                    st.rerun()
            with col_connect:
                if st.button("🤝 Connect", key="connect", type="primary", use_container_width=True):
                    record_connection_request(st.session_state.current_user, email)
                    st.success(f"Connection request sent to {name}!")
                    st.session_state.current_index = (st.session_state.current_index + 1) % len(available_profiles)
                    st.rerun()
            with col_like:
                if st.button("❤️ Like", key="like", use_container_width=True):
                    record_like(st.session_state.current_user, email)
                    st.success(f"Liked {name}!")
                    st.session_state.current_index = (st.session_state.current_index + 1) % len(available_profiles)
                    st.rerun()

# Get profiles with optimized query
def get_profiles(current_user):
    with get_db_connection() as conn:
        try:
            # Pre-fetch blocked users
            blocked_users = conn.execute(
                "SELECT blocked_email FROM blocked_users WHERE blocker_email=?",
                (current_user,)
            ).fetchall()
            blocked_emails = [row["blocked_email"] for row in blocked_users]

            # Get profiles excluding current user and blocked users
            profiles = []
            for row in conn.execute(
                    '''SELECT email, name, age, gender, bio, interests, photo, intention
                       FROM profiles
                       WHERE email != ?''',
                    (current_user,)
            ).fetchall():
                if row["email"] not in blocked_emails:
                    profiles.append(dict(row))
                    
            return profiles
        except sqlite3.Error as e:
            st.error(f"Database error: {e}")
            return []

# Connections Management
def view_connections():
    current_user = st.session_state.current_user

    st.title("Your Connections")

    # Pending Requests
    st.subheader("Pending Requests")
    with get_db_connection() as conn:
        pending_requests = conn.execute(
            '''SELECT c.id, c.from_email, c.timestamp, p.name, p.photo, p.bio
               FROM connections c
                        JOIN profiles p ON c.from_email = p.email
               WHERE c.to_email = ?
                 AND c.status = 'requested'
               ORDER BY c.timestamp DESC''',
            (current_user,)
        ).fetchall()

    if not pending_requests:
        st.info("No pending connection requests")
    else:
        for req in pending_requests:
            req_id = req["id"]
            from_email = req["from_email"]
            timestamp = req["timestamp"]
            name = req["name"]
            photo = req["photo"]
            bio = req["bio"]

            col1, col2 = st.columns([1, 4])
            with col1:
                if photo:
                    try:
                        st.image(Image.open(io.BytesIO(photo)), width=80)
                    except:
                        st.image("default_profile.png", width=80)
                else:
                    st.image("default_profile.png", width=80)

            with col2:
                st.write(f"**{name}** wants to connect with you")
                
                # Convert string to datetime object if needed
                if isinstance(timestamp, str):
                    try:
                        timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f") if '.' in timestamp else datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        pass

                if isinstance(timestamp, datetime):
                    st.caption(f"Requested on {timestamp.strftime('%b %d, %Y at %H:%M')}")
                else:
                    st.caption(f"Requested on {timestamp}")
                    
                st.caption(f"{bio[:100]}..." if bio else "")

                col_accept, col_reject, _ = st.columns([1, 1, 2])
                with col_accept:
                    if st.button("Accept", key=f"accept_{req_id}"):
                        with get_db_connection() as conn:
                            conn.execute(
                                "UPDATE connections SET status='connected' WHERE id=?",
                                (req_id,)
                            )
                            conn.commit()
                        # Add notification
                        notification = {
                            "type": "connection_accepted",
                            "from_user": current_user,
                            "to_user": from_email,
                            "timestamp": datetime.now()
                        }
                        st.session_state.notifications.append(notification)
                        st.rerun()
                with col_reject:
                    if st.button("Reject", key=f"reject_{req_id}"):
                        with get_db_connection() as conn:
                            conn.execute(
                                "DELETE FROM connections WHERE id=?",
                                (req_id,)
                            )
                            conn.commit()
                        st.rerun()
            st.divider()

    # Your Connections
    st.subheader("Your Connections")
    with get_db_connection() as conn:
        connections = conn.execute(
            '''SELECT c.id,
                      CASE WHEN c.from_email = ? THEN c.to_email ELSE c.from_email END as other_email,
                      c.timestamp,
                      p.name,
                      p.photo
               FROM connections c
                        JOIN profiles p ON (CASE WHEN c.from_email = ? THEN c.to_email ELSE c.from_email END) = p.email
               WHERE (c.from_email = ? OR c.to_email = ?)
                 AND c.status = 'connected'
               ORDER BY c.timestamp DESC''',
            (current_user, current_user, current_user, current_user)
        ).fetchall()

    if not connections:
        st.info("You don't have any connections yet")
    else:
        for conn_item in connections:
            conn_id = conn_item["id"]
            other_email = conn_item["other_email"]
            timestamp = conn_item["timestamp"]
            name = conn_item["name"]
            photo = conn_item["photo"]

            # Check for unread messages
            with get_db_connection() as conn:
                unread_count = conn.execute(
                    '''SELECT COUNT(*)
                       FROM messages
                       WHERE chat_id IN (SELECT MIN(id)
                                         FROM messages
                                         WHERE (sender = ? AND receiver = ?)
                                            OR (sender = ? AND receiver = ?))
                         AND receiver = ?
                         AND read =0''',
                    (current_user, other_email, other_email, current_user, current_user)
                ).fetchone()[0]

            col1, col2 = st.columns([1, 4])
            with col1:
                if photo:
                    try:
                        st.image(Image.open(io.BytesIO(photo)), width=80)
                    except:
                        st.image("default_profile.png", width=80)
                else:
                    st.image("default_profile.png", width=80)

            with col2:
                st.write(f"**{name}**")
                # FIXED TIMESTAMP HANDLING
                if isinstance(timestamp, str):
                    try:
                        timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f") if '.' in timestamp else datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        pass
                if isinstance(timestamp, datetime):
                    st.caption(f"Connected since {timestamp.strftime('%b %d, %Y')}")
                else:
                    st.caption(f"Connected since {timestamp}")
                    
                if unread_count > 0:
                    st.caption(f"🔴 {unread_count} unread message{'s' if unread_count > 1 else ''}")

                if st.button("Chat", key=f"chat_{conn_id}"):
                    st.session_state.current_chat = other_email
                    st.session_state.view = "chat"
                    st.rerun()

                # Video call button
                if st.button("📞 Video Call", key=f"call_{conn_id}"):
                    st.session_state.caller = st.session_state.current_user
                    st.session_state.callee = other_email
                    st.session_state.call_state = "ringing"
                    st.session_state.view = "video_call"
                    st.rerun()

                # Report button for connections
                if st.button("⚠️ Report", key=f"report_{conn_id}"):
                    st.session_state.reporting_user = other_email
                    st.session_state.reporting_name = name
                    st.session_state.view = "report_user"
                    st.rerun()

                # Block button for connections
                if st.button("🚫 Block", key=f"block_{conn_id}"):
                    with get_db_connection() as conn:
                        conn.execute(
                            '''INSERT OR IGNORE INTO blocked_users 
                               (blocker_email, blocked_email, timestamp)
                               VALUES (?, ?, ?)''',
                            (current_user, other_email, datetime.now())
                        )
                        conn.execute(
                            "DELETE FROM connections WHERE id=?",
                            (conn_id,)
                        )
                        conn.commit()
                    st.success(f"You have blocked {name}")
                    st.rerun()
            st.divider()

# Chat Interface
def chat_interface():
    current_user = st.session_state.current_user
    other_user = st.session_state.current_chat

    with get_db_connection() as conn:
        other_profile = conn.execute(
            "SELECT name, photo FROM profiles WHERE email=?",
            (other_user,)
        ).fetchone()

    if not other_profile:
        st.error("Profile not found")
        st.session_state.view = "connections"
        st.rerun()

    other_name = other_profile["name"]
    other_photo = other_profile["photo"]

    # Chat header
    col1, col2, col3 = st.columns([1, 8, 1])
    with col1:
        if st.button("← Back"):
            st.session_state.view = "connections"
            st.rerun()
    with col2:
        st.title(f"Chat with {other_name}")
    with col3:
        if st.button("📞 Call"):
            st.session_state.caller = st.session_state.current_user
            st.session_state.callee = other_user
            st.session_state.call_state = "ringing"
            st.session_state.view = "video_call"
            st.rerun()

    # Generate chat ID
    chat_id = "_".join(sorted([current_user, other_user]))

    # Get messages
    with get_db_connection() as conn:
        messages = conn.execute(
            '''SELECT id, sender, receiver, message, time, read
               FROM messages
               WHERE chat_id=?
               ORDER BY time''',
            (chat_id,)
        ).fetchall()

        # Mark received messages as read
        conn.execute(
            '''UPDATE messages
               SET read=1
               WHERE receiver = ?
                 AND chat_id = ?
                 AND read =0''',
            (current_user, chat_id)
        )
        conn.commit()

    # Chat container styling
    st.markdown(
        """
        <style>
        .chat-container {
            height: 400px;
            overflow-y: auto;
            padding: 10px;
            background-color: #1a1d24;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .sender {
            background-color: #4a4e69;
            padding: 10px;
            border-radius: 15px;
            margin-bottom: 10px;
            margin-left: 30%;
            text-align: right;
        }
        .receiver {
            background-color: #2d3039;
            padding: 10px;
            border-radius: 15px;
            margin-bottom: 10px;
            margin-right: 30%;
        }
        .timestamp {
            font-size: 0.7em;
            color: #aaa;
        }
        </style>
        """, 
        unsafe_allow_html=True
    )
    
    # Display chat messages
    with st.container():
        st.markdown('<div class="chat-container">', unsafe_allow_html=True)
        
        for msg in messages:
            msg_id = msg["id"]
            sender = msg["sender"]
            receiver = msg["receiver"]
            message = msg["message"]
            msg_time = msg["time"]
            read = msg["read"]
            
            # Convert timestamp if needed
            if isinstance(msg_time, str):
                try:
                    if '.' in msg_time:
                        msg_time = datetime.strptime(msg_time, "%Y-%m-%d %H:%M:%S.%f")
                    else:
                        msg_time = datetime.strptime(msg_time, "%Y-%m-%d %H:%M:%S")
                except:
                    msg_time = datetime.now()
            
            # Format the time as HH:MM
            timestamp = msg_time.strftime("%H:%M")
            
            if sender == current_user:
                st.markdown(
                    f'<div class="sender">{message}<div class="timestamp">{timestamp}</div></div>', 
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    f'<div class="receiver">{message}<div class="timestamp">{timestamp}</div></div>', 
                    unsafe_allow_html=True
                )
        
        st.markdown('</div>', unsafe_allow_html=True)

    # Message input
    if prompt := st.chat_input("Type a message..."):
        # Add message to database
        with get_db_connection() as conn:
            conn.execute(
                '''INSERT INTO messages
                       (id, chat_id, sender, receiver, message, time, read)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (str(uuid4()), chat_id, current_user, other_user,
                 prompt, datetime.now(), 0)
            )
            conn.commit()
        st.rerun()

# Video Call Interface
def video_call_interface():
    st.title("Video Call 📞")
    
    if st.session_state.call_state == "ringing":
        if st.session_state.current_user == st.session_state.callee:
            st.info(f"{st.session_state.caller} is calling you...")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Answer", type="primary"):
                    st.session_state.call_state = "active"
                    st.rerun()
            with col2:
                if st.button("Decline"):
                    st.session_state.call_state = "ended"
                    st.session_state.view = "connections"
                    st.rerun()
        else:
            st.info(f"Calling {st.session_state.callee}...")
            if st.button("Cancel Call"):
                st.session_state.call_state = "ended"
                st.session_state.view = "connections"
                st.rerun()
    
    elif st.session_state.call_state == "active":
        st.info("Call in progress...")
        
        # Video call component
        webrtc_ctx = webrtc_streamer(
            key="video-chat",
            mode=WebRtcMode.SENDRECV,
            rtc_configuration=RTC_CONFIGURATION,
            media_stream_constraints={
                "video": True,
                "audio": True
            },
            video_frame_callback=None,
            async_processing=True,
        )
        
        # End call button
        if st.button("End Call", type="primary"):
            st.session_state.call_state = "ended"
            if "current_chat" in st.session_state:
                st.session_state.view = "chat"
            else:
                st.session_state.view = "connections"
            st.rerun()
    
    elif st.session_state.call_state == "ended":
        st.info("Call ended")
        if "current_chat" in st.session_state:
            st.session_state.view = "chat"
        else:
            st.session_state.view = "connections"
        st.rerun()

# Report User Interface
def report_user():
    st.title("Report User")
    st.subheader(f"Reporting: {st.session_state.reporting_name}")

    with st.form("report_form"):
        reason = st.selectbox("Reason for reporting", [
            "Inappropriate content",
            "Suspected fake profile",
            "Harassment or bullying",
            "Spam or solicitation",
            "Other"
        ])

        details = st.text_area("Additional details (optional)", height=150)

        submitted = st.form_submit_button("Submit Report")
        cancel = st.form_submit_button("Cancel")

        if cancel:
            st.session_state.view = "discover" if "current_chat" not in st.session_state else "connections"
            st.rerun()

        if submitted:
            report_id = str(uuid4())
            with get_db_connection() as conn:
                conn.execute('''INSERT INTO reports
                                    (id, reporter_email, reported_email, reason, details, timestamp)
                                VALUES (?, ?, ?, ?, ?, ?)''',
                             (report_id,
                              st.session_state.current_user,
                              st.session_state.reporting_user,
                              reason,
                              details,
                              datetime.now()))
                conn.commit()

            # Send email notification to admin
            send_report_notification(
                st.session_state.current_user,
                st.session_state.reporting_user,
                reason,
                details
            )
            
            st.success("Thank you for your report. Our team will review it shortly.")
            time.sleep(2)
            st.session_state.view = "discover" if "current_chat" not in st.session_state else "connections"
            st.rerun()

# Account Deletion
def delete_account():
    st.title("Delete Account")
    st.warning("This action is permanent and cannot be undone!")

    with st.form("delete_account_form"):
        password = st.text_input("Confirm your password", type="password")
        confirm = st.checkbox("I understand all my data will be permanently deleted")

        if st.form_submit_button("Permanently Delete Account"):
            if not password or not confirm:
                st.error("Please enter your password and confirm deletion")
            else:
                # Verify password
                with get_db_connection() as conn:
                    c = conn.cursor()
                    c.execute("SELECT password, salt FROM users WHERE email=?",
                              (st.session_state.current_user,))
                    result = c.fetchone()

                if result:
                    hashed_pw = result["password"]
                    salt = result["salt"]
                    peppered_password = password + PEPPER_SECRET
                    if bcrypt.hashpw(peppered_password.encode(), salt) == hashed_pw:
                        # Delete all user data
                        with get_db_connection() as conn:
                            conn.execute("DELETE FROM users WHERE email=?",
                                         (st.session_state.current_user,))
                            conn.execute("DELETE FROM profiles WHERE email=?",
                                         (st.session_state.current_user,))
                            conn.execute("DELETE FROM connections WHERE from_email=? OR to_email=?",
                                         (st.session_state.current_user, st.session_state.current_user))
                            conn.execute("DELETE FROM messages WHERE sender=? OR receiver=?",
                                         (st.session_state.current_user, st.session_state.current_user))
                            conn.commit()

                        st.success("Account deleted successfully")
                        st.session_state.clear()
                        st.query_params.clear()
                        st.session_state.view = "auth"
                        time.sleep(2)
                        st.rerun()
                    else:
                        st.error("Incorrect password")
                else:
                    st.error("User not found")

# Notification system
def show_notifications():
    if not st.session_state.notifications:
        st.info("No new notifications")
        return

    st.title("Notifications")
    for notification in st.session_state.notifications:
        if notification["type"] == "connection_accepted":
            with get_db_connection() as conn:
                name = conn.execute(
                    "SELECT name FROM profiles WHERE email=?",
                    (notification["from_user"],)
                ).fetchone()["name"]

            st.write(f"✅ {name} accepted your connection request")
            st.caption(notification["timestamp"].strftime("%b %d, %Y at %H:%M"))
            st.divider()

# Admin Panel
def admin_panel():
    if "current_user" not in st.session_state:
        st.error("You must be logged in")
        return
        
    # Check if user is admin
    with get_db_connection() as conn:
        is_admin = conn.execute(
            "SELECT 1 FROM admins WHERE email=?", 
            (st.session_state.current_user,)
        ).fetchone()
    
    if not is_admin:
        st.error("Admin access only")
        return
        
    st.title("Admin Dashboard")
    
    # User management
    st.subheader("User Management")
    with get_db_connection() as conn:
        users = conn.execute(
            "SELECT email, verified, banned FROM users"
        ).fetchall()
    
    if not users:
        st.info("No users found")
    else:
        for user in users:
            email = user["email"]
            verified = user["verified"]
            banned = user["banned"]
            col1, col2, col3 = st.columns([3, 1, 1])
            with col1:
                st.write(f"**{email}**")
                st.caption(f"Verified: {'Yes' if verified else 'No'} | Banned: {'Yes' if banned else 'No'}")
            
            with col2:
                if banned:
                    if st.button("Unban", key=f"unban_{email}"):
                        with get_db_connection() as conn:
                            conn.execute(
                                "UPDATE users SET banned=0 WHERE email=?",
                                (email,)
                            )
                            conn.commit()
                        st.rerun()
                else:
                    if st.button("Ban", key=f"ban_{email}"):
                        with st.expander("Confirm Ban", expanded=True):
                            st.warning(f"Are you sure you want to ban {email}?")
                            if st.text_input("Enter 'CONFIRM BAN' to proceed") == "CONFIRM BAN":
                                with get_db_connection() as conn:
                                    conn.execute(
                                        "UPDATE users SET banned=1 WHERE email=?",
                                        (email,)
                                    )
                                    conn.commit()
                                log_security_event("USER_BANNED", f"Banned user {email}")
                                st.rerun()
                        
            with col3:
                if st.button("Delete", key=f"delete_{email}", type="secondary"):
                    with st.expander("Confirm Delete", expanded=True):
                        st.warning(f"Are you sure you want to delete {email}?")
                        if st.text_input("Enter 'CONFIRM DELETE' to proceed") == "CONFIRM DELETE":
                            with get_db_connection() as conn:
                                conn.execute("DELETE FROM users WHERE email=?", (email,))
                                conn.execute("DELETE FROM profiles WHERE email=?", (email,))
                                conn.commit()
                            log_security_event("USER_DELETED", f"Deleted user {email}")
                            st.rerun()
    
    # Report management
    st.subheader("Report Management")
    with get_db_connection() as conn:
        reports = conn.execute(
            """SELECT id, reporter_email, reported_email, reason, details, timestamp, status
            FROM reports
            ORDER BY timestamp DESC"""
        ).fetchall()
    
    if not reports:
        st.info("No reports found")
    else:
        for report in reports:
            r_id = report["id"]
            reporter = report["reporter_email"]
            reported = report["reported_email"]
            reason = report["reason"]
            details = report["details"]
            timestamp = report["timestamp"]
            status = report["status"]
            with st.expander(f"Report #{r_id[:8]} - {status}"):
                st.write(f"**Reporter:** {reporter}")
                st.write(f"**Reported:** {reported}")
                st.write(f"**Reason:** {reason}")
                st.write(f"**Details:** {details}")
                st.caption(f"Reported at: {timestamp}")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Mark Resolved", key=f"resolve_{r_id}"):
                        with get_db_connection() as conn:
                            conn.execute(
                                "UPDATE reports SET status='resolved' WHERE id=?",
                                (r_id,)
                            )
                            conn.commit()
                        st.rerun()
                with col2:
                    if st.button("Delete Report", key=f"delrep_{r_id}"):
                        with get_db_connection() as conn:
                            conn.execute(
                                "DELETE FROM reports WHERE id=?",
                                (r_id,)
                            )
                            conn.commit()
                        st.rerun()

# Security Dashboard
def security_dashboard():
    if "current_user" not in st.session_state:
        st.error("You must be logged in")
        return
        
    # Check if user is admin
    with get_db_connection() as conn:
        is_admin = conn.execute(
            "SELECT 1 FROM admins WHERE email=?", 
            (st.session_state.current_user,)
        ).fetchone()
    
    if not is_admin:
        st.error("Admin access only")
        return
        
    st.title("Security Dashboard")
    
    # Show recent security events
    st.subheader("Recent Security Events")
    try:
        with open("security.log", "r") as f:
            lines = f.readlines()[-50:]  # Last 50 entries
            for line in lines:
                try:
                    event = json.loads(line)
                    with st.expander(f"{event['event']} - {event['timestamp']}"):
                        st.json(event)
                except:
                    st.text(line)
    except FileNotFoundError:
        st.warning("No security log found")
    
    # System metrics
    st.subheader("System Metrics")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        with get_db_connection() as conn:
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        st.metric("Total Users", user_count)
    
    with col2:
        with get_db_connection() as conn:
            report_count = conn.execute("SELECT COUNT(*) FROM reports WHERE status='pending'").fetchone()[0]
        st.metric("Pending Reports", report_count)
    
    with col3:
        with get_db_connection() as conn:
            banned_count = conn.execute("SELECT COUNT(*) FROM users WHERE banned=1").fetchone()[0]
        st.metric("Banned Users", banned_count)

# Main App
def main():
    # Set session lifetime to 1 day (prevents logout when screen off)
    st.session_state.setdefault('server.maxSessionAge', 86400)

    st.set_page_config(
        page_title="Campus Connect",
        page_icon="❤️",
        layout="wide",
        initial_sidebar_state="collapsed"
    )

    # Apply dark theme
    st.markdown("""
    <style>
    [data-testid="stAppViewContainer"] {
        background-color: #0e1117;
        color: #f0f2f6;
    }
    [data-testid="stHeader"] {
        background-color: #1a1d24;
    }
    [data-testid="stToolbar"] {
        right: 2rem;
    }
    [data-testid="stForm"] {
        background: #1a1d24;
        border-radius: 15px;
        padding: 25px;
        border: 1px solid #2d3039;
    }
    .stButton>button {
        border-radius: 20px;
        padding: 10px 24px;
        background-color: #4a4e69;
        color: white;
        border: none;
    }
    .stButton>button:hover {
        background-color: #3a3e59;
    }
    .st-emotion-cache-1v0mbdj {
        border-radius: 15px;
        border: 1px solid #2d3039;
    }
    .stChatInput {
        background-color: #1a1d24;
    }
    .stChatMessage {
        padding: 12px;
        border-radius: 15px;
        margin: 10px 0;
    }
    .stChatMessage[data-testid="stChatMessage-user"] {
        background-color: #4a4e69;
    }
    .stChatMessage[data-testid="stChatMessage-assistant"] {
        background-color: #2d3039;
    }
    .notification-badge {
        background-color: #ff4b4b;
        color: white;
        border-radius: 50%;
        padding: 2px 6px;
        font-size: 0.8em;
        margin-left: 5px;
    }
    /* Form error styling */
    .stTextInput>div>div>input:focus:not(:focus-visible) {
        box-shadow: 0 0 0 0.2rem rgba(220, 53, 69, 0.25);
        border-color: #dc3545;
    }
    .stTextInput>div>div>input {
        border-color: #dc3545 !important;
    }
    </style>
    """, unsafe_allow_html=True)

    init_database()
    init_session_state()
    
    # Session validation
    if st.session_state.get("session_token"):
        valid_email = validate_session(st.session_state.session_token)
        if not valid_email:
            st.session_state.clear()
            st.query_params.clear()
            st.error("Session expired. Please log in again.")
            st.stop()
        elif valid_email != st.session_state.current_user:
            log_security_event("SESSION_HIJACK", 
                f"Token mismatch: {valid_email} vs {st.session_state.current_user}")
            st.session_state.clear()
            st.query_params.clear()
            st.error("Security violation detected. Please log in again.")
            st.stop()
        else:
            # Refresh session token if about to expire
            token_data = json.loads(st.session_state.session_token.split("|")[0])
            expires = datetime.fromisoformat(token_data["expires"])
            if (expires - datetime.now()) < timedelta(minutes=10):
                new_token = create_session(valid_email)
                st.session_state.session_token = new_token
                st.query_params["session_token"] = new_token

    # Navigation sidebar
    if st.session_state.current_user:
        with st.sidebar:
            st.header("Campus Connect")
            st.divider()

            # Profile quick view
            with get_db_connection() as conn:
                profile = conn.execute(
                    "SELECT name, photo FROM profiles WHERE email=?",
                    (st.session_state.current_user,)
                ).fetchone()

            if profile:
                name = profile["name"]
                photo = profile["photo"]
                if photo:
                    try:
                        st.image(Image.open(io.BytesIO(photo)), width=80)
                    except:
                        st.image("default_profile.png", width=80)
                st.subheader(name)

            # Navigation
            if st.button("Discover People"):
                st.session_state.view = "discover"
                st.rerun()

            if st.button("My Connections"):
                st.session_state.view = "connections"
                st.rerun()

            # Notification badge
            unread_notifications = len(st.session_state.notifications)
            if unread_notifications > 0:
                if st.button(f"Notifications 🔴 {unread_notifications}"):
                    st.session_state.view = "notifications"
                    st.rerun()
            else:
                if st.button("Notifications"):
                    st.session_state.view = "notifications"
                    st.rerun()

            if st.button("Edit Profile"):
                st.session_state.view = "edit_profile"
                st.rerun()
                
            # Check if user is admin
            with get_db_connection() as conn:
                is_admin = conn.execute(
                    "SELECT 1 FROM admins WHERE email=?", 
                    (st.session_state.current_user,)
                ).fetchone()
            
            if is_admin:
                if st.button("Admin Panel"):
                    st.session_state.view = "admin"
                    st.rerun()
                if st.button("Security Dashboard"):
                    st.session_state.view = "security_dashboard"
                    st.rerun()

            if st.button("Delete Account", type="primary"):
                st.session_state.view = "delete_account"
                st.rerun()

            st.divider()
            if st.button("Logout"):
                st.session_state.clear()
                st.query_params.clear()
                st.session_state.view = "auth"
                st.rerun()

    # Main view routing
    if st.session_state.view == "auth":
        auth_system()
    elif st.session_state.view == "forgot_password":
        forgot_password()
    elif st.session_state.view == "profile":
        create_profile()
    elif st.session_state.view == "edit_profile":
        edit_profile()
    elif st.session_state.view == "discover":
        discover_profiles()
    elif st.session_state.view == "connections":
        view_connections()
    elif st.session_state.view == "chat":
        chat_interface()
    elif st.session_state.view == "notifications":
        show_notifications()
    elif st.session_state.view == "report_user":
        report_user()
    elif st.session_state.view == "delete_account":
        delete_account()
    elif st.session_state.view == "video_call":
        video_call_interface()
    elif st.session_state.view == "admin":
        admin_panel()
    elif st.session_state.view == "security_dashboard":
        security_dashboard()
    elif st.session_state.reset_otp_verification:
        auth_system()

    # Add sample data if database is empty
    with get_db_connection() as conn:
        # Insert sample data if empty
        if not conn.execute("SELECT 1 FROM profiles").fetchone():
            # Sample profiles
            sample_profiles = [
                ("123user1@example.com", "Amanda K", 21, "Female",
                 "Psychology major who loves hiking and indie music",
                 "Music, Travel, Art", b"", datetime.now(), "Relationship"),
                ("234user2@example.com", "James L", 22, "Male",
                 "Computer Science student and football enthusiast",
                 "Sports, Gaming, Movies", b"", datetime.now(), "Friendship"),
                ("345user3@example.com", "Priya M", 20, "Female",
                 "Art student passionate about street photography",
                 "Art, Photography, Coffee", b"", datetime.now(), "Not sure yet"),
                ("456user4@example.com", "Thomas O", 23, "Male",
                 "Engineering student who plays guitar and loves jazz",
                 "Music, Technology, Science", b"", datetime.now(), "Hookups"),
                ("567user5@example.com", "Naledi P", 19, "Female",
                 "Environmental science major and vegan foodie",
                 "Nature, Cooking, Sustainability", b"", datetime.now(), "Relationship")
            ]

            # Create sample users
            for profile in sample_profiles:
                email = profile[0]
                salt = bcrypt.gensalt()
                password = "Password123"
                peppered_password = password + PEPPER_SECRET
                hashed_pw = bcrypt.hashpw(peppered_password.encode(), salt)

                conn.execute("INSERT OR IGNORE INTO users (email, password, salt, verified) VALUES (?, ?, ?, ?)",
                             (email, hashed_pw, salt, 1))
                # Only insert profile if it doesn't exist
                exists = conn.execute("SELECT 1 FROM profiles WHERE email=?", (email,)).fetchone()
                if not exists:
                    conn.execute(
                        "INSERT INTO profiles (email, name, age, gender, bio, interests, photo, timestamp, intention) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        profile)

            conn.commit()

if __name__ == "__main__":
    main()
