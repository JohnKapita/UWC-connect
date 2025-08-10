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

# Load environment variables for email credentials
load_dotenv()

# Initialize database with proper schema
def init_database():
    conn = sqlite3.connect("campus_connect.db")
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
                     last_attempt DATETIME
                 )''')

    # Create profiles table with new columns
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

    # Create password resets table (MODIFIED for OTP)
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

    # Add indexes for performance
    c.execute('''CREATE INDEX IF NOT EXISTS idx_connections_from ON connections(from_email)''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_connections_to ON connections(to_email)''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id)''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_profiles_timestamp ON profiles(timestamp)''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_users_verified ON users(verified)''')

    # Database upgrade: Check and add missing columns
    try:
        # Check profiles table
        c.execute("PRAGMA table_info(profiles)")
        profile_columns = [col[1] for col in c.fetchall()]
            
        # Check password_resets table
        c.execute("PRAGMA table_info(password_resets)")
        reset_columns = [col[1] for col in c.fetchall()]
        if 'otp' not in reset_columns:
            c.execute("ALTER TABLE password_resets ADD COLUMN otp TEXT")
        if 'expiry' not in reset_columns:
            c.execute("ALTER TABLE password_resets ADD COLUMN expiry DATETIME")
            
    except Exception as e:
        st.error(f"Database upgrade error: {str(e)}")

    conn.commit()
    conn.close()


# Initialize session state
def init_session_state():
    if "current_user" not in st.session_state:
        # Try to get from cookies
        if st.experimental_get_query_params().get("logged_in"):
            st.session_state.current_user = st.experimental_get_query_params().get("logged_in")[0]
        else:
            st.session_state.current_user = None
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
    # NEW: State for password reset OTP flow
    if "reset_otp_verification" not in st.session_state:
        st.session_state.reset_otp_verification = False
    if "reset_otp_attempts" not in st.session_state:
        st.session_state.reset_otp_attempts = 0
    if "temp_reset_email" not in st.session_state:  # Added missing state variable
        st.session_state.temp_reset_email = None
    # Form validation state
    if "form_errors" not in st.session_state:
        st.session_state.form_errors = {}


# Email validation with first 3 numbers requirement
def is_valid_student_email(email):
    if not email:
        return False
    # Check if first 3 characters are digits
    if len(email) < 3 or not email[:3].isdigit():
        return False
    # Basic email format validation
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


# Generate random 6-digit OTP
def generate_otp():
    return str(random.randint(100000, 999999))


# Send OTP email
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


# NEW: Send password reset OTP email
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


# Verify OTP against database
def verify_otp_in_db(email, user_otp):
    conn = sqlite3.connect("campus_connect.db")
    c = conn.cursor()
    c.execute("SELECT otp, otp_expiry FROM users WHERE email=?", (email,))
    result = c.fetchone()
    conn.close()

    if not result or not result[0]:
        return False

    stored_otp, expiry_str = result
    expiry = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S.%f") if '.' in expiry_str else datetime.strptime(
        expiry_str, "%Y-%m-%d %H:%M:%S")

    return stored_otp == user_otp and datetime.now() < expiry


# NEW: Verify reset OTP
def verify_reset_otp(email, user_otp):
    conn = sqlite3.connect("campus_connect.db")
    c = conn.cursor()
    c.execute("SELECT otp, expiry FROM password_resets WHERE email=?", (email,))
    result = c.fetchone()
    conn.close()

    if not result or not result[0]:
        return False

    stored_otp, expiry_str = result
    expiry = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S.%f") if '.' in expiry_str else datetime.strptime(
        expiry_str, "%Y-%m-%d %H:%M:%S")

    return stored_otp == user_otp and datetime.now() < expiry


# Authentication system
def auth_system():
    st.title("Campus Connect 🔐😍❤️")
    st.subheader("Student social connection platform")
    
    # Add compliance notice
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
                    # Complete registration
                    salt = bcrypt.gensalt()
                    hashed_pw = bcrypt.hashpw(st.session_state.temp_password.encode(), salt)

                    conn = sqlite3.connect("campus_connect.db")
                    conn.execute(
                        "UPDATE users SET password=?, salt=?, verified=1, otp=NULL, otp_expiry=NULL WHERE email=?",
                        (hashed_pw, salt, email)
                    )
                    conn.commit()
                    conn.close()

                    st.session_state.current_user = email
                    st.experimental_set_query_params(logged_in=email)
                    st.session_state.pending_verification = False
                    st.session_state.view = "profile"
                    st.success("Account verified! Please create your profile.")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.session_state.otp_attempts += 1
                    if st.session_state.otp_attempts >= 3:
                        st.error("Too many failed attempts. Please register again.")
                        # Clean up failed registration
                        conn = sqlite3.connect("campus_connect.db")
                        conn.execute("DELETE FROM users WHERE email=?", (email,))
                        conn.commit()
                        conn.close()
                        st.session_state.pending_verification = False
                        time.sleep(2)
                        st.rerun()
                    else:
                        st.error("Invalid OTP. Please try again.")

        with col2:
            if st.button("Resend OTP"):
                new_otp = generate_otp()
                expiry = datetime.now() + timedelta(minutes=10)

                conn = sqlite3.connect("campus_connect.db")
                conn.execute(
                    "UPDATE users SET otp=?, otp_expiry=? WHERE email=?",
                    (new_otp, expiry, email)
                )
                conn.commit()
                conn.close()

                if send_otp_email(email, new_otp):
                    st.success("New OTP sent!")
                else:
                    st.error("Failed to resend OTP")

        with col3:
            if st.button("Cancel"):
                conn = sqlite3.connect("campus_connect.db")
                conn.execute("DELETE FROM users WHERE email=?", (email,))
                conn.commit()
                conn.close()

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
                    # Update password in database
                    salt = bcrypt.gensalt()
                    hashed_pw = bcrypt.hashpw(new_password.encode(), salt)

                    conn = sqlite3.connect("campus_connect.db")
                    conn.execute(
                        "UPDATE users SET password=?, salt=? WHERE email=?",
                        (hashed_pw, salt, st.session_state.temp_email)
                    )
                    conn.execute(
                        "DELETE FROM password_resets WHERE email=?",
                        (st.session_state.temp_email,)
                    )
                    conn.commit()
                    conn.close()

                    st.success("Password updated successfully! Please login with your new password.")
                    st.session_state.resetting_password = False
                    time.sleep(2)
                    st.rerun()

        if st.button("Cancel"):
            st.session_state.resetting_password = False
            st.rerun()

        return

    # NEW: Reset OTP Verification Screen
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
                        # Clean up reset request
                        conn = sqlite3.connect("campus_connect.db")
                        conn.execute("DELETE FROM password_resets WHERE email=?", (email,))
                        conn.commit()
                        conn.close()
                        st.session_state.reset_otp_verification = False
                        time.sleep(2)
                        st.rerun()
                    else:
                        st.error("Invalid OTP. Please try again.")

        with col2:
            if st.button("Resend OTP", key="resend_reset_otp"):
                new_otp = generate_otp()
                expiry = datetime.now() + timedelta(minutes=10)

                conn = sqlite3.connect("campus_connect.db")
                conn.execute(
                    "INSERT OR REPLACE INTO password_resets (email, otp, expiry) VALUES (?, ?, ?)",
                    (email, new_otp, expiry)
                )
                conn.commit()
                conn.close()

                if send_reset_otp_email(email, new_otp):
                    st.success("New OTP sent!")
                else:
                    st.error("Failed to resend OTP")

        with col3:
            if st.button("Cancel", key="cancel_reset_otp"):
                conn = sqlite3.connect("campus_connect.db")
                conn.execute("DELETE FROM password_resets WHERE email=?", (email,))
                conn.commit()
                conn.close()
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
            email = st.text_input("Student Email (must start with 3 numbers)", key="login_email")
            password = st.text_input("Password", type="password")
            remember_me = st.checkbox("Remember me")

            if st.form_submit_button("Login"):
                if not is_valid_student_email(email):
                    st.error("Invalid student email format. Must start with 3 numbers")
                else:
                    conn = sqlite3.connect("campus_connect.db")
                    c = conn.cursor()
                    c.execute("SELECT password, salt, verified FROM users WHERE email=?", (email,))
                    result = c.fetchone()
                    conn.close()

                    if result:
                        hashed_pw, salt, verified = result

                        # Handle missing salt
                        if salt is None:
                            st.error("Account setup incomplete. Please reset your password.")
                            st.stop()

                        try:
                            # Verify password
                            if bcrypt.hashpw(password.encode(), salt) == hashed_pw:
                                if not verified:
                                    st.error("Account not verified. Please check your email.")
                                else:
                                    st.session_state.current_user = email
                                    st.experimental_set_query_params(logged_in=email)
                                    # Check if profile exists
                                    conn = sqlite3.connect("campus_connect.db")
                                    profile_exists = conn.execute(
                                        "SELECT 1 FROM profiles WHERE email=?",
                                        (email,)
                                    ).fetchone()
                                    conn.close()

                                    st.session_state.view = "profile" if not profile_exists else "discover"
                                    st.rerun()
                            else:
                                st.error("Incorrect password")
                        except TypeError as e:
                            st.error(f"Authentication error: {str(e)}")
                    else:
                        st.error("Email not registered")

        # Forgot password link
        if st.button("Forgot Password?"):
            st.session_state.view = "forgot_password"
            st.rerun()

    with register_tab:
        with st.form("register_form"):
            email = st.text_input("Student Email (must start with 3 numbers)", key="register_email")
            password = st.text_input("Create Password (min 8 characters)", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")

            if st.form_submit_button("Create Account"):
                if not is_valid_student_email(email):
                    st.error("Invalid student email format. Must start with 3 numbers")
                elif len(password) < 8:
                    st.error("Password must be at least 8 characters")
                elif password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    # Check if email exists
                    conn = sqlite3.connect("campus_connect.db")
                    c = conn.cursor()
                    c.execute("SELECT 1 FROM users WHERE email=?", (email,))
                    if c.fetchone():
                        conn.close()
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
                conn.close()


# Forgot password flow (UPDATED for OTP)
def forgot_password():
    st.title("Reset Your Password")

    with st.form("forgot_password_form"):
        email = st.text_input("Enter your student email address")

        if st.form_submit_button("Send OTP"):
            if not is_valid_student_email(email):
                st.error("Invalid student email format")
            else:
                conn = sqlite3.connect("campus_connect.db")
                user_exists = conn.execute(
                    "SELECT 1 FROM users WHERE email=?", (email,)
                ).fetchone()

                if not user_exists:
                    st.error("Email not registered")
                else:
                    # Generate and store reset OTP
                    otp = generate_otp()
                    expiry = datetime.now() + timedelta(minutes=10)

                    conn.execute(
                        "INSERT OR REPLACE INTO password_resets (email, otp, expiry) VALUES (?, ?, ?)",
                        (email, otp, expiry)
                    )
                    conn.commit()
                    conn.close()

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


# Profile Creation with form validation highlighting
def create_profile():
    st.title("Create Your Profile")
    st.caption("Complete your profile to start connecting")

    # Initialize form errors if not already set
    if "form_errors" not in st.session_state:
        st.session_state.form_errors = {
            "name": False,
            "bio": False,
            "interests": False,
            "photo": False
        }

    with st.form("profile_form", clear_on_submit=True):
        email = st.text_input("Student Email", value=st.session_state.current_user, disabled=True)
        
        # Name field with validation
        name_label = "Full Name*"
        if st.session_state.form_errors["name"]:
            name_label = f":red[{name_label}]"
        name = st.text_input(name_label)
        
        age = st.slider("Age", 18, 30)
        gender = st.selectbox("Gender", ["Male", "Female", "Non-binary", "Prefer not to say"])
        
        # Bio field with validation
        bio_label = "About Me*"
        if st.session_state.form_errors["bio"]:
            bio_label = f":red[{bio_label}]"
        bio = st.text_area(bio_label, placeholder="Tell others about yourself...")
        
        # Interests field with validation
        interests_label = "Interests*"
        if st.session_state.form_errors["interests"]:
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
        if st.session_state.form_errors["photo"]:
            photo_label = f":red[{photo_label}]"
        photo = st.file_uploader(photo_label, type=["jpg", "png", "jpeg"],
                                 accept_multiple_files=False)

        if st.form_submit_button("Save Profile"):
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

                conn = sqlite3.connect("campus_connect.db")
                conn.execute('''INSERT INTO profiles
                                    (email, name, age, gender, bio, interests, photo, timestamp, intention)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                             (st.session_state.current_user, name, age, gender, bio,
                              ", ".join(interests), photo_data, datetime.now(), intention))
                conn.commit()
                conn.close()

                st.success("Profile created successfully!")
                st.session_state.view = "discover"
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.error(f"Error creating profile: {str(e)}")


# Profile Editing
def edit_profile():
    conn = sqlite3.connect("campus_connect.db")
    profile = conn.execute(
        "SELECT * FROM profiles WHERE email=?",
        (st.session_state.current_user,)
    ).fetchone()
    conn.close()

    if not profile:
        st.error("Profile not found")
        st.session_state.view = "profile"
        st.rerun()

    st.title("Edit Your Profile")
    st.caption("Update your information")

    with st.form("edit_profile_form"):
        name = st.text_input("Full Name", value=profile[1])
        age = st.slider("Age", 18, 30, value=profile[2])
        gender = st.selectbox("Gender",
                              ["Male", "Female", "Non-binary", "Prefer not to say"],
                              index=["Male", "Female", "Non-binary", "Prefer not to say"].index(profile[3]))
        bio = st.text_area("About Me", value=profile[4])
        current_interests = profile[5].split(", ") if profile[5] else []
        interests = st.multiselect("Interests", [
            "Sports", "Music", "Gaming", "Academics",
            "Art", "Travel", "Food", "Movies", "Dancing"
        ], default=current_interests)

        # Show current photo if exists
        if profile[6]:
            try:
                st.image(Image.open(io.BytesIO(profile[6])), width=150, caption="Current Photo")
            except:
                st.image("default_profile.png", width=150, caption="Current Photo")

        photo = st.file_uploader("Update Profile Photo (max 10MB, leave empty to keep current)",
                                 type=["jpg", "png", "jpeg"],
                                 accept_multiple_files=False)

        # Intention field
        intentions = ["Relationship", "Friendship", "Hookups", "Not sure yet"]
        current_intention = profile[8] if len(profile) > 8 else "Not sure yet"
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
            try:
                # Use new photo if provided, otherwise keep existing
                photo_data = profile[6]
                if photo:
                    if photo.size > 10 * 1024 * 1024:  # 10MB limit
                        st.error("Photo size must be less than 10MB")
                        return
                    else:
                        photo_data = photo.read()

                conn = sqlite3.connect("campus_connect.db")
                conn.execute('''UPDATE profiles
                                SET name=?,
                                    age=?,
                                    gender=?,
                                    bio=?,
                                    interests=?,
                                    photo=?,
                                    intention=?
                                WHERE email = ?''',
                             (name, age, gender, bio, ", ".join(interests),
                              photo_data, intention, st.session_state.current_user))
                conn.commit()
                conn.close()

                st.success("Profile updated successfully!")
                st.session_state.view = "discover"
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.error(f"Error updating profile: {str(e)}")


# Record like action
def record_like(from_email, to_email):
    conn = sqlite3.connect("campus_connect.db")
    conn.execute(
        '''INSERT INTO connections (id, from_email, to_email, status, timestamp)
           VALUES (?, ?, ?, ?, ?)''',
        (str(uuid4()), from_email, to_email, "liked", datetime.now())
    )
    conn.commit()
    conn.close()


# Record connection request
def record_connection_request(from_email, to_email):
    conn = sqlite3.connect("campus_connect.db")
    conn.execute(
        '''INSERT INTO connections (id, from_email, to_email, status, timestamp)
           VALUES (?, ?, ?, ?, ?)''',
        (str(uuid4()), from_email, to_email, "requested", datetime.now())
    )
    conn.commit()
    conn.close()


# Discover Profiles with optimized performance and swipe functionality
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
    email, name, age, gender, bio, interests, photo, intention = available_profiles[
        st.session_state.current_index]

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
    conn = sqlite3.connect("campus_connect.db")
    
    try:
        # Pre-fetch blocked users
        blocked_users = conn.execute(
            "SELECT blocked_email FROM blocked_users WHERE blocker_email=?",
            (current_user,)
        ).fetchall()
        blocked_emails = [row[0] for row in blocked_users]

        # Get profiles excluding current user and blocked users
        profiles = []
        for row in conn.execute(
                '''SELECT email, name, age, gender, bio, interests, photo, intention
                   FROM profiles
                   WHERE email != ?''',
                (current_user,)
        ).fetchall():
            if row[0] not in blocked_emails:
                profiles.append(row)
                
        return profiles
    except sqlite3.Error as e:
        st.error(f"Database error: {e}")
        return []
    finally:
        conn.close()


# Connections Management
def view_connections():
    current_user = st.session_state.current_user
    conn = sqlite3.connect("campus_connect.db")

    st.title("Your Connections")

    # Pending Requests
    st.subheader("Pending Requests")
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
            req_id, from_email, timestamp, name, photo, bio = req

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
                
                # FIXED TIMESTAMP HANDLING
                # Convert string to datetime object if needed
                if isinstance(timestamp, str):
                    try:
                        # Handle both formats (with and without microseconds)
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
                        conn.execute(
                            "DELETE FROM connections WHERE id=?",
                            (req_id,)
                        )
                        conn.commit()
                        st.rerun()
            st.divider()

    # Your Connections
    st.subheader("Your Connections")
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
            conn_id, other_email, timestamp, name, photo = conn_item

            # Check for unread messages
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

                # Report button for connections
                if st.button("⚠️ Report", key=f"report_{conn_id}"):
                    st.session_state.reporting_user = other_email
                    st.session_state.reporting_name = name
                    st.session_state.view = "report_user"
                    st.rerun()

                # Block button for connections
                if st.button("🚫 Block", key=f"block_{conn_id}"):
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

    conn.close()


# Chat Interface - Fixed to match your screenshot
def chat_interface():
    current_user = st.session_state.current_user
    other_user = st.session_state.current_chat

    conn = sqlite3.connect("campus_connect.db")
    other_profile = conn.execute(
        "SELECT name, photo FROM profiles WHERE email=?",
        (other_user,)
    ).fetchone()
    conn.close()

    if not other_profile:
        st.error("Profile not found")
        st.session_state.view = "connections"
        st.rerun()

    other_name, other_photo = other_profile

    # Chat header
    col1, col2 = st.columns([1, 10])
    with col1:
        if st.button("← Back"):
            st.session_state.view = "connections"
            st.rerun()
    with col2:
        st.title(f"Chat with {other_name}")

    # Generate chat ID
    chat_id = "_".join(sorted([current_user, other_user]))

    # Get messages
    conn = sqlite3.connect("campus_connect.db")
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
    conn.close()

    # Fixed chat container using CSS to match your screenshot
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
        .chat-bubble {
            margin: 10px 0;
            display: flex;
            flex-direction: column;
        }
        .sender-bubble {
            align-items: flex-end;
        }
        .receiver-bubble {
            align-items: flex-start;
        }
        .bubble-content {
            max-width: 70%;
            padding: 10px 15px;
            border-radius: 15px;
            position: relative;
        }
        .sender-content {
            background-color: #4a4e69;
            margin-left: 30%;
        }
        .receiver-content {
            background-color: #2d3039;
            margin-right: 30%;
        }
        .timestamp {
            font-size: 0.7em;
            color: #aaa;
            margin-top: 5px;
        }
        .receiver-info {
            display: flex;
            align-items: center;
            margin-bottom: 5px;
        }
        .receiver-avatar {
            width: 30px;
            height: 30px;
            border-radius: 50%;
            margin-right: 10px;
            object-fit: cover;
        }
        </style>
        """, 
        unsafe_allow_html=True
    )
    
    # Display chat messages in scrollable container
    chat_container = st.container()
    with chat_container:
        st.markdown('<div class="chat-container">', unsafe_allow_html=True)
        
        for msg in messages:
            msg_id, sender, receiver, message, msg_time, read = msg
            
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
                # Sender (current user) message
                st.markdown(
                    f"""
                    <div class="chat-bubble sender-bubble">
                        <div class="bubble-content sender-content">
                            <div>{message}</div>
                            <div class="timestamp" style="text-align: right;">{timestamp}</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            else:
                # Receiver message with avatar
                avatar_html = "👤"
                if other_photo:
                    try:
                        # Convert to base64 for HTML embedding
                        img = Image.open(io.BytesIO(other_photo))
                        buffered = io.BytesIO()
                        img.save(buffered, format="PNG")
                        img_str = base64.b64encode(buffered.getvalue()).decode()
                        avatar_html = f'<img src="data:image/png;base64,{img_str}" class="receiver-avatar">'
                    except:
                        pass
                
                st.markdown(
                    f"""
                    <div class="chat-bubble receiver-bubble">
                        <div class="receiver-info">
                            {avatar_html}
                            <div><strong>{other_name}</strong></div>
                        </div>
                        <div class="bubble-content receiver-content">
                            <div>{message}</div>
                            <div class="timestamp">{timestamp}</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        
        st.markdown('</div>', unsafe_allow_html=True)

    # Message input
    if prompt := st.chat_input("Type a message..."):
        # Add message to database
        conn = sqlite3.connect("campus_connect.db")
        conn.execute(
            '''INSERT INTO messages
                   (id, chat_id, sender, receiver, message, time, read)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (str(uuid4()), chat_id, current_user, other_user,
             prompt, datetime.now(), 0)
        )
        conn.commit()
        conn.close()
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
            conn = sqlite3.connect("campus_connect.db")
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
            conn.close()

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
                conn = sqlite3.connect("campus_connect.db")
                c = conn.cursor()
                c.execute("SELECT password, salt FROM users WHERE email=?",
                          (st.session_state.current_user,))
                result = c.fetchone()

                if result:
                    hashed_pw, salt = result
                    if bcrypt.hashpw(password.encode(), salt) == hashed_pw:
                        # Delete all user data
                        conn.execute("DELETE FROM users WHERE email=?",
                                     (st.session_state.current_user,))
                        conn.execute("DELETE FROM profiles WHERE email=?",
                                     (st.session_state.current_user,))
                        conn.execute("DELETE FROM connections WHERE from_email=? OR to_email=?",
                                     (st.session_state.current_user, st.session_state.current_user))
                        conn.execute("DELETE FROM messages WHERE sender=? OR receiver=?",
                                     (st.session_state.current_user, st.session_state.current_user))
                        conn.commit()
                        conn.close()

                        st.success("Account deleted successfully")
                        st.session_state.clear()
                        st.session_state.view = "auth"
                        st.experimental_set_query_params()
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
            conn = sqlite3.connect("campus_connect.db")
            name = conn.execute(
                "SELECT name FROM profiles WHERE email=?",
                (notification["from_user"],)
            ).fetchone()[0]
            conn.close()

            st.write(f"✅ {name} accepted your connection request")
            st.caption(notification["timestamp"].strftime("%b %d, %Y at %H:%M"))
            st.divider()


# Main App with persistent sessions
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

    # Navigation sidebar
    if st.session_state.current_user:
        with st.sidebar:
            st.header("Campus Connect")
            st.divider()

            # Profile quick view
            conn = sqlite3.connect("campus_connect.db")
            profile = conn.execute(
                "SELECT name, photo FROM profiles WHERE email=?",
                (st.session_state.current_user,)
            ).fetchone()
            conn.close()

            if profile:
                name, photo = profile
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

            if st.button("Delete Account", type="primary"):
                st.session_state.view = "delete_account"
                st.rerun()

            st.divider()
            if st.button("Logout"):
                st.session_state.clear()
                st.experimental_set_query_params()
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
    # NEW: Handle reset OTP verification view
    elif st.session_state.reset_otp_verification:
        # This is handled within auth_system now
        auth_system()

    # Add sample data if database is empty
    conn = sqlite3.connect("campus_connect.db")
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
            hashed_pw = bcrypt.hashpw(password.encode(), salt)

            conn.execute("INSERT OR IGNORE INTO users (email, password, salt, verified) VALUES (?, ?, ?, ?)",
                         (email, hashed_pw, salt, 1))
            conn.execute(
                "INSERT INTO profiles (email, name, age, gender, bio, interests, photo, timestamp, intention) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                profile)

        conn.commit()
    conn.close()


if __name__ == "__main__":
    main()
