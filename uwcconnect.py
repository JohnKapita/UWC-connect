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
# Add to your existing imports
import os
from PIL import Image, ImageDraw, ImageFont

# Load environment variables for email credentials
load_dotenv()


# Initialize database with proper schema
def init_database():
    conn = sqlite3.connect("uwc_connect.db")
    c = conn.cursor()

    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (
                     email
                     TEXT
                     PRIMARY
                     KEY,
                     password
                     TEXT,
                     salt
                     TEXT,
                     verified
                     BOOLEAN
                     DEFAULT
                     0,
                     otp
                     TEXT,
                     otp_expiry
                     DATETIME
                 )''')

    # Create profiles table with intention column
    c.execute('''CREATE TABLE IF NOT EXISTS profiles
                 (
                     email
                     TEXT
                     PRIMARY
                     KEY,
                     name
                     TEXT,
                     age
                     INTEGER,
                     gender
                     TEXT,
                     bio
                     TEXT,
                     interests
                     TEXT,
                     photo
                     BLOB,
                     timestamp
                     DATETIME,
                     intention
                     TEXT
                     DEFAULT
                     'Not sure yet'
                 )''')

    # Create connections table
    c.execute('''CREATE TABLE IF NOT EXISTS connections
                 (
                     id
                     TEXT
                     PRIMARY
                     KEY,
                     from_email
                     TEXT,
                     to_email
                     TEXT,
                     status
                     TEXT,
                     timestamp
                     DATETIME
                 )''')

    # Create messages table
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (
                     id
                     TEXT
                     PRIMARY
                     KEY,
                     chat_id
                     TEXT,
                     sender
                     TEXT,
                     receiver
                     TEXT,
                     message
                     TEXT,
                     time
                     DATETIME,
                     read
                     BOOLEAN
                     DEFAULT
                     0
                 )''')

    # Create reports table
    c.execute('''CREATE TABLE IF NOT EXISTS reports
                 (
                     id
                     TEXT
                     PRIMARY
                     KEY,
                     reporter_email
                     TEXT,
                     reported_email
                     TEXT,
                     reason
                     TEXT,
                     details
                     TEXT,
                     timestamp
                     DATETIME,
                     status
                     TEXT
                     DEFAULT
                     'pending'
                 )''')

    # Create password resets table
    c.execute('''CREATE TABLE IF NOT EXISTS password_resets
                 (
                     email
                     TEXT
                     PRIMARY
                     KEY,
                     token
                     TEXT,
                     expiry
                     DATETIME
                 )''')

    # Create blocked users table
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_users
    (
        blocker_email
        TEXT,
        blocked_email
        TEXT,
        timestamp
        DATETIME,
        PRIMARY
        KEY
                 (
        blocker_email,
        blocked_email
                 )
        )''')

    # Add indexes
    c.execute('''CREATE INDEX IF NOT EXISTS idx_connections_from ON connections(from_email)''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_connections_to ON connections(to_email)''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id)''')

    # Check for missing columns
    try:
        c.execute("PRAGMA table_info(profiles)")
        columns = [col[1] for col in c.fetchall()]
        if 'intention' not in columns:
            c.execute("ALTER TABLE profiles ADD COLUMN intention TEXT DEFAULT 'Not sure yet'")
    except Exception as e:
        st.error(f"Database upgrade error: {str(e)}")

    conn.commit()
    conn.close()


# Initialize session state
def init_session_state():
    if "current_user" not in st.session_state:
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


# Strict UWC email validation
def is_valid_uwc_email(email):
    if not email:
        return False
    pattern = r'^s?\d{1,7}@myuwc\.ac\.za$'
    return re.match(pattern, email) is not None


# Generate random 6-digit OTP
def generate_otp():
    return str(random.randint(100000, 999999))


# Generate random 32-character reset token
def generate_reset_token():
    return base64.urlsafe_b64encode(os.urandom(24)).decode()


# Send OTP email
def send_otp_email(receiver_email, otp):
    sender_email = os.getenv("SMTP_EMAIL")
    sender_password = os.getenv("SMTP_PASSWORD")

    if not sender_email or not sender_password:
        st.error("Email configuration error. Please check your .env file")
        return False

    message = MIMEText(f"""Your UWC Connect verification code is: {otp}

This code will expire in 10 minutes.""")
    message['Subject'] = "Verify Your UWC Connect Account"
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


# Send password reset email
def send_reset_email(receiver_email, token):
    sender_email = os.getenv("SMTP_EMAIL")
    sender_password = os.getenv("SMTP_PASSWORD")

    if not sender_email or not sender_password:
        st.error("Email configuration error. Please check your .env file")
        return False

    reset_link = f"https://your-app-url.com/reset?token={token}"  # Replace with your actual URL

    message = MIMEText(f"""You requested a password reset for your UWC Connect account.

Click this link to reset your password: {reset_link}

If you didn't request this, please ignore this email.""")

    message['Subject'] = "Password Reset Request - UWC Connect"
    message['From'] = sender_email
    message['To'] = receiver_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        return True
    except Exception as e:
        st.error(f"Failed to send reset email: {str(e)}")
        return False


# Verify OTP against database
def verify_otp_in_db(email, user_otp):
    conn = sqlite3.connect("uwc_connect.db")
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


# Authentication system
def auth_system():
    st.title("UWC Connect 🔐😍❤️")
    st.subheader("Exclusive dating sites for University of the Western Cape Students")

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

                    conn = sqlite3.connect("uwc_connect.db")
                    conn.execute(
                        "UPDATE users SET password=?, salt=?, verified=1, otp=NULL, otp_expiry=NULL WHERE email=?",
                        (hashed_pw, salt, email)
                    )
                    conn.commit()
                    conn.close()

                    st.session_state.current_user = email
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
                        conn = sqlite3.connect("uwc_connect.db")
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

                conn = sqlite3.connect("uwc_connect.db")
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
                conn = sqlite3.connect("uwc_connect.db")
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
        st.subheader("Reset Password")

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

                    conn = sqlite3.connect("uwc_connect.db")
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

    # Normal auth tabs
    login_tab, register_tab = st.tabs(["Login", "Register"])

    with login_tab:
        with st.form("login_form"):
            email = st.text_input("UWC Email (e.g., s1234567@myuwc.ac.za)", key="login_email")
            password = st.text_input("Password", type="password")
            remember_me = st.checkbox("Remember me")

            if st.form_submit_button("Login"):
                if not is_valid_uwc_email(email):
                    st.error("Invalid UWC email format. Must be like s1234567@myuwc.ac.za")
                else:
                    conn = sqlite3.connect("uwc_connect.db")
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
                                    # Check if profile exists
                                    conn = sqlite3.connect("uwc_connect.db")
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
            email = st.text_input("UWC Email (e.g., s1234567@myuwc.ac.za)", key="register_email")
            password = st.text_input("Create Password (min 8 characters)", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")

            if st.form_submit_button("Create Account"):
                if not is_valid_uwc_email(email):
                    st.error("Invalid UWC email format. Must start with numbers (e.g., s1234567@myuwc.ac.za)")
                elif len(password) < 8:
                    st.error("Password must be at least 8 characters")
                elif password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    # Check if email exists
                    conn = sqlite3.connect("uwc_connect.db")
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


# Forgot password flow
def forgot_password():
    st.title("Reset Your Password")

    with st.form("forgot_password_form"):
        email = st.text_input("Enter your UWC email address")

        if st.form_submit_button("Send Reset Link"):
            if not is_valid_uwc_email(email):
                st.error("Invalid UWC email format")
            else:
                conn = sqlite3.connect("uwc_connect.db")
                user_exists = conn.execute(
                    "SELECT 1 FROM users WHERE email=?", (email,)
                ).fetchone()

                if not user_exists:
                    st.error("Email not registered")
                else:
                    # Generate and store reset token
                    token = generate_reset_token()
                    expiry = datetime.now() + timedelta(hours=1)

                    conn.execute(
                        "INSERT OR REPLACE INTO password_resets (email, token, expiry) VALUES (?, ?, ?)",
                        (email, token, expiry)
                    )
                    conn.commit()
                    conn.close()

                    if send_reset_email(email, token):
                        st.success("Password reset link sent to your email!")
                    else:
                        st.error("Failed to send reset email. Please try again.")

    if st.button("Back to Login"):
        st.session_state.view = "auth"
        st.rerun()


# Password reset flow
def reset_password(token):
    conn = sqlite3.connect("uwc_connect.db")
    reset_request = conn.execute(
        "SELECT email, expiry FROM password_resets WHERE token=?", (token,)
    ).fetchone()
    conn.close()

    if not reset_request:
        st.error("Invalid or expired reset token")
        st.session_state.view = "auth"
        st.rerun()
        return

    email, expiry = reset_request
    if datetime.now() > datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S.%f"):
        st.error("Reset token has expired")
        st.session_state.view = "auth"
        st.rerun()
        return

    st.session_state.temp_email = email
    st.session_state.resetting_password = True
    st.rerun()


# Profile Creation
def create_profile():
    st.title("Create Your Profile")
    st.caption("Complete your profile to start connecting")

    with st.form("profile_form", clear_on_submit=True):
        email = st.text_input("UWC Email", value=st.session_state.current_user, disabled=True)
        name = st.text_input("Full Name")
        age = st.slider("Age", 18, 30)
        gender = st.selectbox("Gender", ["Male", "Female", "Non-binary", "Prefer not to say"])
        bio = st.text_area("About Me", placeholder="Tell others about yourself...")
        interests = st.multiselect("Interests", [
            "Sports", "Music", "Gaming", "Academics",
            "Art", "Travel", "Food", "Movies", "Dancing"
        ])

        intention = st.radio("What are you looking for?",
                             ["Relationship", "Friendship", "Hookups", "Not sure yet"],
                             index=3)

        # Photo uploader
        photo = st.file_uploader("Profile Photo (max 2MB)", type=["jpg", "png", "jpeg"],
                                 accept_multiple_files=False)

        if st.form_submit_button("Save Profile"):
            # Validation
            if not name or not bio or not interests or not photo:
                st.error("Please fill in all required fields and upload a photo")
                return

            try:
                # Read and verify photo
                photo_data = photo.read()
                if len(photo_data) > 2 * 1024 * 1024:  # 2MB limit
                    st.error("Photo exceeds 2MB size limit")
                    return

                conn = sqlite3.connect("uwc_connect.db")
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
    conn = sqlite3.connect("uwc_connect.db")
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

        photo = st.file_uploader("Update Profile Photo (leave empty to keep current)",
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
                    if photo.size > 2 * 1024 * 1024:  # 2MB limit
                        st.error("Photo size must be less than 2MB")
                    else:
                        photo_data = photo.read()

                conn = sqlite3.connect("uwc_connect.db")
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


# Discover Profiles
def discover_profiles():
    st.title("Discover UWC SINGLES🥰😍")
    current_user = st.session_state.current_user
    conn = sqlite3.connect('uwc_connect.db')

    try:
        # Get current user's profile
        current_profile = conn.execute(
            "SELECT name, age, gender, interests, intention FROM profiles WHERE email=?",
            (current_user,)
        ).fetchone()

        if not current_profile:
            st.warning("Complete your profile to start discovering others.")
            conn.close()
            return

        current_name, current_age, current_gender, current_interests, current_intention = current_profile
        user_interests = set(current_interests.split(", ")) if current_interests else set()
    except sqlite3.Error as e:
        st.error(f"Database error: {e}")
        conn.close()
        return

    # Get and process profiles
    available_profiles = []
    for row in conn.execute(
            '''SELECT email,
                      name,
                      age,
                      gender,
                      bio,
                      interests,
                      photo,
                      intention
               FROM profiles
               WHERE email != ?''',
            (current_user,)
    ).fetchall():
        # Unpack the row and process each profile
        email, name, age, gender, bio, interests_str, photo, intention = row

        # Check if user is blocked
        is_blocked = conn.execute(
            "SELECT 1 FROM blocked_users WHERE blocker_email=? AND blocked_email=?",
            (current_user, email)
        ).fetchone()

        if is_blocked:
            continue

        # Calculate compatibility score
        other_interests = set(interests_str.split(", ")) if interests_str else set()
        shared_interests = user_interests & other_interests
        score = len(shared_interests)  # Simple compatibility score

        # Add to available profiles
        available_profiles.append((score, email, name, age, gender, bio, interests_str, photo, intention))

    # Sort by compatibility
    available_profiles.sort(reverse=True, key=lambda x: x[0])

    if not available_profiles:
        st.info("No profiles to show. Try again later.")
        conn.close()
        return

    # Get current profile to show
    st.session_state.current_index = st.session_state.get('current_index', 0)
    if st.session_state.current_index >= len(available_profiles):
        st.session_state.current_index = 0

    # Unpack profile data
    score, email, name, age, gender, bio, interests, photo, intention = available_profiles[
        st.session_state.current_index]

    # Display the profile
    col1, col2 = st.columns(2)
    with col1:
        def safe_image_display(image_data, caption, width, is_bytes=False):
            """Safely display images with fallbacks for errors"""
            try:
                if image_data:
                    if is_bytes:
                        st.image(Image.open(io.BytesIO(image_data)),
                                 caption=caption,
                                 width=width)
                    elif os.path.exists(image_data):
                        st.image(image_data, caption=caption, width=width)
                    else:
                        raise FileNotFoundError("Image file not found")
                else:
                    raise ValueError("No image data provided")
            except Exception as e:
                # Create fallback images programmatically
                try:
                    # First fallback: Gray placeholder
                    blank_image = Image.new('RGB', (width, width), (200, 200, 200))
                    draw = ImageDraw.Draw(blank_image)

                    # Add text to the placeholder
                    try:
                        font = ImageFont.truetype("Arial", 20)
                    except:
                        font = ImageFont.load_default()

                    text = "Profile\nImage"
                    text_width, text_height = draw.textsize(text, font=font)
                    position = ((width - text_width) // 2, (width - text_height) // 2)
                    draw.text(position, text, fill=(100, 100, 100), font=font)

                    st.image(blank_image, caption=f"Placeholder: {caption}", width=width)
                except:
                    # Final fallback: Red error image
                    error_image = Image.new('RGB', (width, width), (255, 0, 0))
                    st.image(error_image, caption="Image Error", width=width)

        # Use the safe display function for both cases
        if photo:
            safe_image_display(photo, f"{name}'s Photo", 300, is_bytes=True)
        else:
            safe_image_display("default_profile.png", "Default Profile", 300)

    with col2:
        st.subheader(f"{name}, {age}")
        st.caption(f"{gender}")
        st.caption(f"Looking for: {intention}")
        st.write(f"**Shared interests:** {', '.join(user_interests.intersection(set(interests.split(', '))))}")
        st.write(bio)

        # Report button
        if st.button("⚠️ Report User", key=f"report_{email}"):
            st.session_state.reporting_user = email
            st.session_state.reporting_name = name
            st.session_state.view = "report_user"
            st.rerun()

    # Navigation buttons
    col_nav1, col_nav2, col_nav3 = st.columns(3)
    with col_nav1:
        if st.button("👎 Pass", key="pass"):
            # Move to next profile
            st.session_state.current_index = (st.session_state.current_index + 1) % len(available_profiles)
            st.rerun()
    with col_nav2:
        if st.button("❤️ Like", key="like"):
            # Record like and move to next
            record_like(st.session_state.current_user, email)
            st.session_state.current_index = (st.session_state.current_index + 1) % len(available_profiles)
            st.success(f"Liked {name}!")
            st.rerun()()
    with col_nav3:
        if st.button("👉 Next", key="next"):
            st.session_state.current_index = (st.session_state.current_index + 1) % len(available_profiles)
            st.rerun()  # Only rerun if not a match

    conn.close()


# Record like action
def record_like(from_email, to_email):
    conn = sqlite3.connect("uwc_connect.db")
    conn.execute(
        '''INSERT INTO connections (id, from_email, to_email, status, timestamp)
           VALUES (?, ?, ?, ?, ?)''',
        (str(uuid4()), from_email, to_email, "liked", datetime.now())
    )
    conn.commit()
    conn.close()


# Connections Management
def view_connections():
    current_user = st.session_state.current_user
    conn = sqlite3.connect("uwc_connect.db")

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
                st.caption(f"Requested on {timestamp.strftime('%b %d, %Y at %H:%M')}")
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
                st.caption(f"Connected since {timestamp.strftime('%b %d, %Y')}")
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
                        '''INSERT
                        OR IGNORE INTO blocked_users 
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


# Chat Interface
def chat_interface():
    current_user = st.session_state.current_user
    other_user = st.session_state.current_chat

    conn = sqlite3.connect("uwc_connect.db")
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
    conn = sqlite3.connect("uwc_connect.db")
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

    # Display chat messages
    chat_container = st.container(height=400)
    with chat_container:
        for msg in messages:
            msg_id, sender, receiver, message, msg_time, read = msg

            if sender == current_user:
                col1, col2 = st.columns([0.7, 0.3])
                with col2:
                    with st.chat_message("user", avatar="😊"):
                        st.write(message)
                        st.caption(msg_time.strftime("%H:%M"))
            else:
                col1, col2 = st.columns([0.3, 0.7])
                with col1:
                    avatar = None
                    if other_photo:
                        try:
                            avatar = Image.open(io.BytesIO(other_photo))
                        except:
                            avatar = "👤"
                    else:
                        avatar = "👤"

                    with st.chat_message("assistant", avatar=avatar):
                        st.write(message)
                        st.caption(msg_time.strftime("%H:%M"))

    # Message input
    if prompt := st.chat_input("Type a message..."):
        # Add message to database
        conn = sqlite3.connect("uwc_connect.db")
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
            conn = sqlite3.connect("uwc_connect.db")
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
                conn = sqlite3.connect("uwc_connect.db")
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
            conn = sqlite3.connect("uwc_connect.db")
            name = conn.execute(
                "SELECT name FROM profiles WHERE email=?",
                (notification["from_user"],)
            ).fetchone()[0]
            conn.close()

            st.write(f"✅ {name} accepted your connection request")
            st.caption(notification["timestamp"].strftime("%b %d, %Y at %H:%M"))
            st.divider()


# Main App
def main():
    st.set_page_config(
        page_title="UWC Connect",
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
    </style>
    """, unsafe_allow_html=True)

    init_database()
    init_session_state()

    # Handle password reset token if present - UPDATED TO USE st.query_params
       # Some code above
    if some_condition:  # Line 1349
    # Add at least one indented statement here
    # For example:
    pass  # This is a placeholder

query_params = st.experimental_get_query_params()  # Line 1352
if "token" in query_params:
    token = query_params["token"][0]  # Get first token value
    
    if token:
        reset_password(token)    # Navigation sidebar
    if st.session_state.current_user:
        with st.sidebar:
            st.header("UWC Connect")
            st.divider()

            # Profile quick view
            conn = sqlite3.connect("uwc_connect.db")
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

    # Add sample data if database is empty
    conn = sqlite3.connect("uwc_connect.db")
    # Insert sample data if empty
    if not conn.execute("SELECT 1 FROM profiles").fetchone():
        # Sample profiles
        sample_profiles = [
            ("s123456@myuwc.ac.za", "Amanda K", 21, "Female",
             "Psychology major who loves hiking and indie music",
             "Music, Travel, Art", b"", datetime.now(), "Relationship"),
            ("s234567@myuwc.ac.za", "James L", 22, "Male",
             "Computer Science student and football enthusiast",
             "Sports, Gaming, Movies", b"", datetime.now(), "Friendship"),
            ("s345678@myuwc.ac.za", "Priya M", 20, "Female",
             "Art student passionate about street photography",
             "Art, Photography, Coffee", b"", datetime.now(), "Not sure yet"),
            ("s456789@myuwc.ac.za", "Thomas O", 23, "Male",
             "Engineering student who plays guitar and loves jazz",
             "Music, Technology, Science", b"", datetime.now(), "Hookups"),
            ("s567890@myuwc.ac.za", "Naledi P", 19, "Female",
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
