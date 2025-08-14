# Imports
import streamlit as st
import sqlite3
import bcrypt
import io
import json
import time
from uuid import uuid4
from datetime import datetime, timedelta
from PIL import Image
from streamlit_webrtc import webrtc_streamer, WebRtcMode
from pathlib import Path
import random
import string
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import mimetypes
import requests
import functools
import threading
import logging
import os
import re
import html

# Constants
PEPPER_SECRET = "SuperSecretPepper123!"
DATABASE_FILE = "campus_connect.db"
RTC_CONFIGURATION = {"iceServers": [{"urls": ["stun:stun.l.google.com:19302"]}]}

# Initialize security logger
def log_security_event(event, details):
    entry = json.dumps({
        "timestamp": datetime.now().isoformat(),
        "event": event,
        "details": details
    })
    with open("security.log", "a") as f:
        f.write(entry + "\n")

# Database connection helper
@functools.lru_cache(maxsize=32)
def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database schema
def init_database():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        email TEXT PRIMARY KEY,
                        password BLOB NOT NULL,
                        salt BLOB NOT NULL,
                        verified INTEGER DEFAULT 0,
                        banned INTEGER DEFAULT 0
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS profiles (
                        email TEXT PRIMARY KEY,
                        name TEXT,
                        age INTEGER,
                        gender TEXT,
                        bio TEXT,
                        interests TEXT,
                        photo BLOB,
                        timestamp TIMESTAMP,
                        intention TEXT
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS connections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        from_email TEXT,
                        to_email TEXT,
                        status TEXT,
                        timestamp TIMESTAMP
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS messages (
                        id TEXT PRIMARY KEY,
                        chat_id TEXT,
                        sender TEXT,
                        receiver TEXT,
                        message TEXT,
                        time TIMESTAMP,
                        read INTEGER DEFAULT 0
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS reports (
                        id TEXT PRIMARY KEY,
                        reporter_email TEXT,
                        reported_email TEXT,
                        reason TEXT,
                        details TEXT,
                        timestamp TIMESTAMP,
                        status TEXT DEFAULT 'pending'
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS admins (
                        email TEXT PRIMARY KEY
                    )''')
        conn.commit()

# Session helpers
def init_session_state():
    if "current_user" not in st.session_state:
        st.session_state.current_user = None
    if "view" not in st.session_state:
        st.session_state.view = "auth"
    if "notifications" not in st.session_state:
        st.session_state.notifications = []
    if "session_token" not in st.session_state:
        st.session_state.session_token = None
    if "reset_otp_verification" not in st.session_state:
        st.session_state.reset_otp_verification = False

# -----------------------------
# Authentication System
# -----------------------------
def auth_system():
    st.title("Campus Connect Login / Signup")

    if st.session_state.reset_otp_verification:
        forgot_password()
        return

    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            with get_db_connection() as conn:
                user = conn.execute(
                    "SELECT password, salt, banned FROM users WHERE email=?",
                    (email,)
                ).fetchone()
                if user:
                    if user["banned"]:
                        st.error("Your account is banned")
                        return
                    hashed_pw = user["password"]
                    salt = user["salt"]
                    peppered_password = password + PEPPER_SECRET
                    if bcrypt.hashpw(peppered_password.encode(), salt) == hashed_pw:
                        st.session_state.current_user = email
                        st.session_state.session_token = create_session(email)
                        st.session_state.view = "discover"
                        st.rerun()
                    else:
                        st.error("Incorrect password")
                else:
                    st.error("User not found")

    st.markdown("---")
    st.subheader("New here? Create an account")
    with st.form("signup_form"):
        new_email = st.text_input("Email", key="signup_email")
        new_password = st.text_input("Password", type="password", key="signup_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="signup_confirm")
        submitted_signup = st.form_submit_button("Sign Up")
        if submitted_signup:
            if new_password != confirm_password:
                st.error("Passwords do not match")
            else:
                salt = bcrypt.gensalt()
                peppered_password = new_password + PEPPER_SECRET
                hashed_pw = bcrypt.hashpw(peppered_password.encode(), salt)
                with get_db_connection() as conn:
                    try:
                        conn.execute(
                            "INSERT INTO users (email, password, salt, verified) VALUES (?, ?, ?, ?)",
                            (new_email, hashed_pw, salt, 0)
                        )
                        conn.commit()
                        st.success("Account created! Please create your profile.")
                        st.session_state.current_user = new_email
                        st.session_state.view = "profile"
                        st.rerun()
                    except sqlite3.IntegrityError:
                        st.error("Email already exists")

# -----------------------------
# Forgot Password
# -----------------------------
def forgot_password():
    st.title("Forgot Password")
    email = st.text_input("Enter your email to reset password")
    if st.button("Send Reset Link"):
        with get_db_connection() as conn:
            user_exists = conn.execute(
                "SELECT 1 FROM users WHERE email=?",
                (email,)
            ).fetchone()
        if user_exists:
            reset_token = str(uuid4())
            st.session_state.reset_token = reset_token
            st.session_state.reset_email = email
            st.success(f"Reset link sent! (Simulation) Token: {reset_token}")
        else:
            st.error("Email not found")
    
    if st.session_state.get("reset_token"):
        new_password = st.text_input("Enter new password", type="password")
        confirm_password = st.text_input("Confirm new password", type="password")
        if st.button("Reset Password"):
            if new_password != confirm_password:
                st.error("Passwords do not match")
            else:
                salt = bcrypt.gensalt()
                peppered_password = new_password + PEPPER_SECRET
                hashed_pw = bcrypt.hashpw(peppered_password.encode(), salt)
                with get_db_connection() as conn:
                    conn.execute(
                        "UPDATE users SET password=?, salt=? WHERE email=?",
                        (hashed_pw, salt, st.session_state.reset_email)
                    )
                    conn.commit()
                st.success("Password reset successfully")
                st.session_state.reset_token = None
                st.session_state.reset_email = None
                st.session_state.view = "auth"
                st.rerun()

# -----------------------------
# Profile Creation
# -----------------------------
def create_profile():
    st.title("Create Your Profile")
    with st.form("profile_form"):
        name = st.text_input("Name")
        age = st.number_input("Age", min_value=16, max_value=100)
        gender = st.selectbox("Gender", ["Male", "Female", "Other"])
        bio = st.text_area("Bio", height=100)
        interests = st.text_input("Interests (comma separated)")
        intention = st.selectbox("Relationship Intention", ["Friendship", "Relationship", "Hookups", "Not sure yet"])
        photo_file = st.file_uploader("Upload Profile Photo", type=["png", "jpg", "jpeg"])

        submitted = st.form_submit_button("Save Profile")
        if submitted:
            photo_bytes = photo_file.read() if photo_file else b""
            with get_db_connection() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO profiles (email, name, age, gender, bio, interests, photo, timestamp, intention) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (st.session_state.current_user, name, age, gender, bio, interests, photo_bytes, datetime.now(), intention)
                )
                conn.commit()
            st.success("Profile created successfully")
            st.session_state.view = "discover"
            st.rerun()

# -----------------------------
# Edit Profile
# -----------------------------
def edit_profile():
    st.title("Edit Profile")
    with get_db_connection() as conn:
        profile = conn.execute(
            "SELECT * FROM profiles WHERE email=?",
            (st.session_state.current_user,)
        ).fetchone()
    if not profile:
        st.error("Profile not found")
        st.session_state.view = "profile"
        st.rerun()

    with st.form("edit_profile_form"):
        name = st.text_input("Name", value=profile["name"])
        age = st.number_input("Age", min_value=16, max_value=100, value=profile["age"])
        gender = st.selectbox("Gender", ["Male", "Female", "Other"], index=["Male","Female","Other"].index(profile["gender"]))
        bio = st.text_area("Bio", height=100, value=profile["bio"])
        interests = st.text_input("Interests (comma separated)", value=profile["interests"])
        intention = st.selectbox("Relationship Intention", ["Friendship", "Relationship", "Hookups", "Not sure yet"], index=["Friendship","Relationship","Hookups","Not sure yet"].index(profile["intention"]))
        photo_file = st.file_uploader("Upload New Profile Photo", type=["png", "jpg", "jpeg"])

        submitted = st.form_submit_button("Update Profile")
        if submitted:
            photo_bytes = photo_file.read() if photo_file else profile["photo"]
            with get_db_connection() as conn:
                conn.execute(
                    "UPDATE profiles SET name=?, age=?, gender=?, bio=?, interests=?, photo=?, intention=? WHERE email=?",
                    (name, age, gender, bio, interests, photo_bytes, intention, st.session_state.current_user)
                )
                conn.commit()
            st.success("Profile updated successfully")
            st.session_state.view = "discover"
            st.rerun()

# -----------------------------
# Discover Profiles
# -----------------------------
def discover_profiles():
    st.title("Discover People")
    current_user = st.session_state.current_user

    with get_db_connection() as conn:
        profiles = conn.execute(
            '''SELECT email, name, age, gender, bio, interests, photo, intention
               FROM profiles
               WHERE email != ?
               ORDER BY timestamp DESC''',
            (current_user,)
        ).fetchall()

    if not profiles:
        st.info("No profiles found")
        return

    for profile in profiles:
        email = profile["email"]
        name = profile["name"]
        age = profile["age"]
        gender = profile["gender"]
        bio = profile["bio"]
        interests = profile["interests"]
        photo = profile["photo"]
        intention = profile["intention"]

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
            st.write(f"**{name}, {age} ({gender})**")
            st.caption(f"{bio[:100]}..." if bio else "")
            st.caption(f"Interests: {interests}")
            st.caption(f"Looking for: {intention}")

            col_connect, col_report = st.columns([1, 1])
            with col_connect:
                if st.button("Connect", key=f"connect_{email}"):
                    with get_db_connection() as conn:
                        try:
                            conn.execute(
                                '''INSERT INTO connections (from_email, to_email, status, timestamp)
                                   VALUES (?, ?, 'requested', ?)''',
                                (current_user, email, datetime.now())
                            )
                            conn.commit()
                            st.success(f"Connection request sent to {name}")
                        except sqlite3.IntegrityError:
                            st.warning("Connection request already sent")
                        st.rerun()
            with col_report:
                if st.button("Report", key=f"report_{email}"):
                    st.session_state.reporting_user = email
                    st.session_state.reporting_name = name
                    st.session_state.view = "report_user"
                    st.rerun()
        st.divider()


# -----------------------------
# Connections Management
# -----------------------------
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

                if st.button("📞 Video Call", key=f"call_{conn_id}"):
                    st.session_state.caller = st.session_state.current_user
                    st.session_state.callee = other_email
                    st.session_state.call_state = "ringing"
                    st.session_state.view = "video_call"
                    st.rerun()

                if st.button("⚠️ Report", key=f"report_{conn_id}"):
                    st.session_state.reporting_user = other_email
                    st.session_state.reporting_name = name
                    st.session_state.view = "report_user"
                    st.rerun()

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


# -----------------------------
# Chat Interface
# -----------------------------
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

    chat_id = "_".join(sorted([current_user, other_user]))

    with get_db_connection() as conn:
        messages = conn.execute(
            '''SELECT id, sender, receiver, message, time, read
               FROM messages
               WHERE chat_id=?
               ORDER BY time''',
            (chat_id,)
        ).fetchall()

        conn.execute(
            '''UPDATE messages
               SET read=1
               WHERE receiver = ?
                 AND chat_id = ?
                 AND read =0''',
            (current_user, chat_id)
        )
        conn.commit()

    st.markdown(
        """
        <style>
        .chat-container { height: 400px; overflow-y: auto; padding: 10px; background-color: #1a1d24; border-radius: 10px; margin-bottom: 20px;}
        .sender { background-color: #4a4e69; padding: 10px; border-radius: 15px; margin-bottom: 10px; margin-left: 30%; text-align: right;}
        .receiver { background-color: #2d3039; padding: 10px; border-radius: 15px; margin-bottom: 10px; margin-right: 30%; }
        .timestamp { font-size: 0.7em; color: #aaa; }
        </style>
        """, unsafe_allow_html=True
    )

    with st.container():
        st.markdown('<div class="chat-container">', unsafe_allow_html=True)
        for msg in messages:
            msg_id = msg["id"]
            sender = msg["sender"]
            message = msg["message"]
            msg_time = msg["time"]
            if isinstance(msg_time, str):
                try:
                    if '.' in msg_time:
                        msg_time = datetime.strptime(msg_time, "%Y-%m-%d %H:%M:%S.%f")
                    else:
                        msg_time = datetime.strptime(msg_time, "%Y-%m-%d %H:%M:%S")
                except:
                    msg_time = datetime.now()
            timestamp = msg_time.strftime("%H:%M")

            if sender == current_user:
                st.markdown(f'<div class="sender">{message}<div class="timestamp">{timestamp}</div></div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="receiver">{message}<div class="timestamp">{timestamp}</div></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    if prompt := st.chat_input("Type a message..."):
        with get_db_connection() as conn:
            conn.execute(
                '''INSERT INTO messages (id, chat_id, sender, receiver, message, time, read)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (str(uuid4()), chat_id, current_user, other_user, prompt, datetime.now(), 0)
            )
            conn.commit()
        st.rerun()


# -----------------------------
# Video Call Interface
# -----------------------------
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
        webrtc_ctx = webrtc_streamer(
            key="video-chat",
            mode=WebRtcMode.SENDRECV,
            rtc_configuration=RTC_CONFIGURATION,
            media_stream_constraints={"video": True, "audio": True},
            video_frame_callback=None,
            async_processing=True,
        )
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

# -----------------------------
# Report User Interface
# -----------------------------
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


# -----------------------------
# Account Deletion
# -----------------------------
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


# -----------------------------
# Notification System
# -----------------------------
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


# -----------------------------
# Admin Panel
# -----------------------------
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

# -----------------------------
# Security Dashboard
# -----------------------------
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


# -----------------------------
# Main App
# -----------------------------
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
