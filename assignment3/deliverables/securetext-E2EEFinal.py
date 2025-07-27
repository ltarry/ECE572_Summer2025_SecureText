#!/usr/bin/env python3
"""
Author: Ardeshir S.
Course: ECE 572; Summer 2025
SecureText Console Messenger (Insecure Genesis Version)
A basic console-based messenger application with intentional security vulnerabilities.

Features:
- Account creation with plaintext password storage
- User login
- Send/receive messages via TCP sockets
- Basic password reset functionality
"""

import socket
import threading
import json
import os
import sys
import time
import hashlib
import base64
import secrets
import urllib.parse
import webbrowser
from flask_login import current_user
import requests
import hmac
import pyotp
import collections
import qrcode
import logging
from cryptography.fernet import Fernet
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


logging.basicConfig(
    filename='securetext_server.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)


class SecureTextServer:
    FERNET_KEY = b'WvdwcTgGKOp1iUSaipc4hJa5IoszDQAv-glb-E7ucpo=' #Hardcoded Fernet key for our demo, but is vulnerable in reality
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.users_file = 'users.json'
        self.users = self.load_users()
        self.check_pending_migrations() #check for a migration call required
        self.active_connections = {}  # username -> connection
        self.server_socket = None
        self.fernet = Fernet(self.FERNET_KEY)
        self.totp_attempts = collections.defaultdict(lambda: {'count': 0, 'last_attempt': 0})
        self.failed_logins = collections.defaultdict(int)
    
    def log_event(self, event, username=None, outcome=None, details=None):
        msg = f"EVENT={event}"
        if username:
            msg += f" USER={username}"
        if outcome:
            msg += f" OUTCOME={outcome}"
        if details:
            msg += f" DETAILS={details}"
        logging.info(msg)
    
    def encrypt_totp_secret(self, secret):
        """Encrypt TOTP secret using Fernet"""
        return self.fernet.encrypt(secret.encode()).decode()

    def decrypt_totp_secret(self, encrypted_secret):
        """Decrypt TOTP secret using Fernet"""
        return self.fernet.decrypt(encrypted_secret.encode()).decode()
    
    def generate_totp_uri(self, username, secret):
        """Generate a TOTP URI for QR code setup"""
        return f"otpauth://totp/SecureText:{username}?secret={secret}&issuer=SecureText"
    
    def display_qr_ascii(self, uri):
        """Display QR code as ASCII art in the console"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_Q,  # High error correction
            box_size=2,
            border=2,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
        
    def load_users(self):
        """Load users from JSON file or create empty dict if file doesn't exist"""
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                print(f"Warning: Could not load {self.users_file}, starting with empty user database")
        return {}
    
    def save_users(self):
        """Save users to JSON file with plaintext passwords (INSECURE!)"""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=2)
        except IOError as e:
            print(f"Error saving users: {e}")
    
    def hash_password_sha256(self, password, salt=None):
        """Hash password using SHA-256 with salt"""
        if salt is None:
            salt = secrets.token_bytes(16)  # 128-bit salt
        salted_password = salt + password.encode('utf-8')
        password_hash = hashlib.sha256(salted_password).hexdigest()
        return {
        'hash': password_hash,
        'salt': base64.b64encode(salt).decode('utf-8'),
        'hash_type': 'sha256_salted'
        }

    def generate_salt(self):
        """Generate a cryptographically secure 128-bit salt"""
        return secrets.token_bytes(16)

    def hash_password_pbkdf2(self, password, iterations=100000):
        """Hash password using PBKDF2 with salt"""
        salt = secrets.token_bytes(16)  # 128-bit salt
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations
        )
        return {
            'hash': base64.b64encode(key).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iterations': iterations,
            'hash_type': 'pbkdf2'
        }
    
    def create_account(self, username, password):
        """Create new user account with SHA-256 hashed password"""
        if username in self.users:
            #Suggesting new user to handle local account creation conflicts with Git Users
            suggestion_count = 1
            new_username = f"{username}_{suggestion_count}"
            while new_username in self.users:
                suggestion_count += 1
                new_username = f"{username}_{suggestion_count}"
            return False, f"Username already exists. Suggested: {new_username}", None, None
    
        # Hash password with SHA-256
        password_hash = self.hash_password_sha256(password)
    
        #Generate a unique TOTP secret for the user here
        totp_secret = pyotp.random_base32()
        encrypted_secret = self.encrypt_totp_secret(totp_secret)
        self.users[username] = {
            'password_hash': password_hash,
            'totp_secret': encrypted_secret, # Store TOTP encrypted secret
            'created_at': datetime.now().isoformat(),
            'reset_question': 'What is your favorite color?',
            'reset_answer': 'blue',
            'role': 'user' #Default role
        }
        self.save_users()
        # Generate TOTP URI and display QR code
        uri = self.generate_totp_uri(username, totp_secret)
        return True, "Account created successfully", totp_secret, uri
    
    def authenticate(self, username, password, totp_code=None):
        """Authenticate user with support for all formats, migration, and TOTP"""
        if username not in self.users:
            return False, "Invalid username or password" #Do not let user know if username or password is incorrect
        user = self.users[username]

        # Check Password for all formats:
        password_ok = False    
    
        #Plaintext password storage
        if 'password' in user:
            if user['password'] == password:
                password_ok = True
                self.migrate_user_password(username, password)
    
        #Old unsalted SHA-256 hash
        elif 'password_hash' in user and isinstance(user['password_hash'], str):
            test_hash = hashlib.sha256(password.encode()).hexdigest()
            if test_hash == user['password_hash']:
                password_ok = True
                self.migrate_user_password(username, password)
    
        #New format hashes
        elif 'password_hash' in user and isinstance(user['password_hash'], dict):
            stored_hash = user['password_hash']
            if stored_hash['hash_type'] == 'sha256_salted':
                salt = base64.b64decode(stored_hash['salt'])
                verification_hash = self.hash_password_sha256(password, salt)
                if verification_hash['hash'] == stored_hash['hash']:
                    password_ok = True
                    self.migrate_user_password(username, password)
            elif stored_hash['hash_type'] == 'pbkdf2':
                if self.verify_password_pbkdf2(password, stored_hash):
                    password_ok = True

        if not password_ok:
            return False, "Invalid username or password" #Do not let user know if username or password is incorrect
        
        # --- Rate limiting for TOTP ---
        import time
        now = time.time()
        attempts = self.totp_attempts[username]
        # Reset counter if last attempt was more than 60 seconds ago
        if now - attempts['last_attempt'] > 60:
            attempts['count'] = 0
        attempts['last_attempt'] = now
        if attempts['count'] >= 5:
            return False, "Too many TOTP attempts. Please wait and try again."

        # --- TOTP check with tolerance ---
        if 'totp_secret' in user:
            if not totp_code:
                return False, "TOTP code required"
            totp_secret = self.decrypt_totp_secret(user['totp_secret'])
            totp = pyotp.TOTP(totp_secret)
            # Accept codes within ±1 time step (default 30s)
            if not (totp.verify(totp_code, valid_window=1)):
                attempts['count'] += 1
                return False, "Invalid TOTP code"
            # Reset counter on success
            attempts['count'] = 0
        
        return True, "Authentication successful"

    def migrate_user_password(self, username, password):
        """Migrate user to PBKDF2 hash"""
        print(f"Migrating password for user: {username}")
        hash_data = self.hash_password_pbkdf2(password)
    
        self.users[username] = {
            'password_hash': hash_data,
            'created_at': self.users[username].get('created_at', datetime.now().isoformat()),
            'migrated_at': datetime.now().isoformat(),
            'reset_question': self.users[username].get('reset_question', 'What is your favorite color?'),
            'reset_answer': self.users[username].get('reset_answer', 'blue')
        }
        self.save_users()
        print(f"Successfully migrated password for: {username}")

    def check_pending_migrations(self):
            """Check for users needing migration"""
            needs_migration = []
            for username, data in self.users.items():
                if 'hash_type' not in data.get('password_hash', {}):
                    needs_migration.append(username)
    
            if needs_migration:
                print("\nPassword Migration Status:")
                print(f"Found {len(needs_migration)} users requiring migration:")
                for username in needs_migration:
                    print(f"- {username}")
                print("\nUsers will be migrated upon their next successful login.")
    
            return needs_migration
    
    
    def reset_password(self, username, new_password):
        """Basic password reset - just requires existing username"""
        if username not in self.users:
            return False, "Username not found"
        
        # SECURITY VULNERABILITY: No proper verification for password reset!
        self.users[username]['password'] = new_password
        self.save_users()
        return True, "Password reset successful"
    
    def handle_client(self, conn, addr):
        """Handle individual client connection"""
        print(f"New connection from {addr}")
        current_user = None
        cr_challenges = {}
        conn.settimeout(1.0)  # Wake up every second to check for inactivity
        last_activity = time.time()
        action_count = 0
        TIMEOUT = 30 * 60 # 10 seconds used for demo, set 30 minutes after proof
        MAX_ACTIONS = 10 #2 used for demo, set to 10 after proof

        try:
            while True:
                # Check for session timeout or max actions
                if time.time() - last_activity > TIMEOUT or action_count >= MAX_ACTIONS:
                    self.log_event(
                        event="SESSION_EXPIRED",
                        username=current_user,
                        outcome="EXPIRED",
                        details=f"Session expired after {int(time.time() - last_activity)} seconds or {action_count} actions"
                    )
                    response = {'status': 'error', 'message': 'Session timed out, please log in again.'}
                    try:
                        conn.send(json.dumps(response).encode('utf-8'))
                    except Exception:
                        pass
                        if current_user in self.active_connections:
                            del self.active_connections[current_user]
                            current_user = None
                            last_activity = time.time()
                            action_count = 0

                try:
                    data = conn.recv(1024).decode('latin1')
                    if not data:
                        break
                    last_activity = time.time()  # Only update if data is received
                    action_count += 1

                    try:
                        message = json.loads(data)
                        command = message.get('command')
                    
                        if command == 'CREATE_ACCOUNT':
                            username = message.get('username')
                            password = message.get('password')
                            success, msg, totp_secret, totp_uri = self.create_account(username, password)
                            response = {'status': 'success' if success else 'error', 'message': msg}
                            self.log_event(
                                event=f"COMMAND_{command}",
                                username=current_user,
                                outcome=response.get('status'),
                                details=str(message)
                            )
                            if success:
                                response['totp_secret'] = totp_secret
                                response['totp_uri'] = totp_uri
                        
                        elif command == 'LOGIN':
                            username = message.get('username')
                            password = message.get('password')
                            totp_code = message.get('totp_code')
                            success, msg = self.authenticate(username, password, totp_code)
                            self.log_event(
                            event="AUTH_ATTEMPT",
                            username=current_user,
                            outcome="SUCCESS" if success else "FAIL",
                            details=msg
                            )
                            if not success:
                                self.failed_logins[username] += 1
                                if self.failed_logins[username] >= 3:
                                    print(f"WARNING: 3 failed login attempts for user {username}")
                                    self.log_event(
                                        event="ALERT_FAILED_LOGINS",
                                        username=username,
                                        outcome="WARNING",
                                        details="3 failed login attempts"
                                    )
                            else:
                                self.failed_logins[username] = 0  # Reset on success
                            if success:
                                current_user = username
                                self.active_connections[username] = conn
                                user_role = self.users[username].get('role', 'user')
                                last_activity = time.time()  # Reset timeout clock
                                action_count = 0  # Reset action counter
                            else:
                                user_role = None
                            response = {
                                'status': 'success' if success else 'error',
                                'message': msg,
                                'role': user_role
                            }
                            self.log_event(
                                event=f"COMMAND_{command}",
                                username=current_user,
                                outcome=response.get('status'),
                                details=str(message)
                            )
                        
                        elif command == 'SEND_MESSAGE':
                            if not current_user:
                                response = {'status': 'error', 'message': 'Not logged in'}
                                self.log_event(
                                    event="SEND_MESSAGE",
                                    username=None,
                                    outcome="DENIED",
                                    details="Attempted to send message while not logged in"
                                )
                            else:
                                recipient = message.get('recipient')
                                # For E2EE, we now receive encrypted message components
                                nonce = message.get('nonce')  # Base64 encoded
                                ciphertext = message.get('ciphertext')  # Base64 encoded
        
                                # Validate we have all required fields
                                if not recipient or not nonce or not ciphertext:
                                    response = {'status': 'error', 'message': 'Missing required fields'}
                                else:
                                    # Send message to recipient if they're online
                                    if recipient in self.active_connections:
                                        msg_data = {
                                            'type': 'MESSAGE',
                                            'from': current_user,
                                            'nonce': nonce,
                                            'ciphertext': ciphertext,
                                            'timestamp': datetime.now().isoformat()
                                        }
                                        try:
                                            self.active_connections[recipient].send(
                                                json.dumps(msg_data).encode('utf-8')
                                            )
                                            response = {'status': 'success', 'message': 'Message sent'}
                                            self.log_event(
                                                event="SEND_MESSAGE",
                                                username=current_user,
                                                outcome="SUCCESS",
                                                details=f"Message sent to {recipient}"
                                            )
                                        except:
                                                # Remove inactive connection
                                                del self.active_connections[recipient]
                                                response = {'status': 'error', 'message': 'Recipient is offline'}
                                    else:
                                        response = {'status': 'error', 'message': 'Recipient is offline'}
                                print(f"[SERVER] Relaying encrypted message from {current_user} to {recipient}")
                                print(f"[SERVER] Message content (encrypted): nonce={nonce[:10]}..., ciphertext={ciphertext[:20]}...")
                                print(f"[SERVER] Server CANNOT decrypt this message - no access to keys")
                               
                                self.log_encrypted_message(current_user, recipient, nonce, ciphertext)
                    
                        elif command == 'RESET_PASSWORD':
                            # Support both logged-in and not-logged-in admin
                            if current_user and self.users.get(current_user, {}).get('role') == 'admin':
                                # Optionally require re-authentication here for extra security
                                username = message.get('username')
                                new_password = message.get('new_password')
                                success, msg = self.reset_password(username, new_password)
                                response = {'status': 'success' if success else 'error', 'message': msg}
                                self.log_event(
                                    event="RESET_PASSWORD",
                                    username=current_user,
                                    outcome="AUTHORIZED" if success else "DENIED",
                                    details=f"Reset password for {username}" if success else msg
                                )
                            else:
                                # Not logged in: require admin credentials in the message
                                admin_username = message.get('admin_username')
                                admin_password = message.get('admin_password')
                                admin_totp = message.get('admin_totp')
                                username = message.get('username')
                                new_password = message.get('new_password')
                                # Authenticate admin
                                if not admin_username or self.users.get(admin_username, {}).get('role') != 'admin':
                                    response = {'status': 'error', 'message': 'Admin only'}
                                    self.log_event(
                                        event="RESET_PASSWORD",
                                        username=admin_username,
                                        outcome="DENIED",
                                        details="Non-admin attempted password reset"
                                    )
                                else:
                                    success, msg = self.authenticate(admin_username, admin_password, admin_totp)
                                    if not success:
                                        #Logging for failed admin authentication over 3 attempts
                                        self.failed_logins[admin_username] += 1
                                        if self.failed_logins[admin_username] >= 3:
                                            print(f"WARNING: 3 failed admin login attempts for user {admin_username}")
                                            self.log_event(
                                                event="ALERT_FAILED_LOGINS",
                                                username=admin_username,
                                                outcome="WARNING",
                                                details="3 failed admin login attempts for password reset"
                                                )
                                            response = {'status': 'error', 'message': 'Admin authentication failed'}
                                        else:
                                            self.failed_logins[admin_username] = 0  # Reset on success
                                            success, msg = self.reset_password(username, new_password)
                                            response = {'status': 'success' if success else 'error', 'message': msg}
                                    conn.send(json.dumps(response).encode('utf-8'))
                                    continue
                        
                        elif command == 'CHANGE_PASSWORD':
                            if not current_user:
                                response = {'status': 'error', 'message': 'Not logged in'}
                            else:
                                old_password = message.get('old_password')
                                new_password = message.get('new_password')
                                totp_code = message.get('totp_code')
                                # Authenticate with either password or TOTP
                                user = self.users[current_user]
                                password_ok = False
                                totp_ok = False
                                if old_password:
                                    password_ok, _ = self.authenticate(current_user, old_password, None)
                                if totp_code:
                                    totp_secret = self.decrypt_totp_secret(user['totp_secret'])
                                    totp = pyotp.TOTP(totp_secret)
                                    totp_ok = totp.verify(totp_code, valid_window=1)
                                if not (password_ok or totp_ok):
                                    response = {'status': 'error', 'message': 'Authentication failed: must provide correct password or TOTP'}
                                    self.log_event(
                                        event="CHANGE_PASSWORD",
                                        username=current_user,
                                        outcome="DENIED",
                                        details="Failed authentication for password change"
                                    )
                                else:
                                    success, msg = self.reset_password(current_user, new_password)
                                    response = {'status': 'success' if success else 'error', 'message': msg}
                                    self.log_event(
                                        event="CHANGE_PASSWORD",
                                        username=current_user,
                                        outcome="AUTHORIZED" if success else "DENIED",
                                        details="Password changed" if success else msg
                                    )
                            conn.send(json.dumps(response).encode('utf-8'))
                            continue
                        
                        elif command == 'LIST_USERS':
                            if not current_user:
                                response = {'status': 'error', 'message': 'Not logged in'}
                            elif self.users[current_user].get('role') != 'admin':
                                response = {'status': 'error', 'message': 'Admin only'}
                                self.log_event(
                                    event="LIST_USERS",
                                    username=current_user,
                                    outcome="DENIED",
                                    details="Non-admin attempted to list users"
                                )
                            else:
                                online_users = list(self.active_connections.keys())
                                all_users = list(self.users.keys())
                                response = {
                                    'status': 'success', 
                                    'online_users': online_users,
                                    'all_users': all_users
                                }
                                self.log_event(
                                    event=f"COMMAND_{command}",
                                    username=current_user,
                                    outcome=response.get('status'),
                                    details=str(message)
                                )
                        #Handling Github Login Command
                        elif command == 'COMMAND_MSG':
                            if not current_user:
                                response = {'status': 'error', 'message': 'Not logged in'}
                            else:
                                cmd_msg = message.get('command_msg')
                                mac = message.get('mac')
                                response = self.handle_command_message(current_user, cmd_msg, mac)
                                self.log_event(
                                    event=f"COMMAND_{command}",
                                    username=current_user,
                                    outcome=response.get('status'),
                                    details=str(message)
                                )   

                        elif command == 'GITHUB_LOGIN':
                            github_username = message.get('github_username')
                            github_email = message.get('github_email')
                            # Try to find a local user by email
                            matched_user = None
                            for uname, udata in self.users.items():
                                if udata.get('email') == github_email:
                                    matched_user = uname
                                    break
                            if matched_user:
                                # Link GitHub account to existing user
                                self.users[matched_user]['github_username'] = github_username
                                self.save_users()
                                current_user = matched_user
                                last_activity = time.time()  # Reset timeout clock
                                action_count = 0  # Reset action counter
                                response = {'status': 'success', 'message': f"Logged in as {matched_user} (linked to GitHub {github_username})"}
                                self.log_event(
                                    event="OAUTH_LOGIN",
                                    username=matched_user,
                                    outcome="SUCCESS",
                                    details=f"GitHub login for {github_username} ({github_email})"
                                )
                            else:
                                # Create new user with GitHub info and handle any conflicts here
                                new_username = github_username
                                suggestion_count = 1
                                while new_username in self.users:
                                    new_username = f"{github_username}_{suggestion_count}"
                                    suggestion_count += 1
                                if new_username != github_username:
                                    response = {
                                    'status': 'warning',
                                    'message': f"Username '{github_username}' is taken. You have been assigned '{new_username}'."
                                    }
                                    self.log_event(
                                        event="OAUTH_LOGIN",
                                        username=new_username,
                                        outcome="WARNING",
                                        details=f"GitHub username taken, assigned {new_username} for {github_email}"
                                    )       
                                else:
                                    response = {
                                        'status': 'success',
                                        'message': f"New account created and logged in as {new_username} (GitHub)"
                                }
                                self.log_event(
                                    event="OAUTH_LOGIN",
                                    username=new_username,
                                    outcome="SUCCESS",
                                    details=f"New GitHub account {github_username} ({github_email})"
                                )
                                self.users[new_username] = {
                                'github_username': github_username,
                                'email': github_email,
                                'created_at': datetime.now().isoformat(),
                                'auth_type': 'github'
                                }
                                self.save_users()
                                current_user = new_username
                                response = {'status': 'success', 'message': f"New account created and logged in as {new_username} (GitHub)"}

                        elif command == 'CR_CHALLENGE':
                            username = message.get('username')
                            if username not in self.users:
                                response = {'status': 'error', 'message': 'Unknown user'}
                            else:
                                import secrets
                                challenge = secrets.token_hex(16)
                                cr_challenges[username] = challenge
                                response = {'status': 'ok', 'challenge': challenge}

                        elif command == 'CR_RESPONSE':
                            username = message.get('username')
                            client_mac = message.get('mac')
                            challenge = cr_challenges.get(username)
                            success = False
                            if not challenge:
                                response = {'status': 'error', 'message': 'No challenge issued'}
                            else:
                                # Use a shared secret for demo (insecure in real life!)
                                SHARED_KEY = "SecretKey123"
                                expected_mac = self.compute_mac(SHARED_KEY, challenge)
                                if hmac.compare_digest(client_mac, expected_mac):
                                    current_user = username
                                    last_activity = time.time()  # Reset timeout clock
                                    action_count = 0  # Reset action counter
                                    self.active_connections[username] = conn
                                    response = {'status': 'success', 'message': 'Challenge-response login successful'}
                                else:
                                    response = {'status': 'error', 'message': 'Invalid response'}
                                    success = False
                                del cr_challenges[username]
                            if not success:
                                self.failed_logins[username] += 1
                                if self.failed_logins[username] >= 3:
                                    print(f"WARNING: 3 failed login attempts for user {username}")
                                    self.log_event(
                                        event="ALERT_FAILED_LOGINS",
                                        username=username,
                                        outcome="WARNING",
                                        details="3 failed login attempts"
                                    )
                                else:
                                    self.failed_logins[username] = 0
                        
                        elif command == 'STORE_PUBLIC_KEY':
                            if not current_user:
                                response = {'status': 'error', 'message': 'Not logged in'}
                                self.log_event(
                                    event="STORE_PUBLIC_KEY",
                                    username=None, 
                                    outcome="DENIED",
                                    details="Attempted to store public key while not logged in"
                                )
                            else:
                                public_key = message.get('public_key')
                                if not public_key:
                                    response = {'status': 'error', 'message': 'No public key provided'}
                                else:
                                    # Store the public key in the user's record
                                    self.users[current_user]['public_key'] = public_key
                                    self.save_users()
                                    response = {'status': 'success', 'message': 'Public key stored'}
                                    self.log_event(
                                        event="STORE_PUBLIC_KEY",
                                        username=current_user,
                                        outcome="SUCCESS",
                                        details="Public key stored"
                                    )
                        elif command == 'GET_PUBLIC_KEY':
                            if not current_user:
                                response = {'status': 'error', 'message': 'Not logged in'}
                                self.log_event(
                                    event="GET_PUBLIC_KEY",
                                    username=None,
                                    outcome="DENIED", 
                                    details="Attempted to get public key while not logged in"
                                )
                            else:
                                target_user = message.get('username')
                                if not target_user or target_user not in self.users:
                                    response = {'status': 'error', 'message': 'User not found'}
                                elif 'public_key' not in self.users[target_user]:
                                    response = {'status': 'error', 'message': 'User has no public key'}
                                else:
                                    response = {
                                        'status': 'success',
                                        'username': target_user,
                                        'public_key': self.users[target_user]['public_key']
                                    }
                                    self.log_event(
                                        event="GET_PUBLIC_KEY", 
                                        username=current_user,
                                        outcome="SUCCESS",
                                        details=f"Retrieved {target_user}'s public key"
                                    )
                    
                        conn.send(json.dumps(response).encode('utf-8'))
                    
                    except json.JSONDecodeError:
                            error_response = {'status': 'error', 'message': 'Invalid JSON'}
                            conn.send(json.dumps(error_response).encode('utf-8'))
                except socket.timeout:
                    # No data received, just loop and check timeout again
                    continue    
        except ConnectionResetError:
            pass
        finally:
            # Clean up connection
            if current_user and current_user in self.active_connections:
                del self.active_connections[current_user]
            conn.close()
            print(f"Connection from {addr} closed")
        
    
    def start_server(self):
        """Start the TCP server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"SecureText Server started on {self.host}:{self.port}")
            print("Waiting for connections...")
            
            while True:
                conn, addr = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\nServer shutting down...")
        finally:
            if self.server_socket:
                self.server_socket.close()

    def test_hash_performance(self, password, iterations=1000):
        """Test hashing performance"""
        # Test SHA-256
        start_time = time.time()
        for _ in range(iterations):
            self.hash_password_sha256(password)
        sha256_time = time.time() - start_time
    
        # Test PBKDF2
        pbkdf2_iterations = 10  # Reduce iterations needed
        start_time = time.time()
        for _ in range(pbkdf2_iterations):
            self.hash_password_pbkdf2(password, iterations=100000)
        pbkdf2_time = time.time() - start_time
    
        print("\nHash Performance Comparison:")
        print(f"\nSHA-256 Results:")
        print(f"- {iterations:,} iterations")
        print(f"- Total time: {sha256_time:.4f} seconds")
        print(f"- Average time per hash: {(sha256_time/iterations)*1000:.4f} ms")
    
        print(f"\nPBKDF2 Results:")
        print(f"- {pbkdf2_iterations:,} iterations")
        print(f"- Total time: {pbkdf2_time:.4f} seconds")
        print(f"- Average time per hash: {(pbkdf2_time/pbkdf2_iterations)*1000:.4f} ms")
        print(f"- Slowdown factor: {((pbkdf2_time/pbkdf2_iterations)/(sha256_time/iterations)):.1f}x")
    
    def verify_password_pbkdf2(self, password, stored_hash_data):
        """Verify a password against stored PBKDF2 hash"""
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            base64.b64decode(stored_hash_data['salt']),
            stored_hash_data['iterations']
        )
        return base64.b64encode(key).decode('utf-8') == stored_hash_data['hash']
    
    def compute_mac(self, key, message):
        """Compute secure MAC using HMAC-SHA256"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        return hmac.new(key.encode('utf-8'), 
                       message,
                       hashlib.sha256).hexdigest()

    def verify_mac(self, key, message, received_mac):
        """Verify MAC - intentionally vulnerable to length extension"""
        try:
            
            if isinstance(message, str):
                message = message.encode('utf8')
            else:
                message = message
            
            computed_mac = self.compute_mac(key, message)
            
            # Use constant-time comparison
            return hmac.compare_digest(computed_mac, received_mac)
        except Exception as e:
            print(f"MAC verification error: {e}")
            return False

    def process_command_message(self, message, mac_key):
        """Process command messages with MAC verification"""
        try:
            # Extract command parts
            cmd_parts = message.split('&')
            cmd_dict = {}
            for part in cmd_parts:
                key, value = part.split('=')
                cmd_dict[key] = value
        
            # Verify command has required fields
            if 'CMD' not in cmd_dict:
                return False, "Missing CMD field"
            
            return True, cmd_dict
        except:
            return False, "Invalid command format"

    def handle_command_message(self, current_user, command_msg, mac):
        """Handle command messages with MAC verification"""
        # Simple shared key
        MAC_KEY = "SecretKey123"

        # Verify MAC first
        if not self.verify_mac(MAC_KEY, command_msg, mac):
            return {'status': 'error', 'message': 'Invalid MAC'}

        # Process command
        success, result = self.process_command_message(command_msg, MAC_KEY)
        if not success:
            return {'status': 'error', 'message': result}

        cmd_dict = result
        command = cmd_dict['CMD']

        # Handle different commands
        if command == 'SET_QUOTA':
            if 'USER' not in cmd_dict or 'LIMIT' not in cmd_dict:
                return {'status': 'error', 'message': 'Missing USER or LIMIT'}
            # Process quota setting
            return {'status': 'success', 'message': f"Set quota {cmd_dict['LIMIT']} for user {cmd_dict['USER']}"}
        
        elif command == 'GRANT_ADMIN':
            target_user = cmd_dict.get('username')
            password = cmd_dict.get('password')
            totp_code = cmd_dict.get('totp_code')
            if not current_user or self.users[current_user].get('role') != 'admin':
                response = {'status': 'error', 'message': 'Admin only'}
            elif target_user not in self.users:
                response = {'status': 'error', 'message': 'User not found'}
            else:
                # Re-authenticate admin
                success, msg = self.authenticate(current_user, password, totp_code)
                self.log_event(
                event="AUTH_ATTEMPT",
                username=current_user,
                outcome="SUCCESS" if success else "FAIL",
                details=msg
                )
                if not success:
                    response = {'status': 'error', 'message': 'Re-authentication failed'}
                else:
                    self.users[target_user]['role'] = 'admin'
                    self.save_users()
                    response = {'status': 'success', 'message': f"{target_user} is now an admin."}

        return {'status': 'error', 'message': 'Unknown command'}

    #Added for logging encrypted messages as a demo of E2EE
    def log_encrypted_message(self, sender, recipient, nonce, ciphertext):
        """Log encrypted messages to a file for demonstration"""
        with open('encrypted_messages.log', 'a') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] FROM:{sender} TO:{recipient}\n")
            f.write(f"NONCE: {nonce[:10]}...\n")
            f.write(f"CIPHERTEXT: {ciphertext[:30]}...\n\n")

class SecureTextClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        self.logged_in = False
        self.username = None
        self.running = False
        self.oauth_logged_in = False # Flag to indicate if user is logged in via OAuth
        self.access_token = None # Access token for OAuth authentication
        # For end-to-end encryption
        self.private_key = None
        self.public_key = None
        self.peer_keys = {}  # username -> public key
    
        # Session management
        self.last_activity = time.time()
        self.session_timeout = 300#30 * 60  # 30 minutes
        self.warning_threshold = 120#25 * 60  # 25 minutes (5-min warning)
        
    def connect(self):
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            return True
        except ConnectionRefusedError:
            print("Error: Could not connect to server. Make sure the server is running.")
            return False
        except Exception as e:
            print(f"Connection error: {e}")
            return False
        
    def github_login(self):
        """Login using GitHub OAuth"""
        #Hardcoded GitHub 0Auth Credentials for our demo environment.
        self.logout()  # Ensure any previous session is cleared
        client_id = "GITHUB_CLIENT_ID"
        client_secret = "GITHUB_CLIENT_SECRET"
        if not client_id or not client_secret:
            print("Error: GitHub OAuth client ID/secret not set in environment variables.")
            return
        redirect_uri = "http://localhost"
        state = secrets.token_urlsafe(16)
        scope = "read:user user:email"

        # PKCE: Generate code_verifier and code_challenge
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip("=")

        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "allow_signup": "true",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }
        auth_url = "https://github.com/login/oauth/authorize?" + urllib.parse.urlencode(params)
        print("Opening browser for GitHub login...")
        webbrowser.open(auth_url)
        print("If the browser does not open, please visit this URL manually:")
        print(auth_url)
        redirect_response = input("After logging in, paste the full redirect URL here: ").strip()
        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(redirect_response)
        query_params = parse_qs(parsed_url.query)
        code = query_params.get("code", [None])[0]
        returned_state = query_params.get("state", [None])[0]
        if returned_state != state:
            print("State mismatch! Aborting for security.")
            return
        token_url = "https://github.com/login/oauth/access_token"
        headers = {"Accept": "application/json"}
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_verifier": code_verifier  #PKCE Addition for security
        }
        response = requests.post(token_url, headers=headers, data=data)
        token_json = response.json()
        if "error" in token_json:
            print("OAuth error:", token_json.get("error_description", token_json["error"]))
            return
        access_token = token_json.get("access_token")
        if not access_token:
            print("Failed to get access token.")
            return
        self.access_token = access_token
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/json"
        }
        user_resp = requests.get("https://api.github.com/user", headers=headers)
        user_info = user_resp.json()
        github_username = user_info.get("login")
        email_resp = requests.get("https://api.github.com/user/emails", headers=headers)
        emails = email_resp.json()
        
        primary_email = None
        if isinstance(emails, list):
            for email_entry in emails:
                if isinstance(email_entry, dict) and email_entry.get("primary"):
                    primary_email = email_entry.get("email")
                break
        else:
            print("Could not retrieve email list from GitHub:", emails)
            
        print(f"Authenticated GitHub username: {github_username}")
        print(f"Primary GitHub email: {primary_email}")
        # Send to server for hybrid authentication
        command = {
            'command': 'GITHUB_LOGIN',
            'github_username': github_username,
            'github_email': primary_email
        }
        response = self.send_command(command)
        print(f"{response['message']}")
        if response['status'] == 'success':
            self.logged_in = True
            self.oauth_logged_in = True
            self.username = github_username
            self.role = response.get('role', 'user')
            self.running = True
            # Generate ECDH keys for E2EE
            self.generate_keys()
        
            # Store public key on server
            pub_key = self.serialize_public_key()
            command = {
                'command': 'STORE_PUBLIC_KEY',
                'public_key': pub_key
            }
            response = self.send_command(command)
            if response['status'] != 'success':
                print(f"Warning: {response['message']}")
    
            # Start session monitoring
            session_thread = threading.Thread(target=self.monitor_session)
            session_thread.daemon = True
            session_thread.start()
            listen_thread = threading.Thread(target=self.listen_for_messages)
            listen_thread.daemon = True
            listen_thread.start()

    def challenge_response_login(self):
        print("\n=== Challenge-Response Login ===")
        username = input("Enter username: ").strip()
        # Step 1: Request challenge
        command = {'command': 'CR_CHALLENGE', 'username': username}
        response = self.send_command(command)
        if response['status'] != 'ok':
            print(f"Error: {response['message']}")
            return
        challenge = response['challenge']
        # Step 2: Compute HMAC and send response
        SHARED_KEY = "SecretKey123"
        mac = self.compute_mac(SHARED_KEY, challenge)
        command = {'command': 'CR_RESPONSE', 'username': username, 'mac': mac}
        response = self.send_command(command)
        print(f"{response['message']}")
        if response['status'] == 'success':
            self.logged_in = True
            self.username = username
            self.role = response.get('role', 'user')
            self.running = True
            # Generate ECDH keys for E2EE
            self.generate_keys()
        
            # Store public key on server
            pub_key = self.serialize_public_key()
            command = {
                'command': 'STORE_PUBLIC_KEY',
                'public_key': pub_key
            }
            response = self.send_command(command)
            if response['status'] != 'success':
                print(f"Warning: {response['message']}")
    
            # Start session monitoring
            session_thread = threading.Thread(target=self.monitor_session)
            session_thread.daemon = True
            session_thread.start()
            listen_thread = threading.Thread(target=self.listen_for_messages)
            listen_thread.daemon = True
            listen_thread.start()
    
    def send_command(self, command_data):
        """Send command to server and get response"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self.socket.settimeout(5.0)  # Set 5-second timeout
                self.socket.send(json.dumps(command_data).encode('utf-8'))
                response = self.socket.recv(1024).decode('utf-8')
                self.socket.settimeout(None)  # Reset timeout
                return json.loads(response)
            except Exception as e:
                print(f"Communication error (attempt {attempt+1}/{max_retries}): {e}")
                time.sleep(1)  # Wait before retry
    
        return {'status': 'error', 'message': 'Communication failed after multiple attempts'}
        
    def change_password(self):
        print("\n=== Change Your Password ===")
        old_password = input("Enter your current password (or leave blank to use TOTP): ").strip()
        new_password = input("Enter your new password: ").strip()
        totp_code = ""
        if not old_password:
            totp_code = input("Enter your TOTP code: ").strip()
        command = {
            'command': 'CHANGE_PASSWORD',
            'old_password': old_password,
            'new_password': new_password,
            'totp_code': totp_code
        }
        response = self.send_command(command)
        print(f"{response['message']}")
    
    def grant_admin(self):
        print("\n=== Grant Admin Role ===")
        username = input("Enter username to promote to admin: ").strip()
        password = input("Re-enter your admin password: ").strip()
        totp_code = input("Enter your TOTP code: ").strip()
        command = {
            'command': 'GRANT_ADMIN',
            'username': username,
            'password': password,
            'totp_code': totp_code
        }
        response = self.send_command(command)
        print(f"{response['message']}")
    
    def is_admin(self):
        return getattr(self, 'role', 'user') == 'admin'
    
    def listen_for_messages(self):
        """Listen for incoming messages in a separate thread"""
        while self.running:
            try:
                data = self.socket.recv(1024).decode('utf-8')
                if data:
                    message = json.loads(data)
                    # Check for session timeout
                    if message.get('status') == 'error' and "timed out" in message.get('message', '').lower():
                        print(f"\n[!] Session timed out. Reason: {message.get('message')} Logging out.")
                        self.logout()
                        break
                    
                    if message.get('type') == 'MESSAGE':
                        sender = message['from']
                        self.update_activity()  # Update activity on receiving message
                    
                        # Handle encrypted messages
                        if 'nonce' in message and 'ciphertext' in message:
                            # Get sender's public key if we don't have it
                            if sender not in self.peer_keys:
                                command = {
                                    'command': 'GET_PUBLIC_KEY',
                                    'username': sender
                                }
                                response = self.send_command(command)
                                if response['status'] != 'success':
                                    print(f"\nError receiving message: {response['message']}")
                                    continue
                            
                                sender_public_key = self.deserialize_public_key(response['public_key'])
                                if not sender_public_key:
                                    print("\nError: Invalid public key for sender")
                                    continue
                                
                                self.peer_keys[sender] = sender_public_key
                        
                            # Decrypt the message
                            nonce_b64 = message['nonce']
                            ciphertext_b64 = message['ciphertext']
                            plaintext = self.decrypt_message(sender, nonce_b64, ciphertext_b64)
                        
                            if plaintext:
                                print(f"\n[{message['timestamp']}] {sender}: {plaintext}")
                                print(">> ", end="", flush=True)
                            else:
                                print(f"\nReceived encrypted message from {sender}, but could not decrypt it.")
                                print(">> ", end="", flush=True)
                        else:
                            # Legacy plaintext messages
                            print(f"\n[{message['timestamp']}] {sender}: {message['content']}")
                            print(">> ", end="", flush=True)
            except Exception as e:
                if self.running:  # Only log errors if we're supposed to be running
                    print(f"\nError listening for messages: {e}")
                    break
    
    def create_account(self):
        """Create a new account"""
        print("\n=== Create Account ===")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        
        if not username or not password:
            print("Username and password cannot be empty!")
            return
        
        command = {
            'command': 'CREATE_ACCOUNT',
            'username': username,
            'password': password
        }
        
        response = self.send_command(command)
        print(f"{response['message']}")
        if response.get('totp_secret'):
            print(f"\n[2FA] Add this secret to your authenticator app: {response['totp_secret']}")
            print(f"Or scan this URI with your authenticator app: {response['totp_uri']}")
            # Optionally, display QR code in client (requires qrcode lib on client side)
            try:
                import qrcode
                qr = qrcode.QRCode()
                qr.add_data(response['totp_uri'])
                qr.make(fit=True)
                qr.print_ascii(invert=True)
            except Exception:
                print("(Install 'qrcode' Python package to see QR code in terminal.)")
    
    def login(self):
        """Login to the system"""
        print("\n=== Login ===")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        # Show the current time step (challenge) for TOTP
        current_time_step = int(time.time() / 30)
        print(f"TOTP challenge (time step): {current_time_step}")
        totp_code = input("Enter Time-based One-time password code from authenticator app: ").strip()
        
        command = {
            'command': 'LOGIN',
            'username': username,
            'password': password,
            'totp_code': totp_code
        }
        
        response = self.send_command(command)
        print(f"{response['message']}")
        
        if response['status'] == 'success':
            self.logged_in = True
            self.username = username
            self.role = response.get('role', 'user')
            self.running = True
            self.update_activity()  # Initialize activity tracking
        
            # Generate ECDH keys for E2EE
            self.generate_keys()
        
            # Store public key on server
            pub_key = self.serialize_public_key()
            command = {
                'command': 'STORE_PUBLIC_KEY',
                'public_key': pub_key
            }
            response = self.send_command(command)
            if response['status'] != 'success':
                print(f"Warning: {response['message']}")
        
            # Start listening for messages
            listen_thread = threading.Thread(target=self.listen_for_messages)
            listen_thread.daemon = True
            listen_thread.start()
        
            # Start session monitoring
            session_thread = threading.Thread(target=self.monitor_session)
            session_thread.daemon = True
            session_thread.start()
    
    def send_message(self):
        """Send an encrypted message to another user"""
        if not self.logged_in:
            print("You must be logged in to send messages!")
            return
    
        # Check session before continuing
        if not self.check_session():
            return
        
        self.update_activity()
    
        print("\n=== Send Encrypted Message ===")
        recipient = input("Enter recipient username: ").strip()
        # Check if this is a GitHub user with a suffix
        command = {
            'command': 'LIST_USERS',
        }
        response = self.send_command(command)
        all_users = response.get('all_users', [])
    
        # Check if we're trying to message a GitHub user
        if recipient not in all_users:
            # Look for username with suffix
            for username in all_users:
                if username.startswith(recipient + '_'):
                    print(f"Note: Using {username} instead of {recipient} (GitHub account)")
                    recipient = username
                    break
        content = input("Enter message: ").strip()
    
        if not recipient or not content:
            print("Recipient and message cannot be empty!")
            return
    
        # Get recipient's public key
        if recipient not in self.peer_keys:
            command = {
                'command': 'GET_PUBLIC_KEY',
                'username': recipient
            }
            print(f"[DEBUG] Fetching {recipient}'s public key for encryption...")
            response = self.send_command(command)
            if response['status'] != 'success':
                print(f"Error: {response['message']}")
                return
        
            recipient_public_key = self.deserialize_public_key(response['public_key'])
            if not recipient_public_key:
                print("Error: Invalid public key for recipient")
                return
            
            self.peer_keys[recipient] = recipient_public_key
            print(f"[DEBUG] Successfully retrieved {recipient}'s public key")

        # Encrypt the message
        print(f"[DEBUG] Encrypting message with AES-256-GCM...")
        nonce_b64, ciphertext_b64 = self.encrypt_message(recipient, content)
        if not nonce_b64 or not ciphertext_b64:
            print("Error: Could not encrypt message")
            return
    
        # Send the encrypted message
        command = {
            'command': 'SEND_MESSAGE',
            'recipient': recipient,
            'nonce': nonce_b64,
            'ciphertext': ciphertext_b64
        }
    
        response = self.send_command(command)
        print(f"{response['message']}")
        

    def list_users(self):
        """List all users and show who's online"""
        if not self.logged_in:
            print("You must be logged in to list users!")
            return
        
        command = {'command': 'LIST_USERS'}
        response = self.send_command(command)
        
        if response['status'] == 'success':
            print(f"\nOnline users: {', '.join(response['online_users'])}")
            print(f"All users: {', '.join(response['all_users'])}")
        else:
            print(f"Error: {response['message']}")
    
    def reset_password(self):
        print("\n=== Reset Password ===")
        username = input("Enter username to reset: ").strip()
        new_password = input("Enter new password: ").strip()
        if self.logged_in and self.is_admin():
            # Use current session
            command = {
                'command': 'RESET_PASSWORD',
                'username': username,
                'new_password': new_password
            }
        else:
            # Prompt for admin credentials
            admin_username = input("Enter your admin username: ").strip()
            admin_password = input("Enter your admin password: ").strip()
            admin_totp = input("Enter your TOTP code: ").strip()
            command = {
                'command': 'RESET_PASSWORD',
                'username': username,
                'new_password': new_password,
                'admin_username': admin_username,
                'admin_password': admin_password,
                'admin_totp': admin_totp
            }
        response = self.send_command(command)
        print(f"{response['message']}")
    
    def logout(self):
        self.logged_in = False
        self.running = False
        self.username = None
        self.oauth_logged_in = False   # Reset OAuth login state
        self.access_token = None       # Reset access token
        print("Logged out successfully")
    
    def run(self):
        """Main client loop"""
        if not self.connect():
            return
        
        print("=== SecureText Messenger (Insecure Version) ===")
        print("WARNING: This is an intentionally insecure implementation for educational purposes!")
        
        while True:

            if self.logged_in and not self.running:
                print("\n[!] Session ended (timed out or disconnected). Returning to login menu.")
                self.logged_in = False
                self.username = None
                self.role = 'user'
                self.oauth_logged_in = False
                self.access_token = None
            
            if not self.logged_in:
                print("\n1. Create Account")
                print("2. Login")
                print("3. Login with GitHub")
                print("4. Challenge-Response Login")  # <-- Add this
                print("5. Reset Password")
                print("6. Exit")
                choice = input("Choose an option: ").strip()
                
                if choice == '1':
                    self.create_account()
                elif choice == '2':
                    self.login()
                elif choice == '3':
                    self.github_login()
                elif choice == '4':
                    self.challenge_response_login()
                elif choice == '5':
                    self.reset_password()
                elif choice == '6':
                    break
                else:
                    print("Invalid choice!")
            else:
                print(f"\nLogged in as: {self.username}")
                print("1. Send Message")
                print("2. List Users")
                print("3. Send Command Message")
                print("4. Logout")
                print("5. Change Password")
                if self.logged_in and self.is_admin():
                    print("6. Grant Admin Role")
                choice = input("Choose an option (or just press Enter to wait for messages): ").strip()
                
                if choice == '1':
                    self.send_message()
                elif choice == '2':
                    self.list_users()
                elif choice == '3':
                    self.send_command_message()
                elif choice == '4':
                    self.logout()
                elif choice == '5':
                    self.change_password()
                elif choice == '6' and self.is_admin():
                    self.grant_admin()
                elif choice == '':
                    # Just wait for messages
                    print("Waiting for messages... (press Enter to show menu)")
                    input()
                else:
                    print("Invalid choice!")
        
        if self.socket:
            self.socket.close()
        print("Goodbye!")


    def compute_mac(self, key, message):
        """Compute secure MAC using HMAC-SHA256"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        return hmac.new(key.encode('utf-8'), 
                    message,
                    hashlib.sha256).hexdigest()


    def send_command_message(self):
        """Send a command message with MAC"""
        if not self.logged_in:
            print("You must be logged in to send commands!")
            return

        print("\n=== Send Command ===")
        command_msg = input("Enter command: ").strip()
        
        # Simple shared key
        MAC_KEY = "SecretKey123"
        
        # Compute MAC
        mac = self.compute_mac(MAC_KEY, command_msg)
        
        command = {
            'command': 'COMMAND_MSG',
            'command_msg': command_msg,
            'mac': mac
        }

        response = self.send_command(command)
        print(f"\nServer response: {response['message']}")

    def generate_keys(self):
        """Generate ECDH key pair using P-256 curve"""
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        print("[+] Generated new ECDH key pair")
    
    def serialize_public_key(self):
        """Serialize public key for transmission"""
        if not self.public_key:
            return None
    
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_bytes).decode('utf-8')

    def deserialize_public_key(self, public_key_b64):
        """Deserialize received public key"""
        if not public_key_b64:
            return None
        
        try:
            public_bytes = base64.b64decode(public_key_b64)
            peer_public_key = serialization.load_pem_public_key(public_bytes)
            return peer_public_key
        except Exception as e:
            print(f"Error deserializing public key: {e}")
            return None

    def derive_shared_key(self, other_user):
        """Derive shared key using ECDH and HKDF-SHA256"""
        if not self.private_key or other_user not in self.peer_keys:
            return None

        try:
            # Normalize self username if it's a GitHub user
            normalized_self = self.username
            if self.oauth_logged_in and '_' in self.username:
                normalized_self = self.username.split('_')[0]
            
            # Normalize other username if it has an underscore (GitHub user)
            normalized_other = other_user
            if '_' in other_user:
                normalized_other = other_user.split('_')[0]
            
            # Get other user's public key
            peer_public_key = self.peer_keys[other_user]
        
            # Perform ECDH key exchange
            shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        
            # Use normalized usernames for key derivation
            usernames = sorted([normalized_self, normalized_other])
            info = f"SecureText-{usernames[0]}-{usernames[1]}".encode('utf-8')
        
            print(f"[DEBUG] Using info string for key derivation: '{info.decode()}'")
        
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits for AES-256
                salt=None,
                info=info
            ).derive(shared_secret)
            print(f"[CRYPTO] Derived {len(derived_key)*8}-bit AES key using ECDH with {other_user}")
            return derived_key
        except Exception as e:
            print(f"Error deriving shared key: {e}")
            return None
        
    def encrypt_message(self, recipient, plaintext):
        """Encrypt message using AES-256-GCM"""
        # Update activity timestamp
        self.update_activity()
    
        # Derive key for this recipient
        key = self.derive_shared_key(recipient)
        if not key:
            return None, None
    
        try:
            # Create AES-GCM cipher
            aesgcm = AESGCM(key)
        
            # Generate a unique 96-bit nonce for each message
            nonce = os.urandom(12)
            print(f"[CRYPTO] Generated unique {len(nonce)*8}-bit nonce for this message")
            # Encrypt with associated data (AD) for integrity
            # AD contains sender and recipient to prevent replay attacks
            normalized_sender = self.username
            if self.oauth_logged_in:
                # Use just the GitHub username part without suffix
                normalized_sender = normalized_sender.split('_')[0]
            ad = f"{normalized_sender}:{recipient}".encode('utf-8')
        
            # Encrypt the plaintext
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), ad)
            print(f"[CRYPTO] Message encrypted with AES-256-GCM and authenticated with sender-recipient IDs")
            print(f"[DEBUG] Using AD for encryption: '{normalized_sender}:{recipient}'")
            # Return base64 encoded nonce and ciphertext
            return base64.b64encode(nonce).decode('utf-8'), base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            return None, None

    def decrypt_message(self, sender, nonce_b64, ciphertext_b64):
        """Decrypt message using AES-256-GCM"""
        #For key exchange display/ debug
        print(f"[DEBUG] Attempting to decrypt message from {sender}")
        print(f"[DEBUG] Do I have {sender}'s key? {'Yes' if sender in self.peer_keys else 'No'}")
        # Update activity timestamp
        self.update_activity()

        # Normalize sender name if it's a GitHub user
        normalized_sender = sender
        if '_' in sender:  # Likely a GitHub user
            normalized_sender = sender.split('_')[0]

        # Derive key for this sender
        key = self.derive_shared_key(sender)
        if not key:
            return None
    
        try:
            # Decode nonce and ciphertext from base64
            nonce = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
        
            # Create AES-GCM cipher
            aesgcm = AESGCM(key)
        
            # Use the normalized sender name for AD
            ad = f"{normalized_sender}:{self.username}".encode('utf-8')
            print(f"[DEBUG] Using AD for decryption: '{normalized_sender}:{self.username}'")
        
            # Decrypt the ciphertext
            plaintext = aesgcm.decrypt(nonce, ciphertext, ad)

            #Integrity check for demonstration purposes
            print(f"[SECURITY] Message integrity verified using AES-GCM authentication")
            return plaintext.decode('utf-8')
        except InvalidTag:
            print(f"[SECURITY] INTEGRITY VIOLATION! Message has been tampered with or corrupted.")
            return None
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()
        remaining = self.session_timeout - (time.time() - self.last_activity)
        print(f"[SESSION] Activity detected! Session valid for {int(remaining/60)}m {int(remaining%60)}s")

    def check_session(self):
        """Check if session is about to expire or has expired"""
        if not self.logged_in:
            return True
        
        now = time.time()
        elapsed = now - self.last_activity
    
        # Session expired
        if elapsed > self.session_timeout:
            print("\n[!] Session expired. Please log in again.")
            self.logout(expired=True)
            return False
    
        # Warning before expiration
        if elapsed > self.warning_threshold:
            remaining = self.session_timeout - elapsed
            print(f"\n[!] Warning: Session will expire in {int(remaining/60)} minutes and {int(remaining%60)} seconds.")
    
        return True

    def monitor_session(self):
        """Periodically monitor session status"""
        while self.running:
            self.check_session()
            time.sleep(60)  # Check every minute
        
    def logout(self, expired=False):
        """Securely logout and clean up sensitive material"""
        # Secure cleanup of cryptographic material
        self.private_key = None
        self.public_key = None
        self.peer_keys.clear()
    
        # Reset session state
        self.logged_in = False
        self.running = False
        self.username = None
        self.oauth_logged_in = False
        self.access_token = None
    
        if not expired:
            print("Logged out successfully")
    
        # Force garbage collection to clear sensitive data from memory
        import gc
        gc.collect()

def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        server = SecureTextServer()
        print("\nTesting hash implementations...")
        test_password = "MySecurePassword123"
        
        # Test SHA-256
        sha256_start = time.time()
        sha256_hash = server.hash_password_sha256(test_password)
        sha256_time = time.time() - sha256_start
        
        # Test PBKDF2
        pbkdf2_start = time.time()
        pbkdf2_hash = server.hash_password_pbkdf2(test_password)
        pbkdf2_time = time.time() - pbkdf2_start
        
        print(f"\nSingle Hash Timing:")
        print(f"SHA-256: {sha256_time*1000:.2f}ms")
        print(f"PBKDF2:  {pbkdf2_time*1000:.2f}ms")
        # Test hash performance
        server.test_hash_performance("test_password")
        server.start_server()
    else:
        # Run as client
        client = SecureTextClient()
        client.run()

if __name__ == "__main__":
    main()
