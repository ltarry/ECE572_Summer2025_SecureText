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
import requests
import hmac
import pyotp
import collections
import qrcode
from cryptography.fernet import Fernet
from datetime import datetime
from urllib.parse import urlparse, parse_qs

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
            'reset_answer': 'blue'
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
        
        try:
            while True:
                data = conn.recv(1024).decode('latin1')
                if not data:
                    break
                
                try:
                    message = json.loads(data)
                    command = message.get('command')
                    
                    if command == 'CREATE_ACCOUNT':
                        username = message.get('username')
                        password = message.get('password')
                        success, msg, totp_secret, totp_uri = self.create_account(username, password)
                        response = {'status': 'success' if success else 'error', 'message': msg}
                        if success:
                            response['totp_secret'] = totp_secret
                            response['totp_uri'] = totp_uri
                        
                    elif command == 'LOGIN':
                        username = message.get('username')
                        password = message.get('password')
                        totp_code = message.get('totp_code')
                        success, msg = self.authenticate(username, password, totp_code)
                        if success:
                            current_user = username
                            self.active_connections[username] = conn
                        response = {'status': 'success' if success else 'error', 'message': msg}
                        
                    elif command == 'SEND_MESSAGE':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        else:
                            recipient = message.get('recipient')
                            msg_content = message.get('content')
                            
                            # Send message to recipient if they're online
                            if recipient in self.active_connections:
                                msg_data = {
                                    'type': 'MESSAGE',
                                    'from': current_user,
                                    'content': msg_content,
                                    'timestamp': datetime.now().isoformat()
                                }
                                try:
                                    self.active_connections[recipient].send(
                                        json.dumps(msg_data).encode('utf-8')
                                    )
                                    response = {'status': 'success', 'message': 'Message sent'}
                                except:
                                    # Remove inactive connection
                                    del self.active_connections[recipient]
                                    response = {'status': 'error', 'message': 'Recipient is offline'}
                            else:
                                response = {'status': 'error', 'message': 'Recipient is offline'}
                    
                    elif command == 'RESET_PASSWORD':
                        username = message.get('username')
                        new_password = message.get('new_password')
                        success, msg = self.reset_password(username, new_password)
                        response = {'status': 'success' if success else 'error', 'message': msg}
                        
                    elif command == 'LIST_USERS':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        else:
                            online_users = list(self.active_connections.keys())
                            all_users = list(self.users.keys())
                            response = {
                                'status': 'success', 
                                'online_users': online_users,
                                'all_users': all_users
                            }
                    #Handling Github Login Command
                    elif command == 'COMMAND_MSG':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        else:
                            cmd_msg = message.get('command_msg')
                            mac = message.get('mac')
                            response = self.handle_command_message(current_user, cmd_msg, mac)

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
                            response = {'status': 'success', 'message': f"Logged in as {matched_user} (linked to GitHub {github_username})"}
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
                            else:
                                response = {
                                    'status': 'success',
                                    'message': f"New account created and logged in as {new_username} (GitHub)"
                            }
                            self.users[new_username] = {
                            'github_username': github_username,
                            'email': github_email,
                            'created_at': datetime.now().isoformat(),
                            'auth_type': 'github'
                            }
                            self.save_users()
                            current_user = new_username
                            response = {'status': 'success', 'message': f"New account created and logged in as {new_username} (GitHub)"}
                    else:
                        response = {'status': 'error', 'message': 'Unknown command'}
                    
                    conn.send(json.dumps(response).encode('utf-8'))
                    
                except json.JSONDecodeError:
                    error_response = {'status': 'error', 'message': 'Invalid JSON'}
                    conn.send(json.dumps(error_response).encode('utf-8'))
                    
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
            if 'USER' not in cmd_dict:
                return {'status': 'error', 'message': 'Missing USER'}
            # Process admin grant
            return {'status': 'success', 'message': f"Granted admin privileges to user {cmd_dict['USER']}"}

        return {'status': 'error', 'message': 'Unknown command'}

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
        client_id = "Ov23liKAGQ5DVCq4cMlJ"
        client_secret = "821ba2e2fba93c6b3825a7045580d141f6e8942a"
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
            self.running = True
            listen_thread = threading.Thread(target=self.listen_for_messages)
            listen_thread.daemon = True
            listen_thread.start()
    
    def send_command(self, command_data):
        """Send command to server and get response"""
        try:
            self.socket.send(json.dumps(command_data).encode('utf-8'))
            response = self.socket.recv(1024).decode('utf-8')
            return json.loads(response)
        except Exception as e:
            print(f"Communication error: {e}")
            return {'status': 'error', 'message': 'Communication failed'}
    
    def listen_for_messages(self):
        """Listen for incoming messages in a separate thread"""
        while self.running:
            try:
                data = self.socket.recv(1024).decode('utf-8')
                if data:
                    message = json.loads(data)
                    if message.get('type') == 'MESSAGE':
                        print(f"\n[{message['timestamp']}] {message['from']}: {message['content']}")
                        print(">> ", end="", flush=True)
            except:
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
            self.running = True
            
            # Start listening for messages
            listen_thread = threading.Thread(target=self.listen_for_messages)
            listen_thread.daemon = True
            listen_thread.start()
    
    def send_message(self):
        """Send a message to another user"""
        if not self.logged_in:
            print("You must be logged in to send messages!")
            return
        
        print("\n=== Send Message ===")
        recipient = input("Enter recipient username: ").strip()
        content = input("Enter message: ").strip()
        
        if not recipient or not content:
            print("Recipient and message cannot be empty!")
            return
        
        command = {
            'command': 'SEND_MESSAGE',
            'recipient': recipient,
            'content': content
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
        """Reset password (basic implementation)"""
        print("\n=== Reset Password ===")
        username = input("Enter username: ").strip()
        new_password = input("Enter new password: ").strip()
        
        command = {
            'command': 'RESET_PASSWORD',
            'username': username,
            'new_password': new_password
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
            if not self.logged_in:
                print("\n1. Create Account")
                print("2. Login")
                print("3. Login with GitHub")  #New option for GitHub login
                print("4. Reset Password")
                print("5. Exit")
                choice = input("Choose an option: ").strip()
                
                if choice == '1':
                    self.create_account()
                elif choice == '2':
                    self.login()
                elif choice == '3':
                    self.github_login()
                elif choice == '4':
                    self.reset_password()
                elif choice == '4':
                    break
                else:
                    print("Invalid choice!")
            else:
                print(f"\nLogged in as: {self.username}")
                print("1. Send Message")
                print("2. List Users")
                print("3. Send Command Message")
                print("4. Logout")
                choice = input("Choose an option (or just press Enter to wait for messages): ").strip()
                
                if choice == '1':
                    self.send_message()
                elif choice == '2':
                    self.list_users()
                elif choice == '3':
                    self.send_command_message()
                elif choice == '4':
                    self.logout()
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
