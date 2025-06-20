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
from datetime import datetime

class SecureTextServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.users_file = 'users.json'
        self.users = self.load_users()
        self.check_pending_migrations() #check for a migration call required
        self.active_connections = {}  # username -> connection
        self.server_socket = None
        
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
            return False, "Username already exists"
    
        # Hash password with SHA-256
        password_hash = self.hash_password_sha256(password)
    
        self.users[username] = {
            'password_hash': password_hash,
            'created_at': datetime.now().isoformat(),
            'reset_question': 'What is your favorite color?',
            'reset_answer': 'blue'
        }
        self.save_users()
        return True, "Account created successfully"
    
    def authenticate(self, username, password):
        """Authenticate user with support for all formats and migration"""
        if username not in self.users:
            return False, "Username not found"
    
        user = self.users[username]
    
        #Plaintext password storage
        if 'password' in user:
            if user['password'] == password:
                self.migrate_user_password(username, password)
                return True, "Authentication successful"
            return False, "Invalid password"
    
        #Old unsalted SHA-256 hash
        if 'password_hash' in user and isinstance(user['password_hash'], str):
            test_hash = hashlib.sha256(password.encode()).hexdigest()
            if test_hash == user['password_hash']:
                self.migrate_user_password(username, password)
                return True, "Authentication successful"
            return False, "Invalid password"
    
        #New format hashes
        if 'password_hash' in user and isinstance(user['password_hash'], dict):
            stored_hash = user['password_hash']
        
            # SHA-256 with salt
            if stored_hash['hash_type'] == 'sha256_salted':
                salt = base64.b64decode(stored_hash['salt'])
                verification_hash = self.hash_password_sha256(password, salt)
                if verification_hash['hash'] == stored_hash['hash']:
                    self.migrate_user_password(username, password)
                    return True, "Authentication successful"
        
            # PBKDF2 with salt
            elif stored_hash['hash_type'] == 'pbkdf2':
                if self.verify_password_pbkdf2(password, stored_hash):
                    return True, "Authentication successful"
    
        return False, "Invalid password"

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
                        success, msg = self.create_account(username, password)
                        response = {'status': 'success' if success else 'error', 'message': msg}
                        
                    elif command == 'LOGIN':
                        username = message.get('username')
                        password = message.get('password')
                        success, msg = self.authenticate(username, password)
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
                    
                    elif command == 'COMMAND_MSG':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        else:
                            cmd_msg = message.get('command_msg')
                            mac = message.get('mac')
                            response = self.handle_command_message(current_user, cmd_msg, mac)

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


class SecureTextClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        self.logged_in = False
        self.username = None
        self.running = False
        
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
    
    def login(self):
        """Login to the system"""
        print("\n=== Login ===")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        
        command = {
            'command': 'LOGIN',
            'username': username,
            'password': password
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
                print("3. Reset Password")
                print("4. Exit")
                choice = input("Choose an option: ").strip()
                
                if choice == '1':
                    self.create_account()
                elif choice == '2':
                    self.login()
                elif choice == '3':
                    self.reset_password()
                elif choice == '4':
                    break
                else:
                    print("Invalid choice!")
            else:
                print(f"\nLogged in as: {self.username}")
                print("1. Send Message")
                print("2. List Users")
                print("3. Logout")
                choice = input("Choose an option (or just press Enter to wait for messages): ").strip()
                
                if choice == '1':
                    self.send_message()
                elif choice == '2':
                    self.list_users()
                elif choice == '3':
                    self.logged_in = False
                    self.running = False
                    self.username = None
                    print("Logged out successfully")
                elif choice == '':
                    # Just wait for messages
                    print("Waiting for messages... (press Enter to show menu)")
                    input()
                else:
                    print("Invalid choice!")
        
        if self.socket:
            self.socket.close()
        print("Goodbye!")
        

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
