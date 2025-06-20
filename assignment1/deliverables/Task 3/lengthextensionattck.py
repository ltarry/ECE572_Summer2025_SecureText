import socket
import json
import hashlib

def send_command(sock, command_data):
    sock.sendall((json.dumps(command_data) + '\n').encode('utf-8'))
    return json.loads(sock.recv(4096).decode('utf-8'))

# Connect to server
HOST = "127.0.0.1"
PORT = 12345

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    # Login first
    login_command = {
        'command': 'LOGIN',
        'username': 'admin',  # Using admin account
        'password': 'password123'
    }
    
    print("== Logging in ==")
    response = send_command(s, login_command)
    print(response)
    
    if response['status'] == 'success':
        # Use hash_extender output
        hex_string = "434d443d5345545f51554f544126555345523d626f62264c494d49543d313030800000000000000000000000600100000000000026434d443d4752414e545f41444d494e26555345523d61747461636b6572"
        forged_mac = "18846eed63a94027f8c254c81d8b1474"
        
        # Convert hex to bytes and then to latin1 string
        forged_msg = bytes.fromhex(hex_string).decode('latin1')
        
        attack_command = {
            'command': 'COMMAND_MSG',
            'command_msg': forged_msg,
            'mac': forged_mac
        }

        print("\n== Sending Attack Payload ==")
        print(f"Extended message (hex): {hex_string}")
        print(f"Extended MAC: {forged_mac}")
        
        response = send_command(s, attack_command)
        print("\n== Server Response ==")
        print(json.dumps(response, indent=2))
