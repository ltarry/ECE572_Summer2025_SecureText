import hashlib
import time
import base64
from hashlib import pbkdf2_hmac

#Chosen password
password = "password123"
salt = base64.b64decode("n1SUGm/xsSNo7lXD1bGJoA==")

#Create known hashes for attempt
sha256_hash = hashlib.sha256(password.encode()).hexdigest()

pbkdf2_hash = base64.b64encode(
    pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
).decode()

#Dummy wordlist to test
wordlist = ["123456", "password", "admin", "letmein", "password123", "welcome", "qwerty"]

#To crack SHA-256
start = time.time()
for guess in wordlist:
    guess_hash = hashlib.sha256(guess.encode()).hexdigest()
    if guess_hash == sha256_hash:
        print(f"Found password: {guess}")
        break
end = time.time()
print(f"SHA-256 crack time: {end - start:.4f} seconds\n")

#To crack PBKDF2
start = time.time()
for guess in wordlist:
    guess_hash = base64.b64encode(
        pbkdf2_hmac('sha256', guess.encode(), salt, 100_000)
    ).decode()
    if guess_hash == pbkdf2_hash:
        print(f"Found password: {guess}")
        break
end = time.time()
print(f"PBKDF2 crack time: {end - start:.4f} seconds")
