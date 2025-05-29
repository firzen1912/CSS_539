import os
import sqlite3
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

DB_FILE = "hsm.db"
HSM_SECRET = b"SuperSecretHSMKey1234567890abcd"  # 32 bytes for AES-256

def sha256(data):
    return hashlib.sha256(data.encode()).digest()

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(data))

def aes_decrypt(key, data):
    iv = data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[16:]))

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        password_hash TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS keys (
        key_id TEXT PRIMARY KEY,
        user_id TEXT,
        public_key TEXT,
        encrypted_private_key BLOB,
        kvc BLOB
    )''')
    conn.commit()
    conn.close()

def register_user(user_id, password):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    try:
        c.execute("INSERT INTO users VALUES (?, ?)", (user_id, password_hash))
        conn.commit()
        print(f"[+] User '{user_id}' registered.")
    except sqlite3.IntegrityError:
        print("[!] User ID already exists.")
    conn.close()

def login(user_id, password):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row and row[0] == hashlib.sha256(password.encode()).hexdigest():
        print("[+] Login successful.")
        return True
    print("[!] Login failed.")
    return False

def create_key(user_id, key_password):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    key_id = base64.urlsafe_b64encode(get_random_bytes(8)).decode()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Derive KEK and KVC
    kek = xor_bytes(HSM_SECRET, sha256(key_password))
    encrypted_private_key = aes_encrypt(kek, priv_pem)
    kvc = aes_encrypt(kek, b"test")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO keys VALUES (?, ?, ?, ?, ?)",
              (key_id, user_id, pub_pem, encrypted_private_key, kvc))
    conn.commit()
    conn.close()
    print(f"[+] Key created. Key ID: {key_id}")
    print(f"[+] Public Key:\n{pub_pem}")

def encrypt_with_key(key_id, key_password, plaintext):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT encrypted_private_key, kvc FROM keys WHERE key_id = ?", (key_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        print("[!] Key ID not found.")
        return

    encrypted_private_key, stored_kvc = row
    kek = xor_bytes(HSM_SECRET, sha256(key_password))
    if aes_encrypt(kek, b"test") != stored_kvc:
        print("[!] Invalid key password.")
        return

    try:
        priv_pem = aes_decrypt(kek, encrypted_private_key)
    except:
        print("[!] Decryption failed.")
        return

    private_key = serialization.load_pem_private_key(priv_pem, password=None)
    ciphertext = private_key.encrypt(
        plaintext.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    print(f"[+] Encrypted Text (base64):\n{base64.b64encode(ciphertext).decode()}")

def generate_report():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT user_id FROM users")
    users = c.fetchall()
    c.execute("SELECT key_id, user_id FROM keys")
    keys = c.fetchall()
    conn.close()

    print("\n=== HSM STATUS REPORT ===")
    print("Registered Users:")
    for user in users:
        print(f" - {user[0]}")
    print("\nStored Keys:")
    for key in keys:
        print(f" - Key ID: {key[0]} | Owner: {key[1]}")
    print("==========================\n")

# CLI for testing
def menu():
    init_db()
    while True:
        print("\nOptions: register | login | createkey | encrypt | report | quit")
        choice = input(">> ").strip()
        if choice == "register":
            user_id = input("User ID: ")
            password = input("Password: ")
            register_user(user_id, password)
        elif choice == "login":
            user_id = input("User ID: ")
            password = input("Password: ")
            login(user_id, password)
        elif choice == "createkey":
            user_id = input("User ID: ")
            password = input("Key Password: ")
            create_key(user_id, password)
        elif choice == "encrypt":
            key_id = input("Key ID: ")
            password = input("Key Password: ")
            text = input("Text to Encrypt: ")
            encrypt_with_key(key_id, password, text)
        elif choice == "report":
            generate_report()
        elif choice == "quit":
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    menu()
