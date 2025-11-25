"""Estela Garcia
Date: November 23, 2025
Course: SDEV245
Assignment: Midterm: Build simple application with user login and role-based access control. Demonstrate the implementation of basic authentication and access
restrictions based on role. The project creation where it accepts user input and hashes the input using SHA-256 to ensure integrity. It encrypts the input
using symmetic encryption like AES and decrypts the content and verifies its integrity via hash comparison"""

import hashlib, secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Hashing Function
def generate_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

#users and roles
users = {
    "Mr. Emily": {"password": generate_hash("admin245"), "role": "admin"},
    "Andrew": {"password": generate_hash("user245"), "role": "user"}
}    


#login function
def login():
    username = input("Enter username: ")
    password = input("Enter Password: ")
    
    hashed_input = generate_hash(password)

    if username in users and users[username] ["password"] == hashed_input:
        role = users[username]["role"]
        print(f"Welcome {username}! Role: {role}")
        return username, users[username]["role"]
    print("Unauthorized! Access denied!")
    return None, None
    
#Caesar Cipher
def caesar_cipher(text, shift=3):
    encrypted = ""
    for char in text: 
        if char.isalpha():
            base = 65 if char.isupper() else 97
            encrypted += chr((ord(char) - base + shift) % 26 + base)
        else: 
            encrypted += char 
    
    decrypted = ""
    for char in encrypted: 
        if char.isalpha():
            base =  65 if char.isupper() else 97
            decrypted += chr((ord(char) - base - shift) % 26 + base)
        else:
            decrypted += char

    print("\n Caesar Cipher ")
    print(f"Original: {text}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")

#Global RSA keys - admin
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

#Digital Signature - admin only
def signature():
    print("\n Digital Signature(RSA)")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    
    message = (input("Enter message to sign (or press Enter for 'Hello'):") or "Hello")
    message_bytes = message.encode()
    digital_signature = private_key.sign(message_bytes, padding.PKCS1v15(), hashes.SHA256())
    print("Message signed with private key!")
#verification
    try: 
        public_key.verify(digital_signature, message_bytes, padding.PKCS1v15(), hashes.SHA256())
        print("Signature verified with public key!")
    except:
        print("Signature Verification Failed!")

#Entropy / Randomness
def demonstrate_entropy():
    password = "test245"
    print("\n Entropy/Randomness")
    print("Demonstrated how randomness strengthens cryptographic algorithms:")
    for i in range(2):
        salt = secrets.token_hex(4)
        hashed = hashlib.sha256((password+salt).encode()).hexdigest()
        print(f"Salt: {i+1}: {salt} Hashed:{hashed[:40]}")

#Symmetric Encryption(Fernet/AES) and Integrity Check
def aes_encrypt_decrypt():
    key = Fernet.generate_key()
    cipher = Fernet(key)
    print("\n AES Encryption/Intergrity Check ")
    print(f"Generated AES Key: {key.decode()[:40]}")

    message =input("Enter message to encrypt: ")

    original_hash = generate_hash(message)
    print("original SHA-256:", original_hash[:40] + "...")

    encrypted_message = cipher.encrypt(message.encode())
    print(f"Encrypted Message: {encrypted_message.decode()[:50]}")

    decrypted_bytes = cipher.decrypt(encrypted_message)
    decrypted_message = decrypted_bytes.decode()
    print(f"Decrypted Message: {decrypted_message}")

    decrypted_hash = generate_hash(decrypted_message)
    print("Decrypted SHA-256:", decrypted_hash[:40] + "...")

    if original_hash == decrypted_hash:
        print("Integrity Verified")
    else: 
        print("Integrity FAILED!")
    
    print("\nStrengths: Fast and secure for large data(Confidentiality)")
    print("Weaknesses: Key must be safely shared.")



#CIA Triad and Entropy Explanation
def explanation():
    print("\n CIA & Entropy Explanation ")
    print("Confidentiality: AES encryption protects data from unauthorized access.")
    print("Intergrity: SHA-256 ensures data has not been altered.")
    print("Availability: Program runs reliably and decrypts correctly.")
    print("Entropy: Random salts strengthen hashes and keys, making them harder to guess.")

# Main program

def main():
    username, role = login()
    if not username:
        return
    
    aes_encrypt_decrypt()

    caesar_message = input("\nEnter message for Caesar cipher: ") or "Hello"
    caesar_cipher(caesar_message, 3)

    demonstrate_entropy()

#Role-Based Access Control for Admin Features
    if role == "admin": 
        #Digital Signature
        signature()
        print("\n RSA Asymmetric Encryption (Admin Only)")
        message_rsa = b"SecretMsg245"

        encrypted_rsa = public_key.encrypt(
            message_rsa,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Original: {message_rsa.decode()}")
        print(f"Encrypted (Hex): {encrypted_rsa.hex()[:50]}")
        
        decrypted_rsa = private_key.decrypt(
            encrypted_rsa,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        print(f"Decrypted: {decrypted_rsa.decode()}")

    else: 
        print("\n[Digital signatures and Asymmetric Encryption require admin role]")

   
    explanation()

if __name__ == "__main__":
    main()
