# Module-4-Midterm-Build-a-Secure-Data-Transmission-App-with-Hashing-and-Encryption
This project demonstrates fundamental security concepts including user authentication, role-based access control, encryption, hashing, and digital signatures.

Module 4 Midterm: Build a Secure Data Transmission App with Hashing and Encryption

Estela Garcia
Course: Security and Secure Coding OLCP – SDEV245
Date: November 24, 2025
Assignment: Build a simple application with user login and role-based access control. This demonstrates the implementation of basic authentication and access restrictions based on role.

Project Overview: 
This project implements key cryptographic and security principles in a Python application. It includes secure login with RBAC, for Admin and Standard users. Data confidentiality is maintained through AES(Fernet) encryption and decryption, while SHA-256 ensures integrity. The project also emphasizes the importance of randomness using cryptographic salts and features a Caesar cipher demonstration to showcase basic encryption.

Features: 
•	User Authentication: Login system with SHA-256 hashed passwords
•	Role-Based Access Control: Different privileges for admin vs user roles
•	SHA-256 Hashing: Message integrity verification
•	AES Symmetric Encryption: Fernet implementation for confidentiality
•	Caesar Cipher: Simple substitution cipher demonstration
•	Entropy/Randomness: Shows how random salts strengthen cryptography

Admin-Only Features: 
•	Digital Signatures: RSA-based message signing and verification
•	RSA Asymmetric Encryption: Public/private key encryption demonstration

Prerequisites:
•	Python 3.x
•	Installation of library -pip install cryptography

How to Run the Script:
1.	Run the script using Python 3.x
2.	Pip install cryptography
3.	midterm python crypto_app.py

The Script will prompt you to login first.
•	Admin User: Mr. Emily (username); admin245 (password). Full access (including digital signatures & RSA)
•	Standard User: Andrew (username); user245 (password). Basic access (AES, Caesar cipher, entropy demo)

Follow the on-screen prompts for message input. 
1.	User Login: Authentication of user with username and password. (Username is case sensitive).
2.	AES Encryption/Decryption: Encrypt a message and verify intergrity with SHA-256.
3.	Caesar Cipher: Demonstrate simple substitution cipher.
4.	Entropy Demo: Show how random salts create different hashes. 
5.	Admin Features (if admin): Digital signatures and RSA encryption. 
6.	CIA Explanation: Summary of security concepts demonstrated. 

(Confidentiality, Integrity, Availability) - CIA Triad Implementation: 
Confidentiality is implemented through: 
•	AES symmetric encryption protects data from unauthorized access.
•	Role-based access control (admin only features)
•	Caesar cipher as a basic demonstration
Integrity is maintained through:
•	SHA-256 hashing verifies data has not been altered.
•	Hash comparison before and after encryption.
•	Digital signature verification (admin mode)
Availability is ensured through:
•	System provides reliable authentication and encryption services
•	Role-based access ensures authorized users can access features
Entropy & Key Generation Explanation
Entropy refers to randomness collected for cryptographic use. High entropy prevents guessing attacks, hash prediction, and key duplication making cryptographic operations significantly more secure.
•	Secrets.token_hex() generates unpredictable salts
•	Fernet (AES) generates secure random encryption keys
Sample Output as the Standard User: 
Enter username: Andrew
Enter Password: user245
Welcome Andrew! Role: user

 AES Encryption/Integrity Check 
Generated AES Key: HL_V1XWnR1X1bx5dbnj-KCKfhaA8j0rONHlOh9g_
Enter message to encrypt: highlighter
original SHA-256: cf42b9f7565299fb259b5457e8e14c66afaa15f3...
Encrypted Message: gAAAAABpJSarGibPuVAk6cISglzTZSo4EA-ZHDoP37mCUtzq8e
Decrypted Message: highlighter
Decrypted SHA-256 (verified against original): cf42b9f7565299fb259b5457e8e14c66afaa15f3...
Integrity Verified
[Additional output continues…]

Author: 
Estela
