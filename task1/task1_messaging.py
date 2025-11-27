#!/usr/bin/env python3
# Task 1: Encrypted Messaging App Prototype

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def generate_rsa_key_pair():
    print("Generating RSA key pair for User A...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_keys(private_key, public_key):
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)
    print("Saved private_key.pem")
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)
    print("Saved public_key.pem")

def load_public_key(filename='public_key.pem'):
    with open(filename, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

def load_private_key(filename='private_key.pem'):
    with open(filename, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def user_b_encrypt_message(message_file='message.txt'):
    print("\n=== User B: Encrypting Message ===")
    
    public_key = load_public_key()
    print("Loaded User A's public key")
    
    with open(message_file, 'rb') as f:
        message = f.read()
    print(f"Read message from {message_file}")
    
    aes_key = os.urandom(32)
    print("Generated random AES-256 key")
    
    iv = os.urandom(16)
    print("Generated random IV")
    
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    pad_length = 16 - (len(message) % 16)
    padded_message = message + bytes([pad_length] * pad_length)
    
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    
    with open('encrypted_message.bin', 'wb') as f:
        f.write(iv + encrypted_message)
    print("Saved encrypted_message.bin")
    
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    with open('aes_key_encrypted.bin', 'wb') as f:
        f.write(encrypted_aes_key)
    print("Saved aes_key_encrypted.bin")
    
    return iv, encrypted_message

def user_a_decrypt_message():
    print("\n=== User A: Decrypting Message ===")
    
    private_key = load_private_key()
    print("Loaded User A's private key")
    
    with open('aes_key_encrypted.bin', 'rb') as f:
        encrypted_aes_key = f.read()
    print("Loaded encrypted AES key")
    
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Decrypted AES key")
    
    with open('encrypted_message.bin', 'rb') as f:
        encrypted_data = f.read()
    
    iv = encrypted_data[:16]
    encrypted_message = encrypted_data[16:]
    print("Extracted IV and encrypted message")
    
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
    pad_length = padded_message[-1]
    decrypted_message = padded_message[:-pad_length]
    
    with open('decrypted_message.txt', 'wb') as f:
        f.write(decrypted_message)
    print("Saved decrypted_message.txt")
    
    return decrypted_message

def main():
    print("=" * 60)
    print("Task 1: Encrypted Messaging App Prototype")
    print("=" * 60)
    
    print("\n[Step 1] User A generates RSA key pair")
    private_key, public_key = generate_rsa_key_pair()
    save_keys(private_key, public_key)
    
    print("\n[Step 2] User B encrypts message")
    user_b_encrypt_message()
    
    print("\n[Step 3] User A decrypts message")
    decrypted = user_a_decrypt_message()
    
    print("\n=== Verification ===")
    with open('message.txt', 'rb') as f:
        original = f.read()
    
    if original == decrypted:
        print("SUCCESS: Decrypted message matches original!")
    else:
        print("ERROR: Decrypted message does not match original!")
    
    print("\n" + "=" * 60)
    print("Task 1 completed!")
    print("=" * 60)

if __name__ == '__main__':
    main()

