#!/usr/bin/env python3
# Task 2: Secure File Exchange Using RSA + AES

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import os

def generate_bob_rsa_key_pair():
    print("Generating RSA key pair for Bob...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_bob_keys(private_key, public_key):
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('private.pem', 'wb') as f:
        f.write(private_pem)
    print("Saved private.pem")
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public.pem', 'wb') as f:
        f.write(public_pem)
    print("Saved public.pem")

def load_public_key(filename='public.pem'):
    with open(filename, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

def load_private_key(filename='private.pem'):
    with open(filename, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def compute_sha256_hash(data):
    return hashlib.sha256(data).hexdigest()

def alice_encrypt_file(message_file='alice_message.txt'):
    print("\n=== Alice: Encrypting File ===")
    
    public_key = load_public_key()
    print("Loaded Bob's public key")
    
    with open(message_file, 'rb') as f:
        message_data = f.read()
    print(f"Read message from {message_file}")
    
    original_hash = compute_sha256_hash(message_data)
    print(f"Original file SHA-256 hash: {original_hash}")
    
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
    
    pad_length = 16 - (len(message_data) % 16)
    padded_message = message_data + bytes([pad_length] * pad_length)
    
    encrypted_file = encryptor.update(padded_message) + encryptor.finalize()
    
    with open('encrypted_file.bin', 'wb') as f:
        f.write(iv + encrypted_file)
    print("Saved encrypted_file.bin")
    
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
    
    return original_hash, iv, encrypted_file

def bob_decrypt_file():
    print("\n=== Bob: Decrypting File ===")
    
    private_key = load_private_key()
    print("Loaded Bob's private key")
    
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
    
    with open('encrypted_file.bin', 'rb') as f:
        encrypted_data = f.read()
    
    iv = encrypted_data[:16]
    encrypted_file = encrypted_data[16:]
    print("Extracted IV and encrypted file")
    
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    padded_message = decryptor.update(encrypted_file) + decryptor.finalize()
    
    pad_length = padded_message[-1]
    decrypted_message = padded_message[:-pad_length]
    
    with open('decrypted_message.txt', 'wb') as f:
        f.write(decrypted_message)
    print("Saved decrypted_message.txt")
    
    decrypted_hash = compute_sha256_hash(decrypted_message)
    print(f"Decrypted file SHA-256 hash: {decrypted_hash}")
    
    return decrypted_message, decrypted_hash

def verify_integrity(original_hash, decrypted_hash):
    print("\n=== Integrity Verification ===")
    print(f"Original hash:  {original_hash}")
    print(f"Decrypted hash: {decrypted_hash}")
    
    if original_hash == decrypted_hash:
        print("PASS: File integrity verified! Hashes match.")
        return True
    else:
        print("FAIL: File integrity check failed! Hashes do not match.")
        return False

def main():
    print("=" * 60)
    print("Task 2: Secure File Exchange Using RSA + AES")
    print("=" * 60)
    
    print("\n[Step 1] Generate RSA key pair for Bob")
    private_key, public_key = generate_bob_rsa_key_pair()
    save_bob_keys(private_key, public_key)
    
    print("\n[Step 2] Alice encrypts file")
    original_hash, iv, encrypted_file = alice_encrypt_file()
    
    print("\n[Step 3] Bob decrypts file")
    decrypted_message, decrypted_hash = bob_decrypt_file()
    
    print("\n[Step 4] Verify integrity")
    integrity_ok = verify_integrity(original_hash, decrypted_hash)
    
    print("\n=== Final Verification ===")
    with open('alice_message.txt', 'rb') as f:
        original = f.read()
    
    if original == decrypted_message and integrity_ok:
        print("SUCCESS: Decryption and integrity verification passed!")
    else:
        print("ERROR: Decryption or integrity check failed!")
    
    print("\n" + "=" * 60)
    print("Task 2 completed!")
    print("=" * 60)

if __name__ == '__main__':
    main()

