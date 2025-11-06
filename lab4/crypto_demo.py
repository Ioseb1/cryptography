#!/usr/bin/env python3
"""
Cryptography Demonstration Script
Performs RSA and AES-256 encryption/decryption on files
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def generate_rsa_key_pair():
    """Generate RSA key pair (2048 bits)"""
    print("Generating RSA key pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Save private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('private.pem', 'wb') as f:
        f.write(private_pem)
    
    # Save public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public.pem', 'wb') as f:
        f.write(public_pem)
    
    print("RSA key pair generated: private.pem, public.pem")
    return private_key, public_key

def rsa_encrypt(input_file, output_file, public_key):
    """Encrypt file using RSA public key"""
    print(f"Encrypting {input_file} with RSA...")
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    # RSA encryption with OAEP padding
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    with open(output_file, 'wb') as f:
        f.write(ciphertext)
    print(f"Encrypted file saved: {output_file}")

def rsa_decrypt(input_file, output_file, private_key):
    """Decrypt file using RSA private key"""
    print(f"Decrypting {input_file} with RSA...")
    with open(input_file, 'rb') as f:
        ciphertext = f.read()
    
    # RSA decryption with OAEP padding
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    print(f"Decrypted file saved: {output_file}")

def generate_aes_key_iv():
    """Generate AES-256 key and IV"""
    print("Generating AES-256 key and IV...")
    aes_key = os.urandom(32)  # 256 bits = 32 bytes
    aes_iv = os.urandom(16)   # 128 bits = 16 bytes for CBC mode
    
    with open('aes_key.bin', 'wb') as f:
        f.write(aes_key)
    
    with open('aes_iv.bin', 'wb') as f:
        f.write(aes_iv)
    
    print("AES key and IV generated: aes_key.bin, aes_iv.bin")
    return aes_key, aes_iv

def aes_encrypt(input_file, output_file, key, iv):
    """Encrypt file using AES-256-CBC"""
    print(f"Encrypting {input_file} with AES-256...")
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Pad plaintext to block size (16 bytes for AES)
    pad_length = 16 - (len(plaintext) % 16)
    plaintext_padded = plaintext + bytes([pad_length] * pad_length)
    
    # Encrypt
    ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()
    
    with open(output_file, 'wb') as f:
        f.write(ciphertext)
    print(f"Encrypted file saved: {output_file}")

def aes_decrypt(input_file, output_file, key, iv):
    """Decrypt file using AES-256-CBC"""
    print(f"Decrypting {input_file} with AES-256...")
    with open(input_file, 'rb') as f:
        ciphertext = f.read()
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    pad_length = plaintext_padded[-1]
    plaintext = plaintext_padded[:-pad_length]
    
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    print(f"Decrypted file saved: {output_file}")

def main():
    print("=" * 60)
    print("Cryptography Demonstration: RSA and AES-256")
    print("=" * 60)
    print()
    
    # Step 1: Generate RSA key pair
    private_key, public_key = generate_rsa_key_pair()
    print()
    
    # Step 2: RSA Encryption
    rsa_encrypt('message.txt', 'message_rsa_encrypted.bin', public_key)
    print()
    
    # Step 3: RSA Decryption
    rsa_decrypt('message_rsa_encrypted.bin', 'message_rsa_decrypted.txt', private_key)
    print()
    
    # Step 4: Generate AES key and IV
    aes_key, aes_iv = generate_aes_key_iv()
    print()
    
    # Step 5: AES Encryption
    aes_encrypt('message.txt', 'message_aes_encrypted.bin', aes_key, aes_iv)
    print()
    
    # Step 6: AES Decryption
    aes_decrypt('message_aes_encrypted.bin', 'message_aes_decrypted.txt', aes_key, aes_iv)
    print()
    
    print("=" * 60)
    print("All operations completed successfully!")
    print("=" * 60)

if __name__ == '__main__':
    main()

