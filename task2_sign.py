"""
Task 2B: Sign a message using ECC private key
Signs ecc.txt with the ECC private key
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os

def sign_message(message_file, private_key_file, signature_file):
    """
    Sign a message file using ECC private key.
    
    Args:
        message_file: Path to the file to sign
        private_key_file: Path to the private key file
        signature_file: Path to save the signature
    """
    with open(message_file, 'rb') as f:
        message = f.read()
    
    with open(private_key_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    
    with open(signature_file, 'wb') as f:
        f.write(signature)
    
    print(f"✓ Message signed successfully!")
    print(f"  Message file: {message_file}")
    print(f"  Private key: {private_key_file}")
    print(f"  Signature saved: {signature_file}")
    print(f"  Signature length: {len(signature)} bytes")
    print(f"  Signature (hex): {signature.hex()}")
    
    return signature

if __name__ == "__main__":
    message_file = "ecc.txt"
    private_key_file = "ecc_private_key.pem"
    signature_file = "ecc_signature.bin"
    
    if not os.path.exists(message_file):
        print(f"Error: {message_file} not found!")
        exit(1)
    
    if not os.path.exists(private_key_file):
        print(f"Error: {private_key_file} not found!")
        print("Please run task2_generate_keys.py first to generate keys.")
        exit(1)
    
    sign_message(message_file, private_key_file, signature_file)

