"""
Task 2B: Verify a message signature using ECC public key
Verifies ecc.txt signature using the ECC public key
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os

def verify_signature(message_file, public_key_file, signature_file):
    """
    Verify a message signature using ECC public key.
    
    Args:
        message_file: Path to the original message file
        public_key_file: Path to the public key file
        signature_file: Path to the signature file
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    with open(message_file, 'rb') as f:
        message = f.read()
    
    with open(public_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    
    with open(signature_file, 'rb') as f:
        signature = f.read()
    
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        print("✓ Signature verification: SUCCESS")
        print(f"  The signature is valid!")
        print(f"  Message file: {message_file}")
        print(f"  Public key: {public_key_file}")
        print(f"  Signature: {signature_file}")
        return True
    except InvalidSignature:
        print("✗ Signature verification: FAILED")
        print(f"  The signature is NOT valid!")
        print(f"  The message may have been tampered with or the wrong key was used.")
        return False

if __name__ == "__main__":
    message_file = "ecc.txt"
    public_key_file = "ecc_public_key.pem"
    signature_file = "ecc_signature.bin"
    
    if not os.path.exists(message_file):
        print(f"Error: {message_file} not found!")
        exit(1)
    
    if not os.path.exists(public_key_file):
        print(f"Error: {public_key_file} not found!")
        print("Please run task2_generate_keys.py first to generate keys.")
        exit(1)
    
    if not os.path.exists(signature_file):
        print(f"Error: {signature_file} not found!")
        print("Please run task2_sign.py first to create a signature.")
        exit(1)
    
    verify_signature(message_file, public_key_file, signature_file)

