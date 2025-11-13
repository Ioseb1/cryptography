from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os

def verify_signature(message_file, public_key_file, signature_file):
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
        print("Verification: OK")
        return True
    except InvalidSignature:
        print("Verification: FAILED")
        return False

if __name__ == "__main__":
    message_file = "ecc.txt"
    public_key_file = "ecc_public_key.pem"
    signature_file = "ecc_signature.bin"
    
    if not os.path.exists(message_file):
        print(f"File not found: {message_file}")
        exit(1)
    
    if not os.path.exists(public_key_file):
        print(f"Key not found: {public_key_file}")
        exit(1)
    
    if not os.path.exists(signature_file):
        print(f"Signature not found: {signature_file}")
        exit(1)
    
    verify_signature(message_file, public_key_file, signature_file)

