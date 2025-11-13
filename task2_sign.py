from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os

def sign_message(message_file, private_key_file, signature_file):
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
    
    print(f"Signed: {signature_file}")
    print(f"Length: {len(signature)} bytes")
    print(f"Hex: {signature.hex()}")
    
    return signature

if __name__ == "__main__":
    message_file = "ecc.txt"
    private_key_file = "ecc_private_key.pem"
    signature_file = "ecc_signature.bin"
    
    if not os.path.exists(message_file):
        print(f"File not found: {message_file}")
        exit(1)
    
    if not os.path.exists(private_key_file):
        print(f"Key not found: {private_key_file}")
        exit(1)
    
    sign_message(message_file, private_key_file, signature_file)

