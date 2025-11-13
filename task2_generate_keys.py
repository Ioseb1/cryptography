"""
Task 2A: Generate ECC Keys
Generates ECC key pair using prime256v1 curve (secp256r1)
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_ecc_keys():
    """
    Generate ECC key pair using prime256v1 curve (secp256r1).
    Saves private key to ecc_private_key.pem and public key to ecc_public_key.pem
    """
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        default_backend()
    )
    
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open("ecc_private_key.pem", "wb") as f:
        f.write(private_pem)
    
    with open("ecc_public_key.pem", "wb") as f:
        f.write(public_pem)
    
    print("✓ ECC key pair generated successfully!")
    print(f"  Curve: prime256v1 (secp256r1 / NIST P-256)")
    print(f"  Private key saved: ecc_private_key.pem")
    print(f"  Public key saved: ecc_public_key.pem")
    
    print(f"\nPrivate Key (first 50 chars):")
    print(private_pem.decode('utf-8')[:50] + "...")
    print(f"\nPublic Key (first 50 chars):")
    print(public_pem.decode('utf-8')[:50] + "...")
    
    return private_key, public_key

if __name__ == "__main__":
    generate_ecc_keys()

