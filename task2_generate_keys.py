from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_ecc_keys():
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
    
    print("Keys generated")
    print(f"Curve: prime256v1")
    print(f"Private: ecc_private_key.pem")
    print(f"Public: ecc_public_key.pem")
    
    return private_key, public_key

if __name__ == "__main__":
    generate_ecc_keys()

