from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import getpass

def encrypt_file(input_file, output_file, passphrase):
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode('utf-8'))
    
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext)
    padded_data += padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    with open(output_file, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(ciphertext)
    
    print(f"Encrypted: {output_file}")
    print(f"Salt: {salt.hex()}")
    print(f"IV: {iv.hex()}")
    print(f"Size: {len(ciphertext)} bytes")

if __name__ == "__main__":
    input_file = "secret.txt"
    output_file = "secret.enc"
    
    passphrase = getpass.getpass("Enter passphrase: ")
    
    if not os.path.exists(input_file):
        print(f"File not found: {input_file}")
        exit(1)
    
    encrypt_file(input_file, output_file, passphrase)

