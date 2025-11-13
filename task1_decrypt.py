"""
Task 1B: AES-128-CBC Decryption Script
Decrypts secret.enc using AES-128-CBC with a passphrase
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import getpass

def decrypt_file(input_file, output_file, passphrase):
    """
    Decrypt a file using AES-128-CBC with a passphrase.
    
    Args:
        input_file: Path to the encrypted file
        output_file: Path to save the decrypted file
        passphrase: Passphrase string (will be converted to bytes)
    """
    with open(input_file, 'rb') as f:
        data = f.read()
    
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode('utf-8'))
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext)
    plaintext += unpadder.finalize()
    
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    
    print(f"✓ File decrypted successfully: {output_file}")
    return plaintext

if __name__ == "__main__":
    input_file = "secret.enc"
    output_file = "secret_decrypted.txt"
    
    passphrase = getpass.getpass("Enter passphrase: ")
    
    try:
        decrypted_text = decrypt_file(input_file, output_file, passphrase)
        print(f"\nDecrypted content:")
        print(decrypted_text.decode('utf-8'))
        
        with open("secret.txt", 'rb') as f:
            original = f.read()
        
        if decrypted_text == original:
            print("\n✓ Verification: Decrypted file matches original!")
        else:
            print("\n✗ Verification: Decrypted file does NOT match original!")
            
    except Exception as e:
        print(f"Error during decryption: {e}")

