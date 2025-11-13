from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import getpass

def decrypt_file(input_file, output_file, passphrase):
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
    
    print(f"Decrypted: {output_file}")
    return plaintext

if __name__ == "__main__":
    input_file = "secret.enc"
    output_file = "secret_decrypted.txt"
    
    passphrase = getpass.getpass("Passphrase: ")
    
    try:
        decrypted_text = decrypt_file(input_file, output_file, passphrase)
        print("\nContent:")
        print(decrypted_text.decode('utf-8'))
        
        with open("secret.txt", 'rb') as f:
            original = f.read()
        
        if decrypted_text == original:
            print("\nMatch: OK")
        else:
            print("\nMatch: FAILED")
            
    except Exception as e:
        print(f"Error: {e}")

