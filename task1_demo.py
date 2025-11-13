from task1_encrypt import encrypt_file
from task1_decrypt import decrypt_file
import os

def main():
    passphrase = "MySecurePassphrase123!"
    
    if not os.path.exists("secret.txt"):
        print("File not found: secret.txt")
        return
    
    encrypt_file("secret.txt", "secret.enc", passphrase)
    decrypted_text = decrypt_file("secret.enc", "secret_decrypted.txt", passphrase)
    
    with open("secret.txt", 'rb') as f:
        original_bytes = f.read()
    
    if decrypted_text == original_bytes:
        print("Match: OK")
    else:
        print("Match: FAILED")

if __name__ == "__main__":
    main()

