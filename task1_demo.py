"""
Task 1 Demo: Complete encryption and decryption demonstration
This script demonstrates the full process without requiring interactive input.
"""

from task1_encrypt import encrypt_file
from task1_decrypt import decrypt_file
import os

def main():
    # Demo passphrase (in real use, this would be entered by user)
    passphrase = "MySecurePassphrase123!"
    
    print("=" * 60)
    print("Task 1A: AES-128-CBC Encryption")
    print("=" * 60)
    
    # Check if secret.txt exists
    if not os.path.exists("secret.txt"):
        print("Error: secret.txt not found!")
        return
    
    # Read and display original content
    with open("secret.txt", 'r') as f:
        original_content = f.read()
    print(f"\nOriginal file content:")
    print(f"  {original_content}")
    
    # Encrypt the file
    print(f"\nEncrypting secret.txt -> secret.enc...")
    encrypt_file("secret.txt", "secret.enc", passphrase)
    
    print("\n" + "=" * 60)
    print("Task 1B: AES-128-CBC Decryption")
    print("=" * 60)
    
    # Decrypt the file
    print(f"\nDecrypting secret.enc -> secret_decrypted.txt...")
    decrypted_text = decrypt_file("secret.enc", "secret_decrypted.txt", passphrase)
    
    # Display decrypted content
    print(f"\nDecrypted file content:")
    print(f"  {decrypted_text.decode('utf-8')}")
    
    # Verify
    print("\n" + "=" * 60)
    print("Verification")
    print("=" * 60)
    
    with open("secret.txt", 'rb') as f:
        original_bytes = f.read()
    
    if decrypted_text == original_bytes:
        print("✓ SUCCESS: Decrypted file matches original exactly!")
        print(f"  Original length: {len(original_bytes)} bytes")
        print(f"  Decrypted length: {len(decrypted_text)} bytes")
    else:
        print("✗ ERROR: Decrypted file does NOT match original!")
        print(f"  Original: {original_bytes}")
        print(f"  Decrypted: {decrypted_text}")

if __name__ == "__main__":
    main()

