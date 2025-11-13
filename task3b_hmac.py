"""
Task 3B: HMAC using SHA-256
Creates HMAC for data.txt using SHA-256 with key "secretkey123"
"""

import hmac
import hashlib
import os

def compute_hmac_sha256(filename, key):
    """
    Compute HMAC-SHA256 of a file.
    
    Args:
        filename: Path to the file to hash
        key: Secret key (string or bytes)
    
    Returns:
        str: Hexadecimal representation of the HMAC
    """
    if isinstance(key, str):
        key_bytes = key.encode('utf-8')
    else:
        key_bytes = key
    
    hmac_obj = hmac.new(key_bytes, digestmod=hashlib.sha256)
    
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            hmac_obj.update(byte_block)
    
    return hmac_obj.hexdigest()

if __name__ == "__main__":
    filename = "data.txt"
    key = "secretkey123"
    
    if not os.path.exists(filename):
        print(f"Error: {filename} not found!")
        exit(1)
    
    with open(filename, 'r') as f:
        content = f.read()
    
    print("=" * 60)
    print("Task 3B: HMAC using SHA-256")
    print("=" * 60)
    print(f"\nFile: {filename}")
    print(f"Content: {content}")
    print(f"Key: {key}")
    
    hmac_value = compute_hmac_sha256(filename, key)
    
    print(f"\nHMAC-SHA256:")
    print(f"  {hmac_value}")
    print(f"\nHMAC (uppercase):")
    print(f"  {hmac_value.upper()}")
    print(f"\nHMAC length: {len(hmac_value)} characters (256 bits = 32 bytes)")

