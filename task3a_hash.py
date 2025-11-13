"""
Task 3A: SHA-256 Hash
Hashes data.txt using SHA-256 algorithm
"""

import hashlib
import os

def hash_file_sha256(filename):
    """
    Compute SHA-256 hash of a file.
    
    Args:
        filename: Path to the file to hash
    
    Returns:
        str: Hexadecimal representation of the hash
    """
    sha256_hash = hashlib.sha256()
    
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest()

if __name__ == "__main__":
    filename = "data.txt"
    
    if not os.path.exists(filename):
        print(f"Error: {filename} not found!")
        exit(1)
    
    with open(filename, 'r') as f:
        content = f.read()
    
    print("=" * 60)
    print("Task 3A: SHA-256 Hash")
    print("=" * 60)
    print(f"\nFile: {filename}")
    print(f"Content: {content}")
    
    hash_value = hash_file_sha256(filename)
    
    print(f"\nSHA-256 Hash:")
    print(f"  {hash_value}")
    print(f"\nHash (uppercase):")
    print(f"  {hash_value.upper()}")
    print(f"\nHash length: {len(hash_value)} characters (256 bits = 32 bytes)")

