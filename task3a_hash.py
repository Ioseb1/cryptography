import hashlib
import os

def hash_file_sha256(filename):
    sha256_hash = hashlib.sha256()
    
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest()

if __name__ == "__main__":
    filename = "data.txt"
    
    if not os.path.exists(filename):
        print(f"File not found: {filename}")
        exit(1)
    
    hash_value = hash_file_sha256(filename)
    print(f"SHA-256: {hash_value}")

