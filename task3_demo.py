from task3a_hash import hash_file_sha256
from task3b_hmac import compute_hmac_sha256
from task3c_integrity import compute_hmac_sha256, verify_hmac
import os

def main():
    filename = "data.txt"
    modified_filename = "data_modified.txt"
    key = "secretkey123"
    
    if not os.path.exists(filename):
        print(f"File not found: {filename}")
        return
    
    hash_value = hash_file_sha256(filename)
    print(f"SHA-256: {hash_value}")
    
    hmac_value = compute_hmac_sha256(filename, key)
    print(f"HMAC-SHA256: {hmac_value}")
    
    original_hmac = hmac_value
    
    with open(filename, 'r') as f:
        content = f.read()
    modified_content = content.replace("trust", "trUst")
    
    with open(modified_filename, 'w') as f:
        f.write(modified_content)
    
    modified_hmac = compute_hmac_sha256(modified_filename, key)
    
    print(f"Original HMAC: {original_hmac}")
    print(f"Modified HMAC: {modified_hmac}")
    
    is_valid = verify_hmac(modified_filename, key, original_hmac)
    print(f"Verification: {'PASS' if is_valid else 'FAIL'}")

if __name__ == "__main__":
    main()

