import hmac
import hashlib
import os

def compute_hmac_sha256(filename, key):
    if isinstance(key, str):
        key_bytes = key.encode('utf-8')
    else:
        key_bytes = key
    
    hmac_obj = hmac.new(key_bytes, digestmod=hashlib.sha256)
    
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            hmac_obj.update(byte_block)
    
    return hmac_obj.hexdigest()

def verify_hmac(filename, key, expected_hmac):
    computed_hmac = compute_hmac_sha256(filename, key)
    return hmac.compare_digest(computed_hmac, expected_hmac)

if __name__ == "__main__":
    filename = "data.txt"
    modified_filename = "data_modified.txt"
    key = "secretkey123"
    
    if not os.path.exists(filename):
        print(f"File not found: {filename}")
        exit(1)
    
    with open(filename, 'r') as f:
        original_content = f.read()
    
    original_hmac = compute_hmac_sha256(filename, key)
    print(f"Original HMAC: {original_hmac}")
    
    modified_content = original_content.replace("trust", "trUst")
    
    with open(modified_filename, 'w') as f:
        f.write(modified_content)
    
    modified_hmac = compute_hmac_sha256(modified_filename, key)
    print(f"Modified HMAC: {modified_hmac}")
    
    if original_hmac != modified_hmac:
        print("HMACs differ - modification detected")
    else:
        print("HMACs match - unexpected")
    
    is_valid = verify_hmac(modified_filename, key, original_hmac)
    print(f"Verification: {'PASS' if is_valid else 'FAIL'}")
    
    print("\nHMAC detects any file modification, even single character changes.")
    print("This provides integrity verification and authentication.")

