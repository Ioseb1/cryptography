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

if __name__ == "__main__":
    filename = "data.txt"
    key = "secretkey123"
    
    if not os.path.exists(filename):
        print(f"File not found: {filename}")
        exit(1)
    
    hmac_value = compute_hmac_sha256(filename, key)
    print(f"HMAC-SHA256: {hmac_value}")

