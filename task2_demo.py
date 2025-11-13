from task2_generate_keys import generate_ecc_keys
from task2_sign import sign_message
from task2_verify import verify_signature
import os

def main():
    generate_ecc_keys()
    
    if not os.path.exists("ecc.txt"):
        print("File not found: ecc.txt")
        return
    
    sign_message("ecc.txt", "ecc_private_key.pem", "ecc_signature.bin")
    is_valid = verify_signature("ecc.txt", "ecc_public_key.pem", "ecc_signature.bin")
    
    with open("ecc_modified.txt", 'w') as f:
        f.write("Elliptic Curves are NOT efficient.")
    
    is_valid_modified = verify_signature("ecc_modified.txt", "ecc_public_key.pem", "ecc_signature.bin")
    
    if os.path.exists("ecc_modified.txt"):
        os.remove("ecc_modified.txt")
    
    print(f"Original verification: {'OK' if is_valid else 'FAILED'}")
    print(f"Modified verification: {'OK' if is_valid_modified else 'FAILED'}")

if __name__ == "__main__":
    main()

