import os
import sys
import subprocess

def validate_task1():
    if not os.path.exists("secret.txt"):
        print("Task 1: FAIL - secret.txt not found")
        return False
    
    from task1_encrypt import encrypt_file
    from task1_decrypt import decrypt_file
    
    test_passphrase = "TestPass123!"
    
    try:
        encrypt_file("secret.txt", "secret.enc", test_passphrase)
        
        if not os.path.exists("secret.enc"):
            print("Task 1: FAIL - encryption failed")
            return False
        
        decrypted_text = decrypt_file("secret.enc", "secret_decrypted.txt", test_passphrase)
        
        with open("secret.txt", 'rb') as f:
            original = f.read()
        
        if decrypted_text == original:
            print("Task 1: PASS")
            return True
        else:
            print("Task 1: FAIL - mismatch")
            return False
    except Exception as e:
        print(f"Task 1: FAIL - {e}")
        return False

def validate_task2():
    if not os.path.exists("ecc.txt"):
        print("Task 2: FAIL - ecc.txt not found")
        return False
    
    from task2_generate_keys import generate_ecc_keys
    from task2_sign import sign_message
    from task2_verify import verify_signature
    
    try:
        generate_ecc_keys()
        
        if not os.path.exists("ecc_private_key.pem") or not os.path.exists("ecc_public_key.pem"):
            print("Task 2: FAIL - key generation failed")
            return False
        
        sign_message("ecc.txt", "ecc_private_key.pem", "ecc_signature.bin")
        
        if not os.path.exists("ecc_signature.bin"):
            print("Task 2: FAIL - signing failed")
            return False
        
        result = verify_signature("ecc.txt", "ecc_public_key.pem", "ecc_signature.bin")
        
        if result:
            print("Task 2: PASS")
            return True
        else:
            print("Task 2: FAIL - verification failed")
            return False
    except Exception as e:
        print(f"Task 2: FAIL - {e}")
        return False

def validate_task3():
    if not os.path.exists("data.txt"):
        print("Task 3: FAIL - data.txt not found")
        return False
    
    from task3a_hash import hash_file_sha256
    from task3b_hmac import compute_hmac_sha256
    from task3c_integrity import compute_hmac_sha256 as compute_hmac, verify_hmac
    
    try:
        hash_value = hash_file_sha256("data.txt")
        if len(hash_value) != 64:
            print("Task 3: FAIL - hash length incorrect")
            return False
        
        hmac_value = compute_hmac_sha256("data.txt", "secretkey123")
        if len(hmac_value) != 64:
            print("Task 3: FAIL - HMAC length incorrect")
            return False
        
        original_hmac = compute_hmac("data.txt", "secretkey123")
        
        with open("data.txt", 'r') as f:
            content = f.read()
        modified_content = content.replace("trust", "trUst")
        
        with open("data_test_modified.txt", 'w') as f:
            f.write(modified_content)
        
        modified_hmac = compute_hmac("data_test_modified.txt", "secretkey123")
        
        if original_hmac == modified_hmac:
            print("Task 3: FAIL - HMAC should differ")
            os.remove("data_test_modified.txt")
            return False
        
        is_valid = verify_hmac("data_test_modified.txt", "secretkey123", original_hmac)
        if is_valid:
            print("Task 3: FAIL - verification should fail")
            os.remove("data_test_modified.txt")
            return False
        
        os.remove("data_test_modified.txt")
        print("Task 3: PASS")
        return True
    except Exception as e:
        print(f"Task 3: FAIL - {e}")
        if os.path.exists("data_test_modified.txt"):
            os.remove("data_test_modified.txt")
        return False

def validate_task4():
    from task4a_dh_exchange import simulate_dh_exchange
    
    try:
        result = simulate_dh_exchange()
        if result:
            print("Task 4: PASS")
            return True
        else:
            print("Task 4: FAIL - key exchange failed")
            return False
    except Exception as e:
        print(f"Task 4: FAIL - {e}")
        return False

def main():
    results = []
    
    results.append(("Task 1", validate_task1()))
    results.append(("Task 2", validate_task2()))
    results.append(("Task 3", validate_task3()))
    results.append(("Task 4", validate_task4()))
    
    print("\nSummary:")
    all_passed = True
    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{name}: {status}")
        if not result:
            all_passed = False
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())

