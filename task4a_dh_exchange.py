from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

def simulate_dh_exchange():
    parameters = generate_dh_parameters()
    
    alice_private_key = parameters.generate_private_key()
    alice_public_key = alice_private_key.public_key()
    alice_public_value = alice_public_key.public_numbers().y
    
    bob_private_key = parameters.generate_private_key()
    bob_public_key = bob_private_key.public_key()
    bob_public_value = bob_public_key.public_numbers().y
    
    alice_shared_secret = alice_private_key.exchange(bob_public_key)
    bob_shared_secret = bob_private_key.exchange(alice_public_key)
    
    print(f"Alice public key: {hex(alice_public_value)}")
    print(f"Bob public key: {hex(bob_public_value)}")
    print(f"Shared secret: {alice_shared_secret.hex()}")
    
    if alice_shared_secret == bob_shared_secret:
        print("Keys match: OK")
        return True
    else:
        print("Keys mismatch: ERROR")
        return False

if __name__ == "__main__":
    simulate_dh_exchange()

