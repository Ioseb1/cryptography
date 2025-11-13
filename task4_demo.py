"""
Task 4 Demo: Complete Diffie-Hellman Key Exchange demonstration
Shows the full process and verifies the shared secret
"""

from task4a_dh_exchange import simulate_dh_exchange

def main():
    print("=" * 60)
    print("Task 4: Diffie-Hellman Key Exchange")
    print("=" * 60)
    
    # Run the DH key exchange simulation
    success = simulate_dh_exchange()
    
    if success:
        print("\n" + "=" * 60)
        print("Key Exchange Process Summary")
        print("=" * 60)
        print("""
1. Alice and Bob agree on public parameters (prime p and generator g)
2. Alice generates a private key (a) and computes public key (y_A = g^a mod p)
3. Bob generates a private key (b) and computes public key (y_B = g^b mod p)
4. Alice and Bob exchange their public keys
5. Alice computes shared secret: s = y_B^a mod p = g^(ab) mod p
6. Bob computes shared secret: s = y_A^b mod p = g^(ab) mod p
7. Both parties have the same shared secret: g^(ab) mod p

The security relies on the difficulty of computing discrete logarithms.
Even if an attacker intercepts y_A and y_B, they cannot compute the
shared secret without knowing either a or b.
        """)
    else:
        print("\nKey exchange failed!")

if __name__ == "__main__":
    main()

