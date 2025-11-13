# Task 4: Diffie-Hellman Key Exchange Documentation

## Task 4A: Simulate DH Key Exchange

### Overview
This task simulates a Diffie-Hellman key exchange between two parties (Alice and Bob) to establish a shared secret key over an insecure channel.

### Implementation
**Python Script:** `task4a_dh_exchange.py`

**Usage:**
```bash
python task4a_dh_exchange.py
```

### Process Steps

1. **Generate Shared Parameters**
   - Prime number `p` (2048 bits)
   - Generator `g` (typically 2)
   - These parameters can be public and shared

2. **Alice's Key Generation**
   - Alice generates a private key `a` (kept secret)
   - Alice computes her public key: `y_A = g^a mod p`
   - Alice sends `y_A` to Bob

3. **Bob's Key Generation**
   - Bob generates a private key `b` (kept secret)
   - Bob computes his public key: `y_B = g^b mod p`
   - Bob sends `y_B` to Alice

4. **Shared Secret Computation**
   - Alice computes: `s = y_B^a mod p = g^(ab) mod p`
   - Bob computes: `s = y_A^b mod p = g^(ab) mod p`
   - Both parties arrive at the same shared secret: `g^(ab) mod p`

### Output

The script displays:
- **Alice's Public Key (y_A):** The public value Alice sends to Bob
- **Bob's Public Key (y_B):** The public value Bob sends to Alice
- **Shared Secret Key:** The identical secret computed by both parties
- **Verification:** Confirmation that both shared secrets match

### Example Output Format

```
Alice's Public Key (y_A): 0x[hexadecimal value]
Bob's Public Key (y_B): 0x[hexadecimal value]
Shared Secret Key: [hexadecimal value]
✓ Both shared secrets are IDENTICAL!
```

### Security Properties

- **Discrete Logarithm Problem:** The security relies on the difficulty of computing `a` from `g^a mod p` (discrete logarithm problem)
- **Forward Secrecy:** Each key exchange produces a unique shared secret
- **No Key Transmission:** The shared secret is never transmitted over the network
- **Public Values Only:** Only public keys are exchanged; private keys remain secret

### Alternative: OpenSSL Commands (if available)

**Generate DH parameters:**
```bash
openssl dhparam -out dhparams.pem 2048
```

**Generate private key:**
```bash
openssl genpkey -paramfile dhparams.pem -out alice_private.pem
openssl genpkey -paramfile dhparams.pem -out bob_private.pem
```

**Extract public keys:**
```bash
openssl pkey -in alice_private.pem -pubout -out alice_public.pem
openssl pkey -in bob_private.pem -pubout -out bob_public.pem
```

**Derive shared secret:**
```bash
openssl pkeyutl -derive -inkey alice_private.pem -peerkey bob_public.pem -out shared_secret.bin
openssl pkeyutl -derive -inkey bob_private.pem -peerkey alice_public.pem -out shared_secret2.bin
```

**Compare shared secrets:**
```bash
diff shared_secret.bin shared_secret2.bin
```

---

## Task 4B: Real-Life Applications of Diffie-Hellman

### Where Diffie-Hellman is Used

#### 1. TLS/SSL Handshake

Diffie-Hellman is fundamental to the **TLS (Transport Layer Security) handshake**, which secures HTTPS connections. During the TLS handshake, the client and server use Diffie-Hellman (often in the form of Elliptic Curve Diffie-Hellman or ECDH in modern implementations) to establish a shared secret key. This key is then used to derive symmetric encryption keys for the actual data transmission. The TLS handshake ensures that even if someone intercepts all the communication, they cannot decrypt the data because they don't have the shared secret. This is why HTTPS is secure—your web browser and the server can establish a secure connection even if the initial communication is intercepted.

#### 2. Secure Messaging Protocols

Diffie-Hellman is central to **secure messaging applications** like the **Signal Protocol**, which is used by Signal, WhatsApp, and other privacy-focused messaging apps. The Signal Protocol uses an extended version called the "Double Ratchet" algorithm, which combines Diffie-Hellman key exchange with forward secrecy. This means that even if an attacker compromises one session key, they cannot decrypt past or future messages. Each message exchange uses a new Diffie-Hellman key exchange, ensuring that the compromise of one key doesn't affect other communications. This provides end-to-end encryption where only the communicating parties can read the messages, not even the service provider.

#### 3. Other Applications

- **SSH (Secure Shell):** For secure remote login and file transfer
- **VPN protocols:** Like IKE (Internet Key Exchange) for establishing secure tunnels
- **IPsec:** For securing IP communications
- **Secure email protocols:** Like PGP/GPG for key exchange
- **Wireless security:** WPA3 for Wi-Fi encryption

### Why Diffie-Hellman is Important for Secure Communication

Diffie-Hellman is crucial for secure communication because it solves the fundamental problem of **key distribution** in cryptography. In traditional symmetric encryption, both parties need to share a secret key beforehand, which is difficult and risky—if the key is intercepted during transmission, all security is compromised. Diffie-Hellman allows two parties to establish a shared secret over an insecure channel without ever transmitting the secret itself. This means that even if an attacker intercepts all the public values exchanged between Alice and Bob, they cannot compute the shared secret without solving the discrete logarithm problem, which is computationally infeasible for large numbers. This property enables secure communication in scenarios where the parties have never met and have no pre-shared secrets, making it essential for modern internet security, e-commerce, secure messaging, and virtually all encrypted communications we use today.

### Key Benefits

1. **No Pre-Shared Secret Required:** Parties can establish secure communication without meeting beforehand
2. **Forward Secrecy:** Each session uses a unique key, so compromising one doesn't affect others
3. **Public Key Exchange:** Only public values are transmitted, private keys never leave the device
4. **Mathematical Security:** Based on the hardness of the discrete logarithm problem
5. **Foundation for Modern Cryptography:** Enables secure communication protocols used worldwide

---

## Dependencies

The Python scripts use the `cryptography` library:
```bash
pip install cryptography
```

Or install from requirements.txt:
```bash
pip install -r requirements.txt
```

---

## Mathematical Background

### Diffie-Hellman Key Exchange Formula

Given:
- Prime `p` and generator `g` (public parameters)
- Alice's private key: `a`
- Bob's private key: `b`

**Public Keys:**
- Alice's public key: `y_A = g^a mod p`
- Bob's public key: `y_B = g^b mod p`

**Shared Secret:**
- Alice computes: `s = y_B^a mod p = (g^b)^a mod p = g^(ab) mod p`
- Bob computes: `s = y_A^b mod p = (g^a)^b mod p = g^(ab) mod p`
- Both arrive at the same value: `g^(ab) mod p`

### Security Assumption

The security relies on the **Discrete Logarithm Problem (DLP)**:
- Given `g`, `p`, and `y = g^x mod p`, it is computationally infeasible to find `x`
- This means an attacker who intercepts `y_A` and `y_B` cannot compute `a` or `b`
- Without `a` or `b`, they cannot compute the shared secret `g^(ab) mod p`

---

## File Structure

After running the scripts, you should have:
```
.
├── task4a_dh_exchange.py      # DH key exchange simulation
├── task4b_applications.md     # Real-life applications explanation
├── task4_demo.py              # Complete demo script
└── TASK4_DOCUMENTATION.md     # This documentation file
```

---

## Code Summary

### Task 4A: Python Implementation

```python
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

# Generate parameters
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

# Alice generates keys
alice_private = parameters.generate_private_key()
alice_public = alice_private.public_key()

# Bob generates keys
bob_private = parameters.generate_private_key()
bob_public = bob_private.public_key()

# Compute shared secrets
alice_shared = alice_private.exchange(bob_public)
bob_shared = bob_private.exchange(alice_public)

# Verify they match
assert alice_shared == bob_shared
```

---

## Assumptions

1. **Parameter Size:** 2048-bit parameters are used (standard for security)
2. **Generator:** Generator `g = 2` is used (common choice)
3. **Key Format:** Keys are generated using the cryptography library's DH implementation
4. **Security Model:** Assumes the discrete logarithm problem is hard (standard cryptographic assumption)

---

## Security Notes

- **Parameter Size:** 2048-bit parameters provide good security; larger sizes (3072, 4096 bits) provide even more security
- **Elliptic Curve Variants:** Modern implementations often use ECDH (Elliptic Curve Diffie-Hellman) for better efficiency
- **Perfect Forward Secrecy:** Each session should use new key pairs for forward secrecy
- **Key Derivation:** The shared secret should be passed through a key derivation function (KDF) before use
- **Man-in-the-Middle Attacks:** DH alone doesn't prevent MITM attacks; authentication (e.g., certificates) is needed

---

## Verification

The script automatically verifies that:
1. Both parties compute a shared secret
2. The shared secrets are identical
3. The key exchange was successful

This demonstrates that the Diffie-Hellman protocol works correctly and both parties can establish a shared secret without ever transmitting it over the network.

