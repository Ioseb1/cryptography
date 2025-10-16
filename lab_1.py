# Ioseb Matiashvili

import base64

# Task 1 - decrypt given cyphertext: “Hvs Eiwqy Pfckb Tcl Xiadg Cjsf Hvs Zonm Rcu.”
def caesar_cipher_encrypt(text, shift):
    result = ""

    for i in range(len(text)):
        char = text[i]

        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            result += char
    return result

def caesar_cypher_decrypt(ciphertext, shift):
    return caesar_cipher_encrypt(ciphertext, -shift)


cypher_text1 = "Hvs Eiwqy Pfckb Tcl Xiadg Cjsf Hvs Zonm Rcu."
for i in range(1, 26):
    print(f"Shift {i}: {caesar_cypher_decrypt(cypher_text1, i)}") # decrypted text is "The Brave New World That Lies The Dark Sea" and shift is 13

# Why is Caesar cipher insecure? Where might legacy systems still use
# similar encryption?

### Basically Caesar cipher is insecure because it has a very small key space (only 25 possible shifts),
### which makes it vulnerable to brute-force attacks. An attacker can easily try all possible shifts with 2 lines of code.
### Additionally, frequency analysis can be used to break the cipher by analyzing the frequency of letters in the ciphertext and comparing them to known letter frequencies in the language of the plaintext.

#  Task 2 - XOR Encryption/Decryption 
## Step 1: Caesar Cipher Challenge
cypher_text2 = "mznxpz"
for i in range(1, 26):
    print(f"Shift {i}: {caesar_cypher_decrypt(cypher_text2, i)}") # word is rescue and shift is 21

# Step 2: Solve the Anagram
anagram = "secure"

# Step 3: XOR Decryption
cypher_text3_base64 = "Jw0KBlIMAEUXHRdFKyoxVRENEgkPEBwCFkQ="
decoded_cyper_text3 = base64.b64decode(cypher_text3_base64)


def xor_decrypt(data, key):
    key_bytes = key.encode()
    key_len = len(key_bytes)
    return bytes([data[i] ^ key_bytes[i % key_len] for i in range(len(data))])

plain_bytes = xor_decrypt(decoded_cyper_text3, anagram)
print(plain_bytes.decode())