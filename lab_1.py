# Ioseb Matiashvili

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


cypher_text = "Hvs Eiwqy Pfckb Tcl Xiadg Cjsf Hvs Zonm Rcu."
for i in range(1, 26):
    print(f"Shift {i}: {caesar_cypher_decrypt(cypher_text, i)}")

# Why is Caesar cipher insecure? Where might legacy systems still use
# similar encryption?

### Basically Caesar cipher is insecure because it has a very small key space (only 25 possible shifts),
### which makes it vulnerable to brute-force attacks. An attacker can easily try all possible shifts with 2 lines of code.
### Additionally, frequency analysis can be used to break the cipher by analyzing the frequency of letters in the ciphertext and comparing them to known letter frequencies in the language of the plaintext.

