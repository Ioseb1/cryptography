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

def caesar_cypher_dencrypt(ciphertext, shift):
    return caesar_cipher_encrypt(ciphertext, -shift)


plaintext = "Hello World"
shift = 3
cyphertext = caesar_cipher_encrypt(plaintext, shift)
decripted_text = caesar_cypher_dencrypt(cyphertext, shift)
print("Plaintext: ", plaintext)
print("Shift: ", shift)
print("Encypted text: ", cyphertext)
print("Decripted text: ", decripted_text)