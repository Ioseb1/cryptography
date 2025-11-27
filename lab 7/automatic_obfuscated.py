import base64

encoded_code = b'ZGVmIGZhY3RvcmlhbChuKToKICAgIGlmIG4gPCAwOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoIkZhY3RvcmlhbCBpcyBub3QgZGVmaW5lZCBmb3IgbmVnYXRpdmUgbnVtYmVycyIpCiAgICAKICAgIGlmIG4gPT0gMCBvciBuID09IDE6CiAgICAgICAgcmV0dXJuIDEKICAgIAogICAgcmVzdWx0ID0gMQogICAgZm9yIGkgaW4gcmFuZ2UoMiwgbiArIDEpOgogICAgICAgIHJlc3VsdCA9IHJlc3VsdCAqIGkKICAgIAogICAgcmV0dXJuIHJlc3VsdA=='

decoded_code = base64.b64decode(encoded_code).decode('utf-8')
exec(decoded_code)

def factorial_obfuscated(n):
    return factorial(n)


def main():
    test_cases = [0, 1, 5, 7, 10]
    
    print("Automatically Obfuscated Factorial Function")
    print("=" * 40)
    for num in test_cases:
        result = factorial_obfuscated(num)
        print(f"factorial_obfuscated({num}) = {result}")


if __name__ == "__main__":
    main()

