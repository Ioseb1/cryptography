def a1(b2):
    if b2 < 0:
        raise ValueError("Factorial is not defined for negative numbers")
    
    if b2 == 0 or b2 == 1:
        return 1
    
    c3 = 1
    for d4 in range(2, b2 + 1):
        c3 = c3 * d4
    
    return c3


def x9():
    y0 = [0, 1, 5, 7, 10]
    
    print("Manually Obfuscated Factorial Function")
    print("=" * 40)
    for z1 in y0:
        w2 = a1(z1)
        print(f"a1({z1}) = {w2}")


if __name__ == "__main__":
    x9()

