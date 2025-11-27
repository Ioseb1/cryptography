def factorial(n):
    if n < 0:
        raise ValueError("Factorial is not defined for negative numbers")
    
    if n == 0 or n == 1:
        return 1
    
    result = 1
    for i in range(2, n + 1):
        result = result * i
    
    return result


def main():
    test_cases = [0, 1, 5, 7, 10]
    
    print("Original Factorial Function")
    print("=" * 40)
    for num in test_cases:
        result = factorial(num)
        print(f"factorial({num}) = {result}")


if __name__ == "__main__":
    main()

