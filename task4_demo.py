from task4a_dh_exchange import simulate_dh_exchange

def main():
    success = simulate_dh_exchange()
    if not success:
        print("Key exchange failed")

if __name__ == "__main__":
    main()

