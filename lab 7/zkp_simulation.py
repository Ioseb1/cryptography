import random

def simulate_zkp(trials=20):
    print("=" * 60)
    print("Zero-Knowledge Proof Simulation - Ali Baba Cave Protocol")
    print("=" * 60)
    print()
    
    print("Scenario 1: Legitimate Prover (knows password)")
    print("-" * 60)
    legitimate_success_count = 0
    
    for trial in range(1, trials + 1):
        path_entered = random.choice(['A', 'B'])
        challenge = random.choice(['A', 'B'])
        knows_password = True
        
        if knows_password:
            success = True
        else:
            success = path_entered == challenge
        
        if success:
            legitimate_success_count += 1
        
        if trial <= 5:
            print(f"Trial {trial}: Entered path {path_entered}, Challenge: {challenge}, Success: {success}")
    
    if trials > 5:
        print(f"... ({trials - 5} more trials)")
    
    legitimate_probability = legitimate_success_count / trials
    print(f"\nLegitimate Prover Results:")
    print(f"  Successful responses: {legitimate_success_count}/{trials}")
    print(f"  Success probability: {legitimate_probability:.2%}")
    print()
    
    print("Scenario 2: Malicious Prover (doesn't know password)")
    print("-" * 60)
    malicious_success_count = 0
    
    for trial in range(1, trials + 1):
        path_entered = random.choice(['A', 'B'])
        challenge = random.choice(['A', 'B'])
        knows_password = False
        
        if knows_password:
            success = True
        else:
            success = path_entered == challenge
        
        if success:
            malicious_success_count += 1
        
        if trial <= 5:
            print(f"Trial {trial}: Entered path {path_entered}, Challenge: {challenge}, Success: {success}")
    
    if trials > 5:
        print(f"... ({trials - 5} more trials)")
    
    malicious_probability = malicious_success_count / trials
    print(f"\nMalicious Prover Results:")
    print(f"  Successful responses: {malicious_success_count}/{trials}")
    print(f"  Success probability: {malicious_probability:.2%}")
    print()
    
    print("=" * 60)
    print("Analysis:")
    print("=" * 60)
    print(f"Legitimate prover success rate: {legitimate_probability:.2%}")
    print(f"Malicious prover success rate: {malicious_probability:.2%}")
    print()
    
    if legitimate_probability == 1.0:
        print("✓ Legitimate prover always succeeds (100% success rate)")
    else:
        print(f"⚠ Legitimate prover had {1.0 - legitimate_probability:.2%} failure rate")
    
    print(f"✓ Malicious prover succeeds approximately 50% of the time (guessing)")
    print()
    print("Security Property:")
    print("  - A single round gives a malicious prover a 50% chance of success")
    print("  - Multiple rounds exponentially reduce the chance of success")
    print("  - After n rounds, malicious prover success probability = (1/2)^n")
    
    print()
    print("Malicious prover success probability after multiple rounds:")
    for rounds in [1, 5, 10, 20]:
        prob = (0.5) ** rounds
        print(f"  {rounds} rounds: {prob:.6f} ({prob:.4%})")


if __name__ == "__main__":
    simulate_zkp(trials=20)

