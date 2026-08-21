#!/usr/bin/env python3
"""
Demo: Decentralized Verification Network

Demonstrates:
1. Verifier registration with staking
2. Task submission and assignment
3. Verification and reward distribution
4. Reputation system
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sentinel.verification_network import VerificationNetwork


def main():
    print("=" * 70)
    print("SIA Sentinel: Decentralized Verification Network Demo")
    print("=" * 70)
    print()

    # Демо всегда стартует с чистого состояния
    for state_file in ("demo_registry.json", "demo_queue.json"):
        Path(state_file).unlink(missing_ok=True)

    # Initialize network
    network = VerificationNetwork(
        registry_file="demo_registry.json",
        queue_file="demo_queue.json",
    )
    
    # ===== STEP 1: Register Verifiers =====
    print("STEP 1: Register Verifiers")
    print("-" * 70)
    
    # Register 3 verifiers with different capabilities
    verifiers = [
        ("verifier-python-expert", ["python", "security", "performance"], 200.0),
        ("verifier-js-expert", ["javascript", "typescript"], 150.0),
        ("verifier-fullstack", ["python", "javascript", "security"], 300.0),
    ]
    
    for verifier_id, capabilities, stake in verifiers:
        result = network.register_verifier(
            verifier_id=verifier_id,
            capabilities=capabilities,
            stake_amount=stake,
            initial_balance=1000.0,
        )
        
        print(f"✓ Registered {verifier_id}")
        print(f"  Capabilities: {', '.join(capabilities)}")
        print(f"  Staked: {stake} SIA tokens")
        print(f"  Balance: {result['balance']} SIA tokens")
        print()
    
    # ===== STEP 2: Submit Verification Tasks =====
    print("STEP 2: Submit Verification Tasks")
    print("-" * 70)
    
    tasks = [
        ("task-1", "python", ["python", "security"], 50.0),
        ("task-2", "javascript", ["javascript"], 30.0),
        ("task-3", "fullstack", ["python", "javascript"], 75.0),
    ]
    
    for task_name, lang, requirements, reward in tasks:
        code_hash = f"hash_{task_name}"
        result = network.submit_verification(
            code_hash=code_hash,
            requirements=requirements,
            reward=reward,
        )
        
        print(f"✓ Submitted {task_name}")
        print(f"  Requirements: {', '.join(requirements)}")
        print(f"  Reward: {reward} SIA tokens")
        print(f"  Task ID: {result['task_id'][:16]}...")
        print()
    
    # ===== STEP 3: Verifiers Claim Tasks =====
    print("STEP 3: Verifiers Claim Tasks")
    print("-" * 70)
    
    claimed_tasks = []
    for verifier_id, _, _ in verifiers:
        result = network.claim_task(verifier_id)
        
        if result["success"]:
            task = result["task"]
            print(f"✓ {verifier_id} claimed task {task['task_id'][:16]}...")
            print(f"  Requirements: {', '.join(task['requirements'])}")
            print(f"  Reward: {task['reward']} SIA tokens")
            claimed_tasks.append((verifier_id, task["task_id"]))
        else:
            print(f"✗ {verifier_id} could not claim task: {result['error']}")
        print()
    
    # ===== STEP 4: Submit Verification Results =====
    print("STEP 4: Submit Verification Results")
    print("-" * 70)
    
    for verifier_id, task_id in claimed_tasks:
        # Simulate successful verification
        result = network.submit_result(
            task_id=task_id,
            verifier_id=verifier_id,
            result={"approved": True, "violations": [], "performance_gain": 0.15},
            success=True,
        )
        
        print(f"✓ {verifier_id} completed task")
        print(f"  Result: Approved")
        print(f"  Reward earned: {result['reward']} SIA tokens")
        print(f"  New balance: {result['new_balance']} SIA tokens")
        print(f"  Reputation: {result['reputation']}")
        print()
    
    # ===== STEP 5: Network Statistics =====
    print("STEP 5: Network Statistics")
    print("-" * 70)
    
    stats = network.get_network_stats()
    
    print(f"Total Verifiers: {stats['total_verifiers']}")
    print(f"Pending Tasks: {stats['pending_tasks']}")
    print(f"In Progress Tasks: {stats['in_progress_tasks']}")
    print(f"Completed Tasks: {stats['completed_tasks']}")
    print(f"Average Reputation: {stats['average_reputation']:.1f}")
    print(f"Total Staked: {stats['total_staked']} SIA tokens")
    print()
    
    # ===== STEP 6: Show Verifier Details =====
    print("STEP 6: Verifier Details")
    print("-" * 70)
    
    for verifier in network.registry.list_verifiers():
        print(f"Verifier: {verifier.id}")
        print(f"  Capabilities: {', '.join(verifier.capabilities)}")
        print(f"  Reputation: {verifier.reputation}")
        print(f"  Success Count: {verifier.success_count}")
        print(f"  Failure Count: {verifier.failure_count}")
        print(f"  Total Earned: {verifier.total_earned} SIA tokens")
        print(f"  Success Rate: {verifier.success_rate:.1%}")
        print()
    
    # ===== SUMMARY =====
    print("=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)
    print()
    print("Key achievements:")
    print("  ✓ Decentralized verifier registration with staking")
    print("  ✓ Task queue with automatic assignment")
    print("  ✓ Token-based reward system")
    print("  ✓ Reputation tracking")
    print("  ✓ Network statistics")
    print()
    print("This creates a MARKETPLACE for code verification!")
    print()
    print("Next steps:")
    print("  1. Add API endpoints for network operations")
    print("  2. Integrate with real blockchain for tokens")
    print("  3. Add slashing for malicious verifiers")
    print("  4. Implement dispute resolution")
    print()


if __name__ == "__main__":
    main()
