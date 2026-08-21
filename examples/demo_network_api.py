#!/usr/bin/env python3
"""
Demo: Verification Network API (JSON body version)
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import requests

API_BASE = "http://127.0.0.1:8000"


def main():
    print("=" * 70)
    print("SIA Sentinel: Verification Network API Demo")
    print("=" * 70)
    print()
    
    # ===== STEP 1: Register Verifiers =====
    print("STEP 1: Register Verifiers via API")
    print("-" * 70)
    
    verifiers = [
        ("api-verifier-python", ["python", "security"], 200.0),
        ("api-verifier-js", ["javascript", "typescript"], 150.0),
        ("api-verifier-fullstack", ["python", "javascript", "security"], 300.0),
    ]
    
    for verifier_id, capabilities, stake in verifiers:
        response = requests.post(
            f"{API_BASE}/v1/network/register-verifier",
            json={
                "verifier_id": verifier_id,
                "capabilities": capabilities,
                "stake_amount": stake,
                "initial_balance": 1000.0,
            },
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Registered {verifier_id}")
            print(f"  Capabilities: {', '.join(capabilities)}")
            print(f"  Staked: {stake} SIA tokens")
            print(f"  Balance: {data['balance']} SIA tokens")
        else:
            print(f"✗ Failed to register {verifier_id}: {response.text}")
        print()
    
    # ===== STEP 2: Submit Tasks =====
    print("STEP 2: Submit Verification Tasks via API")
    print("-" * 70)
    
    tasks = [
        ("api-task-1", ["python", "security"], 50.0),
        ("api-task-2", ["javascript"], 30.0),
        ("api-task-3", ["python", "javascript"], 75.0),
    ]
    
    task_ids = []
    for task_name, requirements, reward in tasks:
        response = requests.post(
            f"{API_BASE}/v1/network/submit-task",
            json={
                "code_hash": f"hash_{task_name}",
                "requirements": requirements,
                "reward": reward,
            },
        )
        
        if response.status_code == 200:
            data = response.json()
            task_id = data["task_id"]
            task_ids.append(task_id)
            print(f"✓ Submitted {task_name}")
            print(f"  Task ID: {task_id[:16]}...")
            print(f"  Requirements: {', '.join(requirements)}")
            print(f"  Reward: {reward} SIA tokens")
        else:
            print(f"✗ Failed to submit {task_name}: {response.text}")
        print()
    
    # ===== STEP 3: Claim Tasks =====
    print("STEP 3: Verifiers Claim Tasks via API")
    print("-" * 70)
    
    claimed = []
    for verifier_id, _, _ in verifiers:
        response = requests.post(
            f"{API_BASE}/v1/network/claim-task/{verifier_id}"
        )
        
        if response.status_code == 200:
            data = response.json()
            task = data["task"]
            claimed.append((verifier_id, task["task_id"]))
            print(f"✓ {verifier_id} claimed task {task['task_id'][:16]}...")
            print(f"  Reward: {task['reward']} SIA tokens")
        else:
            print(f"✗ {verifier_id} could not claim: {response.text}")
        print()
    
    # ===== STEP 4: Submit Results =====
    print("STEP 4: Submit Verification Results via API")
    print("-" * 70)
    
    for verifier_id, task_id in claimed:
        response = requests.post(
            f"{API_BASE}/v1/network/submit-result",
            json={
                "task_id": task_id,
                "verifier_id": verifier_id,
                "result": {"approved": True, "violations": [], "performance_gain": 0.12},
                "success": True,
            },
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✓ {verifier_id} completed task")
            print(f"  Reward earned: {data['reward']} SIA tokens")
            print(f"  New balance: {data['new_balance']} SIA tokens")
            print(f"  Reputation: {data['reputation']}")
        else:
            print(f"✗ Failed to submit result: {response.text}")
        print()
    
    # ===== STEP 5: Network Statistics =====
    print("STEP 5: Network Statistics via API")
    print("-" * 70)
    
    response = requests.get(f"{API_BASE}/v1/network/stats")
    
    if response.status_code == 200:
        stats = response.json()
        print(f"Total Verifiers: {stats['total_verifiers']}")
        print(f"Pending Tasks: {stats['pending_tasks']}")
        print(f"In Progress Tasks: {stats['in_progress_tasks']}")
        print(f"Completed Tasks: {stats['completed_tasks']}")
        print(f"Average Reputation: {stats['average_reputation']:.1f}")
        print(f"Total Staked: {stats['total_staked']} SIA tokens")
    print()
    
    # ===== STEP 6: List Verifiers =====
    print("STEP 6: List All Verifiers via API")
    print("-" * 70)
    
    response = requests.get(f"{API_BASE}/v1/network/verifiers")
    
    if response.status_code == 200:
        data = response.json()
        print(f"Total verifiers: {data['count']}")
        print()
        
        for verifier in data["verifiers"]:
            print(f"Verifier: {verifier['id']}")
            print(f"  Capabilities: {', '.join(verifier['capabilities'])}")
            print(f"  Reputation: {verifier['reputation']}")
            print(f"  Success Rate: {verifier['success_rate']:.1%}")
            print(f"  Total Earned: {verifier['total_earned']} SIA tokens")
            print()
    
    # ===== SUMMARY =====
    print("=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)
    print()
    print("Key achievements:")
    print("  ✓ Verifier registration via REST API (JSON body)")
    print("  ✓ Task submission and claiming via API")
    print("  ✓ Result submission with token rewards")
    print("  ✓ Network statistics endpoint")
    print("  ✓ Verifier listing endpoint")
    print()
    print("The Verification Network is now fully accessible via REST API!")
    print()


if __name__ == "__main__":
    main()
