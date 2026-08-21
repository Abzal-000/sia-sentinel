#!/usr/bin/env python3
"""
Demo: Cryptographic Receipts for AI Code Verification

Receipts are signed with Ed25519:
- Anyone can verify a receipt with just the public key (no signing secret)
- Anyone can verify a receipt without access to the original code
- Receipts cannot be tampered with
"""

import json
import requests

API_BASE = "http://127.0.0.1:8000"

def main():
    print("=" * 70)
    print("SIA Sentinel: Cryptographic Receipts Demo")
    print("=" * 70)
    print()
    
    # Step 1: Submit code for verification
    print("Step 1: Submit code for verification")
    print("-" * 70)
    
    payload = {
        "agent_id": "demo-agent-001",
        "description": "Optimize fibonacci function",
        "target_path": "src/fib.py",
        "current_code": "def fib(n): return fib(n-1) + fib(n-2) if n > 1 else n",
        "proposed_code": "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a",
        "allowed_paths": ["src/fib.py"]
    }
    
    response = requests.post(f"{API_BASE}/v1/verify-change", json=payload)
    result = response.json()
    
    print(f"✓ Verification completed")
    print(f"  Evidence ID: {result['evidence_id']}")
    print(f"  Approved: {result['decision']['approved']}")
    print(f"  Safety Score: {result['safety']['approved']}")
    print()
    
    # Step 2: Extract receipt
    print("Step 2: Extract cryptographic receipt")
    print("-" * 70)
    
    receipt = result["cryptographic_receipt"]
    print(f"✓ Receipt generated")
    print(f"  Receipt ID: {receipt['receipt_id']}")
    print(f"  Code Hash: {receipt['code_hash'][:32]}...")
    print(f"  Trust Level: {receipt['trust_level']}")
    print(f"  Signature: {receipt['signature'][:32]}...")
    print()
    
    # Step 3: Verify receipt (public-key verification)
    print("Step 3: Verify receipt (public Ed25519 key)")
    print("-" * 70)
    print("Anyone can verify this receipt without:")
    print("  - Knowing the secret signing key (only the public key is needed)")
    print("  - Having access to the original code")
    print("  - Trusting the verifier")
    print()
    
    verify_payload = {"receipt": receipt}
    verify_response = requests.post(f"{API_BASE}/v1/verify-receipt", json=verify_payload)
    verify_result = verify_response.json()
    
    print(f"✓ Verification result: {verify_result['valid']}")
    print()
    
    # Step 4: Demonstrate tamper detection
    print("Step 4: Demonstrate tamper detection")
    print("-" * 70)
    print("Attempting to tamper with receipt...")
    
    tampered_receipt = receipt.copy()
    tampered_receipt["safety_approved"] = not tampered_receipt["safety_approved"]
    
    tamper_payload = {"receipt": tampered_receipt}
    tamper_response = requests.post(f"{API_BASE}/v1/verify-receipt", json=tamper_payload)
    tamper_result = tamper_response.json()
    
    print(f"✓ Tampered receipt detected: {not tamper_result['valid']}")
    print()
    
    # Step 5: Show JSON receipt
    print("Step 5: Portable receipt (JSON)")
    print("-" * 70)
    print("This receipt can be shared, stored on blockchain, or verified by anyone:")
    print()
    print(json.dumps(receipt, indent=2))
    print()
    
    print("=" * 70)
    print("Demo completed successfully!")
    print("=" * 70)
    print()
    print("Key takeaways:")
    print("  1. Each verification generates a cryptographic receipt")
    print("  2. Receipts are verified with the public key only (Ed25519)")
    print("  3. Receipts cannot be tampered with (cryptographic signatures)")
    print("  4. Receipts are portable (JSON format)")
    print()
    print("This is the foundation for future zkML integration.")
    print("In production, Ed25519 receipts would be replaced with zk-SNARKs,")
    print("proving the verification computation itself.")
    print()

if __name__ == "__main__":
    main()
