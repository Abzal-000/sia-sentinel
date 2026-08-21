#!/usr/bin/env python3
"""
Demo: Portable Reputation via Verifiable Credentials

Demonstrates complete flow:
1. Agent works at Org A, builds reputation
2. Org A issues Verifiable Credential
3. Agent moves to Org B
4. Org B verifies credential and trusts agent immediately
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import requests

API_BASE = "http://127.0.0.1:8000"


def main():
    print("=" * 70)
    print("SIA Sentinel: Portable Reputation Demo")
    print("=" * 70)
    print()
    
    agent_id = "alice-agent-001"
    
    # ===== ORG A: Building Reputation =====
    print("=" * 70)
    print("ORG A: Agent builds reputation through successful verifications")
    print("=" * 70)
    print()
    
    print("Agent completes 25 successful verifications, 5 failures...")
    print()
    
    # Org A issues credential after agent proves reliability
    print("Org A issues Verifiable Credential:")
    response = requests.post(
        f"{API_BASE}/v1/agents/{agent_id}/issue-credential",
        params={
            "trust_level": "JUNIOR",
            "success_count": 25,
            "failure_count": 5,
        },
    )
    
    if response.status_code != 200:
        print(f"ERROR: {response.text}")
        return
    
    data = response.json()
    credential = data["credential"]
    
    print(f"✓ Credential issued")
    print(f"  ID: {credential['id']}")
    print(f"  Trust Level: {credential['credentialSubject']['trustLevel']}")
    print(f"  Success Rate: {credential['credentialSubject']['successRate']:.1%}")
    print(f"  Issuer: {credential['issuer']}")
    print()
    
    # Show credential
    print("Verifiable Credential (JSON):")
    print("-" * 70)
    print(json.dumps(credential, indent=2))
    print("-" * 70)
    print()
    
    # ===== AGENT MOVES TO ORG B =====
    print("=" * 70)
    print("AGENT MOVES TO ORG B")
    print("=" * 70)
    print()
    print("Agent shares credential with Org B...")
    print()
    
    # ===== ORG B: Verifying Credential =====
    print("=" * 70)
    print("ORG B: Verifying agent's credential")
    print("=" * 70)
    print()
    
    print("Org B verifies credential using issuer's public key...")
    verify_response = requests.post(
        f"{API_BASE}/v1/verify-credential",
        json=credential,
    )
    
    if verify_response.status_code != 200:
        print(f"ERROR: {verify_response.text}")
        return
    
    verify_data = verify_response.json()
    
    print(f"✓ Credential valid: {verify_data['valid']}")
    print(f"✓ Expired: {verify_data['expired']}")
    print(f"✓ Trust Level: {verify_data['trust_level']}")
    print()
    
    if not verify_data['valid']:
        print(f"✗ Verification failed: {verify_data.get('error')}")
        return
    
    # ===== ORG B: Trusting Agent =====
    print("=" * 70)
    print("ORG B: Trusting agent based on verified credential")
    print("=" * 70)
    print()
    
    print("Since credential is valid, Org B:")
    print(f"  1. Trusts agent at level: {verify_data['trust_level']}")
    print(f"  2. Skips probation period")
    print(f"  3. Allows immediate access to {verify_data['trust_level']} privileges")
    print()
    
    print("Result: Agent can start working immediately with full JUNIOR privileges!")
    print()
    
    # ===== TAMPER DETECTION =====
    print("=" * 70)
    print("SECURITY: Tamper Detection")
    print("=" * 70)
    print()
    
    print("What if agent tries to fake higher trust level?")
    print()
    
    tampered = json.loads(json.dumps(credential))
    tampered["credentialSubject"]["trustLevel"] = "SENIOR"
    
    print("Agent changes trustLevel from JUNIOR to SENIOR...")
    print()
    
    tamper_response = requests.post(
        f"{API_BASE}/v1/verify-credential",
        json=tampered,
    )
    
    tamper_data = tamper_response.json()
    
    print(f"✓ Tampered credential detected: {not tamper_data['valid']}")
    print(f"✓ Error: {tamper_data.get('error')}")
    print()
    
    print("Cryptographic signature prevents forgery!")
    print()
    
    # ===== RETRIEVE CREDENTIALS =====
    print("=" * 70)
    print("API: Retrieve agent's credentials")
    print("=" * 70)
    print()
    
    creds_response = requests.get(
        f"{API_BASE}/v1/agents/{agent_id}/credentials"
    )
    
    if creds_response.status_code == 200:
        creds_data = creds_response.json()
        print(f"✓ Found {creds_data['count']} credential(s) for {agent_id}")
        
        for i, cred in enumerate(creds_data["credentials"], 1):
            print(f"  {i}. {cred['credentialSubject']['trustLevel']} "
                  f"(issued: {cred['issuanceDate'][:10]})")
    print()
    
    # ===== SUMMARY =====
    print("=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)
    print()
    print("Key achievements:")
    print("  ✓ Agent reputation is portable across organizations")
    print("  ✓ Credentials are cryptographically signed")
    print("  ✓ Anyone can verify credentials (decentralized)")
    print("  ✓ Tampered credentials are detected")
    print("  ✓ No central authority needed for verification")
    print()
    print("This enables a GLOBAL TRUST NETWORK for AI agents!")
    print()
    print("Next steps:")
    print("  1. Deploy to production with proper key management")
    print("  2. Integrate with existing trust systems")
    print("  3. Build reputation marketplace")
    print()


if __name__ == "__main__":
    main()
