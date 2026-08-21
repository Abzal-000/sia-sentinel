#!/usr/bin/env python3
"""
Demo: Verifiable Credentials for Agent Trust Levels

Demonstrates:
1. Issuing trust level credentials
2. Storing credentials on disk
3. Verifying credentials (decentralized)
4. Portable reputation across organizations
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sentinel.agent_identity import AgentIdentityManager
from sentinel.trust_credentials import (
    TrustCredentialIssuer,
    TrustCredentialVerifier,
)


def main():
    print("=" * 70)
    print("SIA Sentinel: Verifiable Credentials Demo")
    print("=" * 70)
    print()
    
    # Initialize
    identity_manager = AgentIdentityManager(identities_dir="demo_identities")
    issuer = TrustCredentialIssuer(
        identity_manager=identity_manager,
        credentials_dir="demo_credentials",
    )
    verifier = TrustCredentialVerifier(identity_manager=identity_manager)
    
    # Step 1: Create agent identity
    print("Step 1: Create Agent Identity")
    print("-" * 70)
    
    agent_passport = identity_manager.create_identity(
        agent_id="copilot-agent-002",
        metadata={"type": "github-copilot", "owner": "acme-corp"},
    )
    
    print(f"✓ Agent DID: {agent_passport.did}")
    print(f"✓ Public Key: {agent_passport.public_key_b64[:32]}...")
    print()
    
    # Step 2: Issue trust credential
    print("Step 2: Issue Trust Level Credential")
    print("-" * 70)
    
    credential = issuer.issue_trust_credential(
        agent_did=agent_passport.did,
        trust_level="JUNIOR",
        success_count=25,
        verification_count=30,
        expires_in_days=365,
    )
    
    print(f"✓ Credential ID: {credential.id}")
    print(f"✓ Issuer: {credential.issuer}")
    print(f"✓ Trust Level: {credential.credential_subject['trustLevel']}")
    print(f"✓ Success Rate: {credential.credential_subject['successRate']:.2%}")
    print()
    
    # Step 3: Show credential JSON
    print("Step 3: Verifiable Credential (JSON)")
    print("-" * 70)
    print("This credential can be shared with any organization:")
    print()
    print(credential.to_json())
    print()
    
    # Step 4: Verify credential
    print("Step 4: Verify Credential")
    print("-" * 70)
    
    result = verifier.verify_credential(credential)
    
    print(f"✓ Valid: {result['valid']}")
    print(f"✓ Expired: {result['expired']}")
    if result['error']:
        print(f"✗ Error: {result['error']}")
    print()
    
    # Step 5: Tamper detection
    print("Step 5: Tamper Detection")
    print("-" * 70)
    print("Attempting to tamper with credential...")
    
    credential.credential_subject["trustLevel"] = "SENIOR"
    result = verifier.verify_credential(credential)
    
    print(f"✓ Tampered credential detected: {not result['valid']}")
    if result['error']:
        print(f"  Error: {result['error']}")
    print()
    
    # Step 6: Retrieve credentials
    print("Step 6: Retrieve Agent Credentials")
    print("-" * 70)
    
    credentials = issuer.get_credentials(agent_passport.did)
    print(f"✓ {len(credentials)} credential(s) found for {agent_passport.did}")
    
    latest = issuer.get_latest_credential(agent_passport.did)
    if latest:
        print(f"✓ Latest trust level: {latest.credential_subject['trustLevel']}")
    print()
    
    # Step 7: Portable reputation
    print("Step 7: Portable Reputation Scenario")
    print("-" * 70)
    print("Scenario: Agent moves from Org A to Org B")
    print()
    print("1. Org A issues credential: JUNIOR (25/30 success)")
    print("2. Agent shares credential with Org B")
    print("3. Org B verifies credential using issuer public key")
    print("4. Org B trusts agent immediately (no probation period)")
    print()
    print("This is PORTABLE REPUTATION!")
    print()
    
    print("=" * 70)
    print("Demo completed successfully!")
    print("=" * 70)
    print()
    print("Key takeaways:")
    print("  1. Trust levels are issued as Verifiable Credentials")
    print("  2. Credentials are cryptographically signed")
    print("  3. Anyone can verify credentials (decentralized)")
    print("  4. Tampered credentials are detected")
    print("  5. Reputation is portable across organizations")
    print()
    print("This creates a GLOBAL TRUST NETWORK for AI agents!")
    print()


if __name__ == "__main__":
    main()
