#!/usr/bin/env python3
"""
Demo: Agent Passport with W3C DID/VC

Demonstrates:
1. Creating decentralized identity for AI agent
2. Generating W3C-compliant DID Document
3. Signing messages with agent's private key
4. Decentralized verification (with public key only)
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sentinel.agent_identity import AgentIdentityManager


def main():
    print("=" * 70)
    print("SIA Sentinel: Agent Passport Demo (W3C DID/VC)")
    print("=" * 70)
    print()
    
    manager = AgentIdentityManager(identities_dir="demo_identities")
    
    # Step 1: Create identity
    print("Step 1: Create Agent Identity")
    print("-" * 70)
    
    passport = manager.create_identity(
        agent_id="copilot-agent-001",
        metadata={
            "type": "github-copilot",
            "owner": "acme-corp",
            "model": "gpt-4",
            "created_by": "platform",
        },
    )
    
    print(f"✓ Agent ID: {passport.agent_id}")
    print(f"✓ DID: {passport.did}")
    print(f"✓ Public Key: {passport.public_key_b64[:32]}...")
    print(f"✓ Created: {passport.created_at}")
    print()
    
    # Step 2: Generate DID Document
    print("Step 2: Generate W3C DID Document")
    print("-" * 70)
    
    did_doc = manager.get_did_document("copilot-agent-001")
    did_json = did_doc.to_json()
    
    print("W3C-compliant DID Document:")
    print(did_json)
    print()
    
    # Step 3: Sign a message
    print("Step 3: Sign Message with Agent's Private Key")
    print("-" * 70)
    
    message = "I verify this code change is safe"
    signature = manager.sign_message("copilot-agent-001", message)
    
    print(f"Message: '{message}'")
    print(f"Signature: {signature}")
    print()
    
    # Step 4: Verify signature (with agent_id)
    print("Step 4: Verify Signature (with agent_id)")
    print("-" * 70)
    
    is_valid = manager.verify_signature("copilot-agent-001", message, signature)
    print(f"✓ Signature valid: {is_valid}")
    print()
    
    # Step 5: Decentralized verification (with public key only!)
    print("Step 5: Decentralized Verification (public key only)")
    print("-" * 70)
    print("Anyone can verify this signature using ONLY the public key,")
    print("without needing access to the agent identity store!")
    print()
    
    is_valid_decentralized = manager.verify_signature_with_public_key(
        public_key_b64=passport.public_key_b64,
        message=message,
        signature_b64=signature,
    )
    
    print(f"✓ Decentralized verification: {is_valid_decentralized}")
    print()
    
    # Step 6: Tamper detection
    print("Step 6: Tamper Detection")
    print("-" * 70)
    print("Attempting to verify tampered message...")
    
    is_valid_tampered = manager.verify_signature_with_public_key(
        public_key_b64=passport.public_key_b64,
        message="I verify this code change is UNSAFE",  # Tampered!
        signature_b64=signature,
    )
    
    print(f"✓ Tampered message detected: {not is_valid_tampered}")
    print()
    
    # Step 7: List all agents
    print("Step 7: List All Registered Agents")
    print("-" * 70)
    
    agents = manager.list_agents()
    print(f"✓ {len(agents)} agent(s) registered:")
    for agent in agents:
        print(f"  - {agent}")
    print()
    
    print("=" * 70)
    print("Demo completed successfully!")
    print("=" * 70)
    print()
    print("Key takeaways:")
    print("  1. Each AI agent has a unique DID (did:sia:<agent_id>)")
    print("  2. DID Documents follow W3C standard")
    print("  3. Agents can sign messages with their private key")
    print("  4. Anyone can verify signatures with public key (decentralized)")
    print("  5. Foundation for Verifiable Credentials (trust levels)")
    print()
    print("Next: Issue Verifiable Credentials for trust levels")
    print()


if __name__ == "__main__":
    main()
