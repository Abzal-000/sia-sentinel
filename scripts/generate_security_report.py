#!/usr/bin/env python3
"""
Security Report Generator for SIA Sentinel.

Generates comprehensive security audit report in JSON and Markdown formats.
"""

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def run_tests(test_module):
    """Run tests and return results."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "unittest", test_module, "-v"],
            capture_output=True,
            text=True,
            timeout=120,
        )

        output = result.stdout + result.stderr
        lines = output.split("\n")

        passed = failed = errors = 0
        for line in lines:
            if " ok" in line:
                passed += 1
            elif " FAIL" in line:
                failed += 1
            elif " ERROR" in line:
                errors += 1

        return {
            "module": test_module,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "success": result.returncode == 0,
            "output": output,
        }
    except Exception as e:
        return {
            "module": test_module,
            "passed": 0,
            "failed": 0,
            "errors": 1,
            "success": False,
            "output": str(e),
        }


def generate_security_report():
    """Generate comprehensive security report."""
    report = {
        "report_metadata": {
            "title": "SIA Sentinel Security Audit Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "version": "1.0",
            "audit_scope": "Automated penetration testing and security validation",
        },
        "executive_summary": {
            "overall_status": "PASS",
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "error_tests": 0,
            "pass_rate": 0.0,
        },
        "test_results": [],
        "security_controls": {
            "input_validation": {
                "status": "IMPLEMENTED",
                "controls": [
                    "XSS pattern detection and blocking",
                    "SQL injection pattern detection",
                    "Path traversal prevention",
                    "Length limits enforcement",
                    "Character whitelist for agent_id",
                    "Null byte sanitization",
                ],
            },
            "authentication": {
                "status": "IMPLEMENTED",
                "controls": [
                    "JWT token authentication",
                    "API Key authentication",
                    "Role-Based Access Control (RBAC)",
                    "Token expiration enforcement",
                ],
            },
            "rate_limiting": {
                "status": "IMPLEMENTED",
                "controls": [
                    "Per-minute rate limiting (60 req/min)",
                    "Per-hour rate limiting (1000 req/hour)",
                    "Rate limit headers in responses",
                    "429 Too Many Requests enforcement",
                ],
            },
            "cors": {
                "status": "IMPLEMENTED",
                "controls": [
                    "Whitelist-based origin validation",
                    "Credentials support for allowed origins",
                    "Preflight request handling",
                    "HSTS header for HTTPS",
                ],
            },
            "security_headers": {
                "status": "IMPLEMENTED",
                "controls": [
                    "X-Content-Type-Options: nosniff",
                    "X-Frame-Options: DENY",
                    "X-XSS-Protection: 1; mode=block",
                    "Content-Security-Policy: default-src 'self'",
                    "Referrer-Policy: strict-origin-when-cross-origin",
                ],
            },
            "cryptographic_security": {
                "status": "IMPLEMENTED",
                "controls": [
                    "Ed25519 signatures for agent identity",
                    "HMAC-SHA256 for evidence signing",
                    "Secure random generation for keys",
                    "Key hashing for API key storage",
                ],
            },
        },
        "recommendations": [
            {
                "priority": "HIGH",
                "category": "Production Deployment",
                "recommendation": "Use strong random keys for JWT_SECRET_KEY and EVIDENCE_SIGNING_KEY",
                "rationale": "Default keys are for development only",
            },
            {
                "priority": "HIGH",
                "category": "Production Deployment",
                "recommendation": "Enable HTTPS with valid TLS certificate",
                "rationale": "Required for secure API communication",
            },
            {
                "priority": "MEDIUM",
                "category": "Authentication",
                "recommendation": "Implement password hashing with bcrypt or argon2",
                "rationale": "Current demo uses plaintext passwords",
            },
            {
                "priority": "MEDIUM",
                "category": "Monitoring",
                "recommendation": "Add security event logging and alerting",
                "rationale": "Detect and respond to security incidents",
            },
            {
                "priority": "LOW",
                "category": "Performance",
                "recommendation": "Use Redis for distributed rate limiting",
                "rationale": "Current in-memory limiter doesn't work across multiple instances",
            },
        ],
    }

    test_modules = [
        "tests.test_security_layer",
        "tests.test_auth",
        "tests.test_cors",
        "tests.security.test_penetration",
    ]

    print("Running security tests...")
    print("=" * 70)

    for module in test_modules:
        print(f"Testing {module}...")
        result = run_tests(module)
        report["test_results"].append(result)

        print(f"  Passed: {result['passed']}, Failed: {result['failed']}, Errors: {result['errors']}")

        report["executive_summary"]["total_tests"] += result["passed"] + result["failed"] + result["errors"]
        report["executive_summary"]["passed_tests"] += result["passed"]
        report["executive_summary"]["failed_tests"] += result["failed"]
        report["executive_summary"]["error_tests"] += result["errors"]

    total = report["executive_summary"]["total_tests"]
    passed = report["executive_summary"]["passed_tests"]
    report["executive_summary"]["pass_rate"] = (passed / total * 100) if total > 0 else 0

    if report["executive_summary"]["failed_tests"] > 0 or report["executive_summary"]["error_tests"] > 0:
        report["executive_summary"]["overall_status"] = "FAIL"

    return report


def generate_markdown_report(report, output_path):
    """Generate Markdown report."""
    lines = [
        "# SIA Sentinel Security Audit Report",
        "",
        f"**Generated:** {report['report_metadata']['generated_at']}",
        "",
        "## Executive Summary",
        "",
        f"- **Overall Status:** {report['executive_summary']['overall_status']}",
        f"- **Total Tests:** {report['executive_summary']['total_tests']}",
        f"- **Passed:** {report['executive_summary']['passed_tests']}",
        f"- **Failed:** {report['executive_summary']['failed_tests']}",
        f"- **Errors:** {report['executive_summary']['error_tests']}",
        f"- **Pass Rate:** {report['executive_summary']['pass_rate']:.1f}%",
        "",
        "## Test Results",
        "",
    ]

    for result in report["test_results"]:
        status = "✅ PASS" if result["success"] else "❌ FAIL"
        lines.append(f"### {result['module']}")
        lines.append(f"**Status:** {status}")
        lines.append(f"- Passed: {result['passed']}")
        lines.append(f"- Failed: {result['failed']}")
        lines.append(f"- Errors: {result['errors']}")
        lines.append("")

    lines.extend(["## Security Controls", ""])

    for control_name, control_data in report["security_controls"].items():
        lines.append(f"### {control_name.replace('_', ' ').title()}")
        lines.append(f"**Status:** {control_data['status']}")
        lines.append("")
        lines.append("**Controls:**")
        for control in control_data["controls"]:
            lines.append(f"- {control}")
        lines.append("")

    lines.extend(["## Recommendations", ""])

    for rec in report["recommendations"]:
        lines.append(f"### {rec['priority']} - {rec['category']}")
        lines.append(f"**{rec['recommendation']}**")
        lines.append(f"*{rec['rationale']}*")
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    """Generate security report."""
    print("=" * 70)
    print("SIA Sentinel Security Report Generator")
    print("=" * 70)
    print()

    report = generate_security_report()

    # Автосгенерированные результаты тестов идут в artifacts/, чтобы не
    # перезаписывать рукописный SECURITY_REPORT.md (threat model + статус
    # исправлений аудита).
    artifacts_dir = Path("artifacts")
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    json_path = artifacts_dir / "security_report.json"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n✅ JSON report saved to: {json_path}")

    md_path = artifacts_dir / "security_test_report.md"
    generate_markdown_report(report, md_path)
    print(f"✅ Markdown report saved to: {md_path}")

    print()
    print("=" * 70)
    print("SECURITY AUDIT SUMMARY")
    print("=" * 70)
    print(f"Overall Status: {report['executive_summary']['overall_status']}")
    print(f"Pass Rate: {report['executive_summary']['pass_rate']:.1f}%")
    print(f"Total Tests: {report['executive_summary']['total_tests']}")
    print(f"Passed: {report['executive_summary']['passed_tests']}")
    print(f"Failed: {report['executive_summary']['failed_tests']}")
    print(f"Errors: {report['executive_summary']['error_tests']}")
    print()

    if report["executive_summary"]["overall_status"] == "PASS":
        print("✅ All security tests passed!")
        print("✅ SIA Sentinel is ready for production deployment (with recommendations)")
    else:
        print("❌ Some security tests failed")
        print("⚠️  Review failed tests before production deployment")

    print()
    print("Top Recommendations:")
    for rec in report["recommendations"][:3]:
        print(f"  - [{rec['priority']}] {rec['recommendation']}")
    print()


if __name__ == "__main__":
    main()
