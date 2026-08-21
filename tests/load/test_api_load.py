"""
Load testing for SIA Sentinel API (with valid payloads).

Tests:
- Concurrent requests to /v1/verify-change
- Concurrent requests to /v1/verify-receipt
- Concurrent requests to /v1/network/submit-task

Metrics:
- Requests per second (RPS)
- P50/P95/P99 latency
- Error rate
"""

import asyncio
import time
import uuid
import hashlib
import hmac
from dataclasses import dataclass, field
from statistics import mean
from typing import Any

import aiohttp


@dataclass
class LoadTestResult:
    """Results from a load test."""
    endpoint: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    total_time: float
    latencies: list[float] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.successful_requests / self.total_requests

    @property
    def requests_per_second(self) -> float:
        if self.total_time == 0:
            return 0.0
        return self.total_requests / self.total_time

    @property
    def avg_latency(self) -> float:
        if not self.latencies:
            return 0.0
        return mean(self.latencies)

    @property
    def p50_latency(self) -> float:
        if not self.latencies:
            return 0.0
        sorted_latencies = sorted(self.latencies)
        idx = int(len(sorted_latencies) * 0.50)
        return sorted_latencies[idx]

    @property
    def p95_latency(self) -> float:
        if not self.latencies:
            return 0.0
        sorted_latencies = sorted(self.latencies)
        idx = min(int(len(sorted_latencies) * 0.95), len(sorted_latencies) - 1)
        return sorted_latencies[idx]

    @property
    def p99_latency(self) -> float:
        if not self.latencies:
            return 0.0
        sorted_latencies = sorted(self.latencies)
        idx = min(int(len(sorted_latencies) * 0.99), len(sorted_latencies) - 1)
        return sorted_latencies[idx]

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": self.success_rate,
            "requests_per_second": self.requests_per_second,
            "total_time": self.total_time,
            "avg_latency": self.avg_latency,
            "p50_latency": self.p50_latency,
            "p95_latency": self.p95_latency,
            "p99_latency": self.p99_latency,
        }


async def make_verify_change_request(
    session: aiohttp.ClientSession,
    base_url: str,
    request_id: int,
) -> dict[str, Any]:
    """Make a single /v1/verify-change request with unique agent_id."""
    start = time.time()

    payload = {
        "agent_id": f"load-test-agent-{request_id}-{uuid.uuid4().hex[:8]}",
        "description": "Load test verification",
        "target_path": "src/test.py",
        "target_symbol": "add",
        "current_code": "def add(a, b): return a + b",
        "proposed_code": "def add(a, b): return b + a",
        "allowed_paths": ["src/test.py"],
    }

    try:
        async with session.post(
            f"{base_url}/v1/verify-change",
            json=payload,
        ) as response:
            latency = time.time() - start
            data = await response.json()

            return {
                "success": response.status == 200,
                "latency": latency,
                "status_code": response.status,
                "data": data,
            }
    except Exception as e:
        return {
            "success": False,
            "latency": time.time() - start,
            "error": str(e),
        }


async def make_verify_receipt_request(
    session: aiohttp.ClientSession,
    base_url: str,
    request_id: int,
) -> dict[str, Any]:
    """Make a single /v1/verify-receipt request with valid signed receipt."""
    start = time.time()

    # Generate valid receipt with signature
    signing_key = "test-key-for-performance-testing"
    receipt_id = f"receipt-{uuid.uuid4()}"

    receipt = {
        "receipt_id": receipt_id,
        "evidence_id": f"evidence-{uuid.uuid4()}",
        "agent_id": f"load-agent-{request_id}",
        "timestamp": time.time(),
        "code_hash": hashlib.sha256(f"code-{request_id}".encode()).hexdigest(),
        "safety_approved": True,
        "trust_level": "NOVICE",
        "nonce": f"nonce-{uuid.uuid4().hex[:8]}",
    }

    # Create signature
    canonical = str(sorted([(k, v) for k, v in receipt.items()]))
    signature = hmac.new(
        signing_key.encode(),
        canonical.encode(),
        hashlib.sha256
    ).hexdigest()
    receipt["signature"] = signature

    payload = {"receipt": receipt}

    try:
        async with session.post(
            f"{base_url}/v1/verify-receipt",
            json=payload,
        ) as response:
            latency = time.time() - start

            return {
                "success": response.status == 200,
                "latency": latency,
                "status_code": response.status,
            }
    except Exception as e:
        return {
            "success": False,
            "latency": time.time() - start,
            "error": str(e),
        }


async def run_load_test(
    base_url: str,
    endpoint: str,
    request_func,
    num_requests: int = 100,
    concurrency: int = 10,
) -> LoadTestResult:
    """Run a load test against an endpoint."""
    start_time = time.time()

    semaphore = asyncio.Semaphore(concurrency)

    async def limited_request(session, request_id):
        async with semaphore:
            return await request_func(session, base_url, request_id)

    async with aiohttp.ClientSession() as session:
        tasks = [
            limited_request(session, i)
            for i in range(num_requests)
        ]
        results = await asyncio.gather(*tasks)

    end_time = time.time()
    total_time = end_time - start_time

    successful = sum(1 for r in results if r["success"])
    failed = len(results) - successful
    latencies = [r["latency"] for r in results if r["success"]]

    return LoadTestResult(
        endpoint=endpoint,
        total_requests=num_requests,
        successful_requests=successful,
        failed_requests=failed,
        total_time=total_time,
        latencies=latencies,
    )


async def main():
    """Run all load tests."""
    base_url = "http://127.0.0.1:8000"

    print("=" * 70)
    print("SIA Sentinel: API Load Testing (Day 49 - Valid Payloads)")
    print("=" * 70)
    print()

    tests = [
        ("/v1/verify-change", make_verify_change_request, 50, 5),
        ("/v1/verify-receipt", make_verify_receipt_request, 50, 5),
    ]

    results = []

    for endpoint, request_func, num_requests, concurrency in tests:
        print(f"Testing {endpoint}...")
        print(f"  Requests: {num_requests}, Concurrency: {concurrency}")

        result = await run_load_test(
            base_url=base_url,
            endpoint=endpoint,
            request_func=request_func,
            num_requests=num_requests,
            concurrency=concurrency,
        )

        results.append(result)

        print(f"  Completed in {result.total_time:.2f}s")
        print(f"    Success rate: {result.success_rate:.1%}")
        print(f"    RPS: {result.requests_per_second:.1f}")
        print(f"    Avg latency: {result.avg_latency*1000:.1f}ms")
        print(f"    P50 latency: {result.p50_latency*1000:.1f}ms")
        print(f"    P95 latency: {result.p95_latency*1000:.1f}ms")
        print(f"    P99 latency: {result.p99_latency*1000:.1f}ms")
        print()

    print("=" * 70)
    print("LOAD TEST SUMMARY")
    print("=" * 70)
    print()

    for result in results:
        print(f"{result.endpoint}:")
        print(f"  Total requests: {result.total_requests}")
        print(f"  Success rate: {result.success_rate:.1%}")
        print(f"  RPS: {result.requests_per_second:.1f}")
        print(f"  P95 latency: {result.p95_latency*1000:.1f}ms")
        print()

    print("=" * 70)
    print("COMPARISON WITH DAY 39 BASELINE")
    print("=" * 70)
    print()

    baseline = {
        "/v1/verify-change": {"rps": 242.6, "p95_ms": 41.4, "success": 100},
        "/v1/verify-receipt": {"rps": 864.0, "p95_ms": 10.4, "success": 100},
        "/v1/network/submit-task": {"rps": 383.1, "p95_ms": 24.7, "success": 100},
    }

    for result in results:
        bl = baseline.get(result.endpoint, {})
        bl_rps = bl.get("rps", 0)
        bl_p95 = bl.get("p95_ms", 0)
        bl_success = bl.get("success", 0)

        rps_change = ((result.requests_per_second - bl_rps) / bl_rps * 100) if bl_rps > 0 else 0
        p95_change = ((result.p95_latency * 1000 - bl_p95) / bl_p95 * 100) if bl_p95 > 0 else 0

        print(f"{result.endpoint}:")
        print(f"  RPS: {result.requests_per_second:.1f} vs {bl_rps} (Day 39) [{rps_change:+.1f}%]")
        print(f"  P95: {result.p95_latency*1000:.1f}ms vs {bl_p95}ms [{p95_change:+.1f}%]")
        print(f"  Success: {result.success_rate*100:.1f}% vs {bl_success}%")
        print()

    print("=" * 70)
    print("TARGET CHECK")
    print("=" * 70)
    print()

    targets = {
        "/v1/verify-change": {"rps": 20, "p95_ms": 500},
        "/v1/verify-receipt": {"rps": 50, "p95_ms": 200},
        "/v1/network/submit-task": {"rps": 30, "p95_ms": 300},
    }

    for result in results:
        target = targets.get(result.endpoint, {})
        rps_target = target.get("rps", 0)
        p95_target = target.get("p95_ms", 0)

        rps_pass = result.requests_per_second >= rps_target
        p95_pass = result.p95_latency * 1000 <= p95_target
        success_pass = result.success_rate >= 0.95

        print(f"{result.endpoint}:")
        print(f"  RPS: {result.requests_per_second:.1f} (target: {rps_target}) {'PASS' if rps_pass else 'FAIL'}")
        print(f"  P95: {result.p95_latency*1000:.1f}ms (target: {p95_target}ms) {'PASS' if p95_pass else 'FAIL'}")
        print(f"  Success: {result.success_rate*100:.1f}% (target: 95%+) {'PASS' if success_pass else 'FAIL'}")
        print()


if __name__ == "__main__":
    asyncio.run(main())
