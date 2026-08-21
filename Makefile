.PHONY: help install test test-security run-api run-dashboard clean docker-build docker-up docker-down docker-logs lint format benchmark audit-code audit-llm audit-live optimize-demo optimize-live

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install dependencies
	python -m pip install --upgrade pip
	python -m pip install -r requirements.txt

test:  ## Run all tests
	python -m unittest discover -s tests -t . -v

test-security:  ## Run security tests only
	python -m unittest tests.test_security_suite -v

run-api:  ## Run Sentinel API locally
	python -m uvicorn sentinel.api:app --reload --port 8000

run-dashboard:  ## Run Streamlit dashboard locally
	streamlit run dashboard/app.py

clean:  ## Clean up temporary files
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +

docker-build:  ## Build Docker images
	docker compose build

docker-up:  ## Start services with Docker Compose
	docker compose up -d

docker-down:  ## Stop services
	docker compose down

docker-logs:  ## View service logs
	docker compose logs -f

lint:  ## Run linters
	python -m ruff check sia/ sentinel/ tests/
	python -m mypy sia/ sentinel/

format:  ## Format code
	python -m ruff format sia/ sentinel/ tests/

benchmark:  ## Run research benchmark
	python -m sia.research_benchmark --output artifacts/benchmark_report.json

audit-code:  ## Run Proof-of-Savings audit on the example code flow
	python audit_cli.py --flow flows/example_code_flow.json --out artifacts/audit_report_code.json --markdown artifacts/audit_report_code.md --sign artifacts/audit_receipt_code.json

audit-llm:  ## Run Proof-of-Savings audit on the example LLM flow (simulated)
	python audit_cli.py --flow flows/example_llm_flow.json --out artifacts/audit_report_llm.json --markdown artifacts/audit_report_llm.md --sign artifacts/audit_receipt_llm.json

audit-live:  ## Run live Proof-of-Savings pilot against NVIDIA NIM (requires NVIDIA_API_KEY)
	python audit_cli.py --flow flows/live_pilot.json --out artifacts/audit_report_live.json --markdown artifacts/audit_report_live.md --sign artifacts/audit_receipt_live.json

optimize-demo:  ## Run Savings Autopilot on the simulated example flow
	python audit_cli.py --flow flows/example_optimize_flow.json --out artifacts/optimize_report_demo.json --markdown artifacts/optimize_report_demo.md --sign artifacts/optimize_receipt_demo.json

optimize-live:  ## Run live Savings Autopilot against NVIDIA NIM (requires NVIDIA_API_KEY)
	python audit_cli.py --flow flows/live_optimize.json --out artifacts/optimize_report_live.json --markdown artifacts/optimize_report_live.md --sign artifacts/optimize_receipt_live.json
