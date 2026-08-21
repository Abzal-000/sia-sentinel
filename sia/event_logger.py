from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from .tracing import get_current_trace_id, get_current_span_id


class EventLogger:
    def __init__(self, log_dir: str = "logs") -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.log_dir / "events.jsonl"

    def log(self, event_type: str, payload: dict[str, Any]) -> None:
        record = {
            "timestamp": time.time(),
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "trace_id": get_current_trace_id(),
            "span_id": get_current_span_id(),
            "payload": payload,
        }

        with open(self.events_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=True, default=str) + "\n")
