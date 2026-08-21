from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)


_tracer_provider: Optional[TracerProvider] = None


class FileSpanExporter(SpanExporter):
    """Экспортер спанов в JSONL-файл для последующей визуализации."""

    def __init__(self, file_path: str = "logs/traces.jsonl") -> None:
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def export(self, spans) -> SpanExportResult:
        try:
            with open(self.file_path, "a", encoding="utf-8") as f:
                for span in spans:
                    record = json.loads(span.to_json())
                    f.write(json.dumps(record, ensure_ascii=True, default=str) + "\n")
            return SpanExportResult.SUCCESS
        except Exception:
            return SpanExportResult.FAILURE

    def shutdown(self) -> None:
        pass


def init_tracing(
    service_name: str = "sia",
    exporter: str = "console",
    otlp_endpoint: Optional[str] = None,
    traces_file: str = "logs/traces.jsonl",
) -> None:
    global _tracer_provider

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    if exporter == "console":
        processor = SimpleSpanProcessor(ConsoleSpanExporter())
        provider.add_span_processor(processor)
    elif exporter == "file":
        processor = SimpleSpanProcessor(FileSpanExporter(file_path=traces_file))
        provider.add_span_processor(processor)
    elif exporter == "both":
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
        provider.add_span_processor(SimpleSpanProcessor(FileSpanExporter(file_path=traces_file)))
    elif exporter == "otlp" and otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
            processor = BatchSpanProcessor(otlp_exporter)
            provider.add_span_processor(processor)
        except ImportError:
            processor = SimpleSpanProcessor(ConsoleSpanExporter())
            provider.add_span_processor(processor)
    else:
        processor = SimpleSpanProcessor(ConsoleSpanExporter())
        provider.add_span_processor(processor)

    trace.set_tracer_provider(provider)
    _tracer_provider = provider


def get_tracer(name: str = "sia"):
    return trace.get_tracer(name)


def get_current_trace_id() -> Optional[str]:
    span = trace.get_current_span()
    if span and span.get_span_context().is_valid:
        return format(span.get_span_context().trace_id, "032x")
    return None


def get_current_span_id() -> Optional[str]:
    span = trace.get_current_span()
    if span and span.get_span_context().is_valid:
        return format(span.get_span_context().span_id, "016x")
    return None


def shutdown_tracing() -> None:
    global _tracer_provider
    if _tracer_provider is not None:
        _tracer_provider.shutdown()
        _tracer_provider = None
