"""Validate a JSON Lines file of events against the common schema.

JSON Lines (``.jsonl``) stores one JSON object per line. It suits security logs
because a file can be streamed line by line, and one broken line does not stop
the rest of the file from being read.

This module reads and checks a file without touching the database. It is the
first step of the ingestion pipeline built in Phase 2.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from sentinelforge.events.schema import SecurityEvent

# A single log line larger than this is almost certainly a mistake or abuse.
MAX_LINE_BYTES = 1_000_000


@dataclass(frozen=True)
class LineError:
    line_number: int
    field: str
    message: str


@dataclass
class ValidationReport:
    path: Path
    total: int = 0
    valid_events: list[SecurityEvent] = field(default_factory=list)
    errors: list[LineError] = field(default_factory=list)
    invalid_lines: set[int] = field(default_factory=set)

    @property
    def valid(self) -> int:
        return len(self.valid_events)

    @property
    def invalid(self) -> int:
        return len(self.invalid_lines)

    @property
    def ok(self) -> bool:
        return self.invalid == 0


def _pydantic_errors(line_number: int, exc: ValidationError) -> list[LineError]:
    """Turn a pydantic error into readable messages.

    ``include_input=False`` keeps the offending value out of the message, so
    a password that ended up in the wrong field is not echoed to the terminal.
    """
    results = []
    for err in exc.errors(include_input=False):
        location = ".".join(str(part) for part in err["loc"]) or "(event)"
        message = err["msg"].removeprefix("Value error, ")
        results.append(LineError(line_number, location, message))
    return results


def validate_jsonl(path: Path) -> ValidationReport:
    """Validate every non-blank line in ``path``.

    Raises ``FileNotFoundError`` if the file does not exist and
    ``UnicodeDecodeError`` if it is not UTF-8 text.
    """
    report = ValidationReport(path=path)

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue  # blank lines are allowed and not counted
            report.total += 1

            if len(line.encode("utf-8")) > MAX_LINE_BYTES:
                report.errors.append(LineError(line_number, "(line)", "line is too long"))
                report.invalid_lines.add(line_number)
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                report.errors.append(LineError(line_number, "(line)", f"not valid JSON: {exc.msg}"))
                report.invalid_lines.add(line_number)
                continue

            if not isinstance(record, dict):
                report.errors.append(
                    LineError(line_number, "(line)", "each line must be a JSON object")
                )
                report.invalid_lines.add(line_number)
                continue

            try:
                report.valid_events.append(SecurityEvent.model_validate(record))
            except ValidationError as exc:
                report.errors.extend(_pydantic_errors(line_number, exc))
                report.invalid_lines.add(line_number)

    return report
