"""Request/response schemas — input validation for every mutating endpoint."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

SEVERITIES = ("critical", "high", "medium", "low", "info")
SUPPORT_LEVELS = ("insufficient", "low", "moderate", "strong")
CHAIN_STATUSES = ("open", "escalated", "dismissed", "resolved")


def _no_control_chars(value: str, *, field: str = "value") -> str:
    """Reject control characters that can corrupt HTTP headers, filenames

    CR/LF permit header injection / response splitting; other C0 controls and
    DEL have no legitimate place in names, identifiers, descriptions or notes.
    Legitimate Unicode (including non-ASCII characters such as é, ø, 中文) is
    preserved.
    """
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"{field} must not contain control characters")
    return value


class InvestigationCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=255,
                      description="Human-readable investigation name")
    case_id: str = Field(..., min_length=2, max_length=100,
                         description="Case identifier, unique per organisation")
    description: str | None = Field(None, max_length=4000)
    notes: str | None = Field(None, max_length=20000)

    @field_validator("name", "case_id")
    @classmethod
    def _strip(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value

    @field_validator("name")
    @classmethod
    def _name_no_control_chars(cls, value: str) -> str:
        # Names flow into report text, graph labels and audit metadata, and for
        # pre-existing rows may still be reflected by legacy components. Reject
        # control characters so neither header nor content injection is possible.
        return _no_control_chars(value, field="name")

    @field_validator("case_id")
    @classmethod
    def _case_id_no_control_chars(cls, value: str) -> str:
        # case_id flows directly into Content-Disposition filenames and was the
        # original CRLF / quote-injection vector.
        return _no_control_chars(value, field="case_id")

    @field_validator("description", "notes")
    @classmethod
    def _text_no_control_chars(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _no_control_chars(value, field="description")


class InvestigationUpdate(BaseModel):
    name: str | None = Field(None, min_length=3, max_length=255)
    description: str | None = Field(None, max_length=4000)
    notes: str | None = Field(None, max_length=20000)
    status: Literal["open", "in_review", "closed"] | None = None

    @field_validator("name")
    @classmethod
    def _name_no_control_chars(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _no_control_chars(value, field="name")

    @field_validator("description", "notes")
    @classmethod
    def _text_no_control_chars(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _no_control_chars(value, field="description")


class AnalysisConfigUpdate(BaseModel):
    chain_window_hours: float | None = Field(None, ge=0, le=8760,
                                              description="Max hours between chain steps")
    activity_window_hours: float | None = Field(None, ge=0, le=720)
    mass_deletion_threshold: int | None = Field(None, ge=1, le=10_000)
    mass_deletion_window_hours: float | None = Field(None, gt=0, le=240)
    logging_gap_hours: float | None = Field(None, gt=0, le=8760)
    clock_drift_seconds: int | None = Field(None, ge=0, le=86_400)
    graph_max_nodes: int | None = Field(None, ge=10, le=5000)


class ChainUpdate(BaseModel):
    status: Literal["open", "escalated", "dismissed", "resolved"]
    note: str | None = Field(None, max_length=2000)


class DemoRequest(BaseModel):
    scenarios: list[str] | None = Field(
        None, description="Scenario ids to generate; defaults to all scenarios")
    mode: Literal["each", "single"] = "each"


class TimelineQuery(BaseModel):
    start: str | None = None
    end: str | None = None
    event_types: list[str] = []
    sort: Literal["asc", "desc"] = "asc"
    search: str | None = None
    limit: int = Field(200, ge=1, le=5000)
    offset: int = Field(0, ge=0)


class PathRequest(BaseModel):
    source_id: str
    target_id: str


class EvaluationRequest(BaseModel):
    scenarios: list[str] | None = None
    # A: timeline only, B: + detection rules, C: + graph correlation + uncertainty
    configurations: list[Literal["A", "B", "C"]] = ["A", "B", "C"]


class SignupRequest(BaseModel):
    """Create an account. Username/password rules are enforced by the
    accounts service so error codes stay stable for the UI."""
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)
    display_name: str | None = Field(None, max_length=128)

    @field_validator("username", "password")
    @classmethod
    def _no_control_chars(cls, value: str) -> str:
        return _no_control_chars(value, field="credentials")


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)

    @field_validator("username", "password")
    @classmethod
    def _no_control_chars(cls, value: str) -> str:
        return _no_control_chars(value, field="credentials")


class ErrorBody(BaseModel):
    code: str
    message: str
    details: Any | None = None