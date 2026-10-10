from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["high", "medium", "low"]


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    category: str
    line: int = Field(ge=1)
    description: str
    recommendation: str
    evidence: str
    patched_code: str | None = None


class FindingSummary(BaseModel):
    total: int
    high: int
    medium: int
    low: int


class SolidityAnalysisResponse(BaseModel):
    filename: str
    analyzer: str
    analysis_type: str
    lines_of_code: int
    result: Literal["review_required", "no_known_issues_found"]
    findings_truncated: bool
    summary: FindingSummary
    findings: list[Finding]
    limitations: list[str]
