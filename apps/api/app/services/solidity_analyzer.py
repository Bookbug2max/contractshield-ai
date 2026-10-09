import bisect
import re
from collections.abc import Iterator

from app.schemas.analysis import Finding, FindingSummary, Severity, SolidityAnalysisResponse

MAX_FINDINGS = 200

_TX_ORIGIN = re.compile(r"\btx\s*\.\s*origin\b")
_DELEGATECALL = re.compile(r"\.\s*delegatecall\b")
_SELFDESTRUCT = re.compile(r"\b(?:selfdestruct|suicide)\s*\(")
_FUNCTION = re.compile(r"\bfunction\s+[A-Za-z_$][\w$]*\s*\([^)]*\)[^{;]*\{")
_LOW_LEVEL_CALL = re.compile(r"\.\s*call(?:\s*\{[^}]*\})?\s*\(", re.DOTALL)
_STATE_WRITE = re.compile(
    r"\b[A-Za-z_$][\w$]*(?:\s*\[[^\]\n]+\])?\s*(?:\+\+|--|[+\-*/%]?=)"
)

_LIMITATIONS = [
    "This source-pattern analysis is not a compiler-backed audit and cannot prove that a contract is safe.",
    "It only reports the explicitly implemented checks; complex control flow, inherited code, dependencies, "
    "and business-logic flaws may not be detected.",
    "Review each finding and recommendation in the context of the full project before changing or deploying "
    "a contract.",
]


def _mask_comments_and_strings(source: str) -> str:
    """Hide comments and string contents while preserving source offsets and newlines."""
    output = list(source)
    index = 0
    state = "code"

    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""

        if state == "line_comment":
            if char in "\r\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                output[index] = " "
                output[index + 1] = " "
                index += 1
                state = "code"
            elif char not in "\r\n":
                output[index] = " "
        elif state in ("single_string", "double_string"):
            quote = "'" if state == "single_string" else '"'
            if char == "\\":
                output[index] = " "
                if index + 1 < len(source) and source[index + 1] not in "\r\n":
                    output[index + 1] = " "
                    index += 1
            elif char == quote:
                output[index] = " "
                state = "code"
            elif char not in "\r\n":
                output[index] = " "
        elif char == "/" and next_char == "/":
            output[index] = " "
            output[index + 1] = " "
            index += 1
            state = "line_comment"
        elif char == "/" and next_char == "*":
            output[index] = " "
            output[index + 1] = " "
            index += 1
            state = "block_comment"
        elif char == "'":
            output[index] = " "
            state = "single_string"
        elif char == '"':
            output[index] = " "
            state = "double_string"

        index += 1

    return "".join(output)


def _line_starts(source: str) -> list[int]:
    return [0, *(index + 1 for index, char in enumerate(source) if char == "\n")]


def _line_at(offset: int, starts: list[int]) -> int:
    return bisect.bisect_right(starts, offset)


def _function_blocks(code: str) -> Iterator[tuple[str, str, int]]:
    for match in _FUNCTION.finditer(code):
        depth = 1
        end = match.end()
        while end < len(code) and depth:
            if code[end] == "{":
                depth += 1
            elif code[end] == "}":
                depth -= 1
            end += 1
        if depth == 0:
            yield match.group(), code[match.end() : end - 1], match.start()


def analyze_solidity(source: str, filename: str) -> SolidityAnalysisResponse:
    code = _mask_comments_and_strings(source)
    starts = _line_starts(source)
    source_lines = source.splitlines()
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    def add_finding(
        *,
        rule_id: str,
        title: str,
        severity: Severity,
        category: str,
        offset: int,
        description: str,
        recommendation: str,
    ) -> None:
        line = _line_at(offset, starts)
        key = (rule_id, line)
        if key in seen:
            return
        seen.add(key)
        evidence = source_lines[line - 1].strip() if line <= len(source_lines) else ""
        findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                category=category,
                line=line,
                description=description,
                recommendation=recommendation,
                evidence=evidence[:240],
            )
        )

    for match in _TX_ORIGIN.finditer(code):
        add_finding(
            rule_id="SOL-001",
            title="Authorization relies on tx.origin",
            severity="high",
            category="Access control",
            offset=match.start(),
            description=(
                "tx.origin identifies the transaction's original signer, not necessarily the immediate "
                "caller. A malicious intermediary contract can make origin-based authorization unsafe."
            ),
            recommendation=(
                "Use msg.sender for caller checks and protect privileged actions with an explicit role or "
                "ownership mechanism. Review any intended trusted-forwarder design separately."
            ),
        )

    for match in _DELEGATECALL.finditer(code):
        add_finding(
            rule_id="SOL-002",
            title="Delegatecall executes code in this contract's storage context",
            severity="high",
            category="External calls",
            offset=match.start(),
            description=(
                "delegatecall runs another address's code with this contract's storage and authority. "
                "An untrusted or upgradeable target can take control of the calling contract."
            ),
            recommendation=(
                "Restrict the target to trusted, validated code; document and test storage-layout "
                "compatibility; and protect target changes with tightly controlled authorization."
            ),
        )

    for match in _SELFDESTRUCT.finditer(code):
        add_finding(
            rule_id="SOL-003",
            title="Contract destruction primitive is present",
            severity="high",
            category="Destructive operations",
            offset=match.start(),
            description=(
                "selfdestruct (or its legacy alias) can transfer the contract's balance and has "
                "chain-version-dependent effects on contract code."
            ),
            recommendation=(
                "Remove the destruction path unless it is a deliberate, reviewed requirement. If it is "
                "required, gate it behind explicit authorization and test its behavior on the target chain."
            ),
        )

    for signature, body, function_offset in _function_blocks(code):
        if re.search(r"\bnonReentrant\b", signature):
            continue
        for call in _LOW_LEVEL_CALL.finditer(body):
            later_write = _STATE_WRITE.search(body, call.end())
            if later_write is None:
                continue
            add_finding(
                rule_id="SOL-004",
                title="External call occurs before a later assignment",
                severity="medium",
                category="Reentrancy",
                offset=function_offset + call.start(),
                description=(
                    "A low-level external call is followed by an assignment in the same function. "
                    "This source-pattern check cannot determine whether the assignment changes storage. "
                    "If the callee is untrusted and can re-enter before an important state update, this "
                    "ordering may expose a reentrancy path."
                ),
                recommendation=(
                    "Check the full call path and whether the target is trusted. Prefer checks-effects-"
                    "interactions by updating state before the external call, and use a reviewed "
                    "reentrancy guard when appropriate."
                ),
            )

    severity_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda finding: (severity_rank[finding.severity], finding.line))
    truncated = len(findings) > MAX_FINDINGS
    findings = findings[:MAX_FINDINGS]
    counts = {
        severity: sum(finding.severity == severity for finding in findings)
        for severity in ("high", "medium", "low")
    }

    return SolidityAnalysisResponse(
        filename=filename,
        analyzer="ContractShield Solidity source rules",
        analysis_type="static source-pattern screening",
        lines_of_code=sum(bool(line.strip()) for line in code.splitlines()),
        result="review_required" if findings else "no_known_issues_found",
        findings_truncated=truncated,
        summary=FindingSummary(
            total=len(findings),
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
        ),
        findings=findings,
        limitations=_LIMITATIONS,
    )
