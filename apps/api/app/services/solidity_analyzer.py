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

_STATEMENT_END = re.compile(r";|\n\s*(?=\w)")
_IF_ELSE = re.compile(r"\bif\s*\(|\belse\b")
_LOOP = re.compile(r"\b(for|while)\s*\(")
_REQUIRE_REVERT = re.compile(r"\b(require|revert|assert)\s*\(")
_RETURN = re.compile(r"\breturn\s+(?:\w+|;)")
_REENTRANCY_GUARD_IMPORT = re.compile(
    r'import\s+["\']@openzeppelin[^"\']*ReentrancyGuard[^"\']*["\']'
)
_PRAGMA_SOLIDITY = re.compile(r"pragma\s+solidity\s+[^;]+;")

_LIMITATIONS = [
    "This source-pattern analysis is not a compiler-backed audit and cannot "
    "prove that a contract is safe.",
    "It only reports the explicitly implemented checks; complex control flow, "
    "inherited code, dependencies, and business-logic flaws may not be detected.",
    "Review each finding and recommendation in the context of the full project "
    "before changing or deploying a contract.",
    "Proposed patches are pattern-based suggestions only. They have not been "
    "compiled or tested. Always verify patches in a full development environment "
    "with tests before deployment.",
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


def _extract_function_from_source(source: str, function_offset: int) -> tuple[str, int, int] | None:
    """Extract the full function text and its start/end positions from the source."""
    if function_offset >= len(source):
        return None
    depth = 0
    end = function_offset
    found_open = False
    while end < len(source):
        if source[end] == "{":
            depth += 1
            found_open = True
        elif source[end] == "}":
            depth -= 1
            if found_open and depth == 0:
                end += 1
                return source[function_offset:end], function_offset, end
        end += 1
    return None


def _generate_checks_effects_patch(
    source: str,
    masked_source: str,
    function_offset: int,
    call_offset: int,
    write_offset: int,
) -> str | None:
    """
    Generate a conservative checks-effects-interactions patch by moving the state write
    before the external call. This is a pattern suggestion only - not a guaranteed fix.

    Returns None if the transformation cannot be confirmed as behavior-preserving:
    - Multiple state writes in the function
    - Multiple external calls in the function
    - Any statements between call and write (require, revert, return, conditionals, loops, etc.)
    - The write depends on the external call's return value
    - The write is not a simple assignment to a state variable
    - Ambiguous or complex syntax that cannot be reliably parsed
    """
    # Use masked source for all pattern matching to avoid comment/string interference
    func_info = _extract_function_from_source(masked_source, function_offset)
    if func_info is None:
        return None
    func_text, func_start, func_end = func_info

    signature_match = _FUNCTION.search(func_text)
    if not signature_match:
        return None
    body_start = signature_match.end()

    relative_call = call_offset - function_offset
    relative_write = write_offset - function_offset

    if relative_call < body_start or relative_write < body_start:
        return None
    if relative_call >= len(func_text) or relative_write >= len(func_text):
        return None
    if relative_call >= relative_write:
        return None

    body_relative_call = relative_call - body_start
    body_relative_write = relative_write - body_start

    body_text = func_text[body_start:]

    call_match = _LOW_LEVEL_CALL.search(body_text, body_relative_call)
    if not call_match:
        return None
    call_start = call_match.start()
    call_end = call_match.end()

    write_match = _STATE_WRITE.search(body_text, body_relative_write)
    if not write_match:
        return None
    write_start = write_match.start()
    write_end = write_match.end()

    if call_start >= write_start:
        return None

    # Find the end of the call statement (including closing ); )
    call_stmt_end_match = _STATEMENT_END.search(body_text, call_end)
    if call_stmt_end_match:
        call_stmt_end = call_stmt_end_match.end()
    else:
        call_stmt_end = call_end

    # Safety check 0: Call must be a standalone statement, not part of a variable declaration
    # Check if there's an assignment (=) before the call on the same line
    # Find the start of the line containing the call
    line_start = body_text.rfind("\n", 0, call_start) + 1
    line_text = body_text[line_start:call_start]
    if "=" in line_text:
        return None  # Call is on a line with an assignment - likely part of variable declaration

    # Safety check 1: No other external calls in the function body
    other_calls = list(_LOW_LEVEL_CALL.finditer(body_text))
    if len(other_calls) > 1:
        return None  # Multiple external calls - unsafe to reorder

    # Safety check 2: No other state writes in the function body
    other_writes = list(_STATE_WRITE.finditer(body_text))
    if len(other_writes) > 1:
        return None  # Multiple state writes - unsafe to reorder

    # Safety check 3: No statements between call and write that could affect behavior
    # Check region between end of call statement and start of write
    between_text = body_text[call_stmt_end:write_start]
    if between_text.strip():
        # Check for any control flow or statement that affects execution
        if (
            _IF_ELSE.search(between_text)
            or _LOOP.search(between_text)
            or _REQUIRE_REVERT.search(between_text)
            or _RETURN.search(between_text)
        ):
            return None  # Conditional, loop, require/revert/return between call and write - unsafe
        # Any non-whitespace content between call and write is suspicious
        # Only allow if it's purely whitespace/comments (which are masked to spaces)
        if not between_text.strip().isspace() and between_text.strip() != "":
            return None  # Other statements between call and write - unsafe

    # Safety check 4: Write must be a simple assignment to a state variable
    write_text = body_text[write_start:write_end]
    # Must be simple assignment (not compound like +=, -=, etc.)
    if re.search(r"[+\-*/%]\s*=", write_text):
        return None  # Compound assignment - unsafe to reorder
    # Must match simple state variable assignment pattern
    if not re.match(r"^\s*\w+(\s*\[\s*[^\]]+\s*\])?\s*=$", write_text.strip()):
        return None  # Not a simple assignment - unsafe

    # Safety check 5: Write must not depend on the external call's return value
    # Check if the RHS of the assignment references the call result
    call_var_match = re.search(r"\(\s*bool\s+(\w+)\s*,", body_text[call_start:call_end])
    if call_var_match:
        call_var = call_var_match.group(1)
        # Get the full write statement to check RHS
        stmt_end_match = _STATEMENT_END.search(body_text, write_end)
        if stmt_end_match:
            full_write_end = stmt_end_match.end()
        else:
            full_write_end = write_end
        full_write_text = body_text[write_start:full_write_end]
        # Check if RHS uses the call return variable
        if re.search(rf"\b{re.escape(call_var)}\b", full_write_text):
            return None  # Write depends on call return value - unsafe to reorder

    # Extract the full write statement for moving
    stmt_end_match = _STATEMENT_END.search(body_text, write_end)
    if stmt_end_match:
        full_write_end = stmt_end_match.end()
    else:
        full_write_end = write_end

    # Apply the same transformation to the original source
    orig_func_info = _extract_function_from_source(source, function_offset)
    if orig_func_info is None:
        return None
    orig_func_text, orig_func_start, orig_func_end = orig_func_info

    # Find corresponding positions in original source
    orig_signature_match = _FUNCTION.search(orig_func_text)
    if not orig_signature_match:
        return None
    orig_body_start = orig_signature_match.end()

    # The relative positions should be the same since masking preserves offsets
    orig_body_text = orig_func_text[orig_body_start:]

    # Re-find call and write in original to ensure exact text match
    orig_call_match = _LOW_LEVEL_CALL.search(orig_body_text, body_relative_call)
    orig_write_match = _STATE_WRITE.search(orig_body_text, body_relative_write)
    if not orig_call_match or not orig_write_match:
        return None

    orig_call_start = orig_call_match.start()
    orig_call_end = orig_call_match.end()
    orig_write_start = orig_write_match.start()
    orig_write_end = orig_write_match.end()

    # Find end of call statement in original source too
    orig_call_stmt_end_match = _STATEMENT_END.search(orig_body_text, orig_call_end)
    if orig_call_stmt_end_match:
        orig_call_stmt_end = orig_call_stmt_end_match.end()
    else:
        orig_call_stmt_end = orig_call_end

    orig_stmt_end_match = _STATEMENT_END.search(orig_body_text, orig_write_end)
    if orig_stmt_end_match:
        orig_full_write_end = orig_stmt_end_match.end()
    else:
        orig_full_write_end = orig_write_end

    orig_before_call = orig_body_text[:orig_call_start]
    orig_call_text = orig_body_text[orig_call_start:orig_call_stmt_end]
    orig_between = orig_body_text[orig_call_stmt_end:orig_write_start]
    orig_write_text = orig_body_text[orig_write_start:orig_full_write_end]
    orig_after_write = orig_body_text[orig_full_write_end:]

    orig_patched_body = (
        orig_before_call
        + orig_write_text
        + orig_between
        + orig_call_text
        + orig_after_write
    )
    orig_patched_func = orig_func_text[:orig_body_start] + orig_patched_body

    return source[:orig_func_start] + orig_patched_func + source[orig_func_end:]


def _generate_reentrancy_guard_patch(source: str, function_offset: int) -> str | None:
    """
    Generate a patch that adds ReentrancyGuard inheritance and nonReentrant modifier.
    This is a pattern suggestion only - not a guaranteed fix.

    Returns None if:
    - OpenZeppelin ReentrancyGuard import is not present
    - Solidity version is incompatible (< 0.8.0)
    - Contract definition cannot be found
    """
    func_info = _extract_function_from_source(source, function_offset)
    if func_info is None:
        return None
    func_text, func_start, func_end = func_info

    signature_match = _FUNCTION.search(func_text)
    if not signature_match:
        return None

    signature = signature_match.group()
    if "nonReentrant" in signature:
        return None

    # Safety check: Verify OpenZeppelin ReentrancyGuard import exists
    if not _REENTRANCY_GUARD_IMPORT.search(source):
        return None  # Import not found - cannot safely add dependency

    # Safety check: Verify Solidity version >= 0.8.0
    pragma_match = _PRAGMA_SOLIDITY.search(source)
    if pragma_match:
        pragma_text = pragma_match.group()
        # Extract version number (simplified check)
        version_match = re.search(r"0\.(\d+)", pragma_text)
        if version_match:
            minor = int(version_match.group(1))
            if minor < 8:
                return None  # Solidity < 0.8.0 - ReentrancyGuard not compatible

    has_guard = "ReentrancyGuard" in source

    lines = source.splitlines(keepends=True)

    if not has_guard:
        contract_idx = -1
        for i, line in enumerate(lines):
            if line.strip().startswith("pragma solidity"):
                pass
            if contract_idx == -1 and "contract " in line and "{" in line:
                contract_idx = i
        if contract_idx == -1:
            return None

        contract_line = lines[contract_idx]
        if "is " in contract_line:
            lines[contract_idx] = contract_line.replace("is ", "is ReentrancyGuard, ")
        else:
            lines[contract_idx] = contract_line.replace("{", " is ReentrancyGuard {")

        patched_source = "".join(lines)
    else:
        patched_source = source

    func_info2 = _extract_function_from_source(patched_source, func_start)
    if func_info2 is None:
        return None
    _, new_func_start, new_func_end = func_info2
    func_text2 = patched_source[new_func_start:new_func_end]

    signature_match2 = _FUNCTION.search(func_text2)
    if not signature_match2:
        return None
    signature2 = signature_match2.group()

    if ")" in signature2 and "{" in signature2:
        before_brace = signature2[: signature2.index("{")]
        after_brace = signature2[signature2.index("{") :]
        if "nonReentrant" not in before_brace:
            new_signature = before_brace.rstrip() + " nonReentrant " + after_brace
            func_text2 = func_text2.replace(signature2, new_signature, 1)

    return patched_source[:new_func_start] + func_text2 + patched_source[new_func_end:]


def _generate_reentrancy_patch(
    source: str,
    masked_source: str,
    function_offset: int,
    call_offset: int,
    write_offset: int,
) -> str | None:
    """
    Generate a conservative reentrancy patch using checks-effects-interactions only.
    ReentrancyGuard fallback is disabled. Returns None if the pattern cannot be
    verified as safe to transform automatically.

    Note: A generated patch passing a re-scan does NOT prove the patch is secure.
    The analyzer only detects the specific source patterns it implements.
    """
    return _generate_checks_effects_patch(
        source, masked_source, function_offset, call_offset, write_offset
    )


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
        patched_code: str | None = None,
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
                patched_code=patched_code,
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
                "tx.origin identifies the transaction's original signer, not necessarily "
                "the immediate caller. A malicious intermediary contract can make "
                "origin-based authorization unsafe."
            ),
            recommendation=(
                "Use msg.sender for caller checks and protect privileged actions with an "
                "explicit role or ownership mechanism. Review any intended "
                "trusted-forwarder design separately."
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
                "delegatecall runs another address's code with this contract's storage "
                "and authority. An untrusted or upgradeable target can take control of "
                "the calling contract."
            ),
            recommendation=(
                "Restrict the target to trusted, validated code; document and test "
                "storage-layout compatibility; and protect target changes with tightly "
                "controlled authorization."
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
                "selfdestruct (or its legacy alias) can transfer the contract's balance "
                "and has chain-version-dependent effects on contract code."
            ),
            recommendation=(
                "Remove the destruction path unless it is a deliberate, reviewed "
                "requirement. If it is required, gate it behind explicit authorization "
                "and test its behavior on the target chain."
            ),
        )

    for signature, body, function_offset in _function_blocks(code):
        if re.search(r"\bnonReentrant\b", signature):
            continue
        body_start = function_offset + len(signature)
        for call in _LOW_LEVEL_CALL.finditer(body):
            later_write = _STATE_WRITE.search(body, call.end())
            if later_write is None:
                continue
            call_offset = body_start + call.start()
            write_offset = body_start + later_write.start()
            patched = _generate_reentrancy_patch(
                source, code, function_offset, call_offset, write_offset
            )
            if patched is None:
                recommendation = (
                    "Check the full call path and whether the target is trusted. "
                    "Prefer checks-effects-interactions by updating state before "
                    "the external call, and use a reviewed reentrancy guard when "
                    "appropriate. Automatic remediation was declined because the "
                    "code pattern could not be verified as safe to transform "
                    "(e.g., multiple writes/calls, control flow, call-dependent "
                    "assignment, or ambiguous syntax)."
                )
            else:
                recommendation = (
                    "Check the full call path and whether the target is trusted. "
                    "Prefer checks-effects-interactions by updating state before "
                    "the external call, and use a reviewed reentrancy guard when "
                    "appropriate."
                )
            add_finding(
                rule_id="SOL-004",
                title="External call occurs before a later assignment",
                severity="medium",
                category="Reentrancy",
                offset=call_offset,
                description=(
                    "A low-level external call is followed by an assignment in the same "
                    "function. This source-pattern check cannot determine whether the "
                    "assignment changes storage. If the callee is untrusted and can re-enter "
                    "before an important state update, this ordering may expose a "
                    "reentrancy path."
                ),
                recommendation=recommendation,
                patched_code=patched,
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
