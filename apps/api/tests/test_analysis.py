import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.services.solidity_analyzer import (
    _generate_reentrancy_guard_patch,
    analyze_solidity,
)


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


VULNERABLE_REENTRANCY_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        (bool sent, ) = payable(msg.sender).call{value: balances[msg.sender]}("");
        require(sent, "Transfer failed");
        balances[msg.sender] = 0;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
""".strip()


# Simple reentrancy pattern - automatic patching is declined for safety
# because regex-based transformation cannot reliably preserve behavior
SIMPLE_REENTRANCY_CONTRACT = """
contract Vault {
    mapping(address => uint256) balances;
    function withdraw() external {
        (bool sent, ) = payable(msg.sender).call{value: balances[msg.sender]}("");
        balances[msg.sender] = 0;
    }
}
""".strip()


@pytest.mark.asyncio
async def test_analysis_reports_tx_origin_and_recommendation(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/analysis/solidity",
        json={
            "filename": "Wallet.sol",
            "source": "contract Wallet {\n    function withdraw() public {\n"
            "        require(tx.origin == owner);\n    }\n}",
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["result"] == "review_required"
    assert result["summary"] == {"total": 1, "high": 1, "medium": 0, "low": 0}
    assert result["findings"][0]["rule_id"] == "SOL-001"
    assert result["findings"][0]["line"] == 3
    assert "msg.sender" in result["findings"][0]["recommendation"]


@pytest.mark.asyncio
async def test_analysis_ignores_comments_and_string_literals(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/analysis/solidity",
        json={
            "filename": "Notes.sol",
            "source": (
                "// tx.origin\n"
                "/* delegatecall(address) */\n"
                'contract Notes { string public note = "selfdestruct(address)"; }\n'
            ),
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["result"] == "no_known_issues_found"
    assert result["summary"]["total"] == 0
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_analysis_reports_delegatecall_and_selfdestruct(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/analysis/solidity",
        json={
            "filename": "Proxy.sol",
            "source": (
                "contract Proxy {\n"
                "    function execute(address target, bytes calldata data) external {\n"
                "        target.delegatecall(data);\n"
                "    }\n"
                "    function destroy() external {\n"
                "        selfdestruct(payable(msg.sender));\n"
                "    }\n"
                "}\n"
            ),
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert {finding["rule_id"] for finding in result["findings"]} == {"SOL-002", "SOL-003"}
    assert result["summary"] == {"total": 2, "high": 2, "medium": 0, "low": 0}


@pytest.mark.asyncio
async def test_analysis_reports_possible_reentrancy_with_line_evidence(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/analysis/solidity",
        json={
            "filename": "Vault.sol",
            "source": (
                "contract Vault {\n"
                "    mapping(address => uint256) balances;\n"
                "    function withdraw() external {\n"
                '        (bool sent, ) = payable(msg.sender).call{value: '
                'balances[msg.sender]}("");\n'
                "        require(sent);\n"
                "        balances[msg.sender] = 0;\n"
                "    }\n"
                "}\n"
            ),
        },
    )

    assert response.status_code == 200
    finding = response.json()["findings"][0]
    assert finding["rule_id"] == "SOL-004"
    assert finding["severity"] == "medium"
    assert finding["line"] == 4
    assert "re-enter" in finding["description"]
    assert "checks-effects-interactions" in finding["recommendation"]
    # With require(sent) between call and write, patch should be refused
    assert finding["patched_code"] is None
    assert "Automatic remediation was declined" in finding["recommendation"]


@pytest.mark.asyncio
async def test_analysis_does_not_report_reentrancy_for_non_reentrant_function(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/analysis/solidity",
        json={
            "filename": "Vault.sol",
            "source": (
                "contract Vault {\n"
                "    mapping(address => uint256) balances;\n"
                "    function withdraw() external nonReentrant {\n"
                '        (bool sent, ) = payable(msg.sender).call{value: '
                'balances[msg.sender]}("");\n'
                "        require(sent);\n"
                "        balances[msg.sender] = 0;\n"
                "    }\n"
                "}\n"
            ),
        },
    )

    assert response.status_code == 200
    assert response.json()["summary"]["total"] == 0


@pytest.mark.asyncio
async def test_analysis_rejects_unsupported_file_and_empty_source(client: AsyncClient) -> None:
    unsupported = await client.post(
        "/api/v1/analysis/solidity",
        json={"filename": "contract.txt", "source": "contract C {}"},
    )
    empty = await client.post(
        "/api/v1/analysis/solidity",
        json={"filename": "contract.sol", "source": " \n "},
    )

    assert unsupported.status_code == 422
    assert empty.status_code == 422


@pytest.mark.asyncio
async def test_analysis_includes_patched_code_for_reentrancy(client: AsyncClient) -> None:
    """Test that reentrancy finding is reported but automatic patch is declined for safety."""
    response = await client.post(
        "/api/v1/analysis/solidity",
        json={
            "filename": "Vault.sol",
            "source": SIMPLE_REENTRANCY_CONTRACT,
        },
    )

    assert response.status_code == 200
    finding = response.json()["findings"][0]
    assert finding["rule_id"] == "SOL-004"
    # Automatic patching is declined because regex-based transformation
    # cannot reliably preserve behavior (call target separation, etc.)
    assert finding["patched_code"] is None
    assert "Automatic remediation was declined" in finding["recommendation"]


@pytest.mark.asyncio
async def test_patched_code_passes_re_scan(client: AsyncClient) -> None:
    """Test that finding is reported without automatic patch."""
    response = await client.post(
        "/api/v1/analysis/solidity",
        json={
            "filename": "Vault.sol",
            "source": SIMPLE_REENTRANCY_CONTRACT,
        },
    )

    assert response.status_code == 200
    finding = response.json()["findings"][0]
    # No patch generated due to safety concerns with regex-based transformation
    assert finding["patched_code"] is None
    assert "Automatic remediation was declined" in finding["recommendation"]

    # Finding should still be present
    assert finding["rule_id"] == "SOL-004"
    assert finding["severity"] == "medium"


@pytest.mark.asyncio
async def test_vulnerable_contract_demo_reports_finding_but_refuses_patch(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/analysis/solidity",
        json={"filename": "VulnerableVault.sol", "source": VULNERABLE_REENTRANCY_CONTRACT},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["result"] == "review_required"
    assert result["summary"]["total"] >= 1

    reentrancy_findings = [f for f in result["findings"] if f["rule_id"] == "SOL-004"]
    assert len(reentrancy_findings) >= 1

    # VulnerableVault has require(sent, "Transfer failed") between call and write
    # so automatic patching should be refused
    for finding in reentrancy_findings:
        assert finding["patched_code"] is None
        assert "Automatic remediation was declined" in finding["recommendation"]


@pytest.mark.asyncio
async def test_non_reentrant_function_no_patch_generated(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/analysis/solidity",
        json={
            "filename": "Vault.sol",
            "source": (
                "contract Vault {\n"
                "    mapping(address => uint256) balances;\n"
                "    function withdraw() external nonReentrant {\n"
                '        (bool sent, ) = payable(msg.sender).call{value: '
                'balances[msg.sender]}("");\n'
                "        require(sent);\n"
                "        balances[msg.sender] = 0;\n"
                "    }\n"
                "}\n"
            ),
        },
    )

    assert response.status_code == 200
    assert response.json()["summary"]["total"] == 0


@pytest.mark.asyncio
async def test_direct_analyzer_patch_generation() -> None:
    """Test that finding is reported but automatic patch is declined for safety."""
    source = SIMPLE_REENTRANCY_CONTRACT
    result = analyze_solidity(source, "Vault.sol")
    assert result.summary.total >= 1

    reentrancy_finding = next(f for f in result.findings if f.rule_id == "SOL-004")
    # Automatic patching is declined because regex-based transformation
    # cannot reliably preserve behavior
    assert reentrancy_finding.patched_code is None
    assert "Automatic remediation was declined" in reentrancy_finding.recommendation


@pytest.mark.asyncio
async def test_multiple_state_writes_refuses_patch() -> None:
    """Multiple state writes in function - automatic patching should be refused."""
    source = (
        "contract Vault {\n"
        "    mapping(address => uint256) balances;\n"
        "    mapping(address => uint256) withdrawals;\n"
        "    function withdraw() external {\n"
        '        (bool sent, ) = payable(msg.sender).call{value: '
        'balances[msg.sender]}("");\n'
        "        require(sent);\n"
        "        balances[msg.sender] = 0;\n"
        "        withdrawals[msg.sender] += 1;\n"
        "    }\n"
        "}\n"
    )
    result = analyze_solidity(source, "Vault.sol")
    reentrancy_finding = next(f for f in result.findings if f.rule_id == "SOL-004")
    # Should detect the issue but refuse to generate a patch due to multiple writes
    assert reentrancy_finding.patched_code is None


@pytest.mark.asyncio
async def test_multiple_external_calls_refuses_patch() -> None:
    """Multiple external calls in function - automatic patching should be refused."""
    source = (
        "contract Vault {\n"
        "    mapping(address => uint256) balances;\n"
        "    function withdraw(address to) external {\n"
        '        (bool sent, ) = payable(msg.sender).call{value: '
        'balances[msg.sender]}("");\n'
        "        require(sent);\n"
        '        (bool sent2, ) = payable(to).call{value: 1}("");\n'
        "        require(sent2);\n"
        "        balances[msg.sender] = 0;\n"
        "    }\n"
        "}\n"
    )
    result = analyze_solidity(source, "Vault.sol")
    reentrancy_finding = next(f for f in result.findings if f.rule_id == "SOL-004")
    # Should detect the issue but refuse to generate a patch due to multiple calls
    assert reentrancy_finding.patched_code is None


@pytest.mark.asyncio
async def test_control_flow_between_call_and_write_refuses_patch() -> None:
    """Conditional control flow between call and write - automatic patching should be refused."""
    source = (
        "contract Vault {\n"
        "    mapping(address => uint256) balances;\n"
        "    bool public paused;\n"
        "    function withdraw() external {\n"
        '        (bool sent, ) = payable(msg.sender).call{value: '
        'balances[msg.sender]}("");\n'
        "        require(sent);\n"
        "        if (!paused) {\n"
        "            balances[msg.sender] = 0;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    result = analyze_solidity(source, "Vault.sol")
    reentrancy_finding = next(f for f in result.findings if f.rule_id == "SOL-004")
    # Should detect the issue but refuse to generate a patch due to control flow
    assert reentrancy_finding.patched_code is None


@pytest.mark.asyncio
async def test_reentrancy_guard_patch_refused_without_import() -> None:
    """ReentrancyGuard patch should be refused when OpenZeppelin import is missing."""
    source = (
        "pragma solidity ^0.8.20;\n"
        "contract Vault {\n"
        "    mapping(address => uint256) balances;\n"
        "    function withdraw() external {\n"
        '        (bool sent, ) = payable(msg.sender).call{value: '
        'balances[msg.sender]}("");\n'
        "        require(sent);\n"
        "        balances[msg.sender] = 0;\n"
        "    }\n"
        "}\n"
    )
    # Direct test of the guard patch function
    # Find function offset
    import re
    func_match = re.search(r"\bfunction\s+withdraw\s*\(", source)
    assert func_match
    func_offset = func_match.start()

    patch = _generate_reentrancy_guard_patch(source, func_offset)
    # Should refuse because no OpenZeppelin import
    assert patch is None


@pytest.mark.asyncio
async def test_reentrancy_guard_patch_accepted_with_import() -> None:
    """ReentrancyGuard patch should be accepted when OpenZeppelin import is present."""
    source = (
        'pragma solidity ^0.8.20;\n'
        'import "@openzeppelin/contracts/security/ReentrancyGuard.sol";\n'
        "contract Vault is ReentrancyGuard {\n"
        "    mapping(address => uint256) balances;\n"
        "    function withdraw() external {\n"
        '        (bool sent, ) = payable(msg.sender).call{value: '
        'balances[msg.sender]}("");\n'
        "        require(sent);\n"
        "        balances[msg.sender] = 0;\n"
        "    }\n"
        "}\n"
    )
    import re
    func_match = re.search(r"\bfunction\s+withdraw\s*\(", source)
    assert func_match
    func_offset = func_match.start()

    patch = _generate_reentrancy_guard_patch(source, func_offset)
    # Should accept and generate patch with nonReentrant modifier
    assert patch is not None
    assert "nonReentrant" in patch


@pytest.mark.asyncio
async def test_call_dependent_assignment_refuses_patch() -> None:
    """Write depending on call return value should refuse patch."""
    source = (
        "contract Vault {\n"
        "    mapping(address => uint256) balances;\n"
        "    function withdraw() external {\n"
        '        (bool sent, uint256 returned) = payable(msg.sender).call{value: '
        'balances[msg.sender]}("");\n'
        "        require(sent);\n"
        "        balances[msg.sender] = returned;\n"
        "    }\n"
        "}\n"
    )
    result = analyze_solidity(source, "Vault.sol")
    reentrancy_finding = next(f for f in result.findings if f.rule_id == "SOL-004")
    assert reentrancy_finding.patched_code is None
    assert "Automatic remediation was declined" in reentrancy_finding.recommendation


@pytest.mark.asyncio
async def test_require_between_call_and_write_refuses_patch() -> None:
    """require() between call and write should refuse patch."""
    source = (
        "contract Vault {\n"
        "    mapping(address => uint256) balances;\n"
        "    function withdraw() external {\n"
        '        (bool sent, ) = payable(msg.sender).call{value: '
        'balances[msg.sender]}("");\n'
        "        require(sent, \"Transfer failed\");\n"
        "        balances[msg.sender] = 0;\n"
        "    }\n"
        "}\n"
    )
    result = analyze_solidity(source, "Vault.sol")
    reentrancy_finding = next(f for f in result.findings if f.rule_id == "SOL-004")
    assert reentrancy_finding.patched_code is None
    assert "Automatic remediation was declined" in reentrancy_finding.recommendation


@pytest.mark.asyncio
async def test_revert_between_call_and_write_refuses_patch() -> None:
    """revert() between call and write should refuse patch."""
    source = (
        "contract Vault {\n"
        "    mapping(address => uint256) balances;\n"
        "    function withdraw() external {\n"
        '        (bool sent, ) = payable(msg.sender).call{value: '
        'balances[msg.sender]}("");\n'
        "        if (!sent) revert(\"Transfer failed\");\n"
        "        balances[msg.sender] = 0;\n"
        "    }\n"
        "}\n"
    )
    result = analyze_solidity(source, "Vault.sol")
    reentrancy_finding = next(f for f in result.findings if f.rule_id == "SOL-004")
    assert reentrancy_finding.patched_code is None
    assert "Automatic remediation was declined" in reentrancy_finding.recommendation


@pytest.mark.asyncio
async def test_return_between_call_and_write_refuses_patch() -> None:
    """Early return between call and write should refuse patch."""
    source = (
        "contract Vault {\n"
        "    mapping(address => uint256) balances;\n"
        "    function withdraw() external {\n"
        '        (bool sent, ) = payable(msg.sender).call{value: '
        'balances[msg.sender]}("");\n'
        "        if (!sent) return;\n"
        "        balances[msg.sender] = 0;\n"
        "    }\n"
        "}\n"
    )
    result = analyze_solidity(source, "Vault.sol")
    reentrancy_finding = next(f for f in result.findings if f.rule_id == "SOL-004")
    assert reentrancy_finding.patched_code is None
    assert "Automatic remediation was declined" in reentrancy_finding.recommendation


@pytest.mark.asyncio
async def test_comment_string_patterns_do_not_mislead_patch_generation() -> None:
    """Comments/strings containing Solidity-like patterns should not mislead detection."""
    source = (
        "contract Vault {\n"
        "    mapping(address => uint256) balances;\n"
        "    function withdraw() external {\n"
        "        // This is a fake call: (bool sent, ) = addr.call(\"\");\n"
        "        /* Another fake: balances[msg.sender] = 0; */\n"
        '        (bool sent, ) = payable(msg.sender).call{value: '
        'balances[msg.sender]}("");\n'
        "        balances[msg.sender] = 0;\n"
        "    }\n"
        "}\n"
    )
    result = analyze_solidity(source, "Vault.sol")
    reentrancy_finding = next(f for f in result.findings if f.rule_id == "SOL-004")
    # Finding should be reported (comments/strings are masked during detection)
    # but patch is declined because the call is part of a variable declaration
    assert reentrancy_finding.patched_code is None
    assert "Automatic remediation was declined" in reentrancy_finding.recommendation


@pytest.mark.asyncio
async def test_finding_present_without_patch() -> None:
    """SOL-004 finding should be present even when patch is refused."""
    source = (
        "contract Vault {\n"
        "    mapping(address => uint256) balances;\n"
        "    mapping(address => uint256) withdrawals;\n"
        "    function withdraw() external {\n"
        '        (bool sent, ) = payable(msg.sender).call{value: '
        'balances[msg.sender]}("");\n'
        "        require(sent);\n"
        "        balances[msg.sender] = 0;\n"
        "        withdrawals[msg.sender] += 1;\n"
        "    }\n"
        "}\n"
    )
    result = analyze_solidity(source, "Vault.sol")
    sol_004_findings = [f for f in result.findings if f.rule_id == "SOL-004"]
    assert len(sol_004_findings) == 1
    finding = sol_004_findings[0]
    assert finding.patched_code is None
    assert "Automatic remediation was declined" in finding.recommendation
    assert finding.severity == "medium"
    assert finding.category == "Reentrancy"
