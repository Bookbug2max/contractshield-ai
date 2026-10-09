import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


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
                '        (bool sent, ) = payable(msg.sender).call{value: balances[msg.sender]}("");\n'
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
                '        (bool sent, ) = payable(msg.sender).call{value: balances[msg.sender]}("");\n'
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
