import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from backend.llm.reasoner import LLMReasoner
from backend.core.finding import StaticFinding, CodeContext


@pytest.mark.asyncio
async def test_reentrancy_rejection_must_not_ignore_conflicting_source_evidence():
    finding = StaticFinding(
        id="reentrancy-regression",
        contract="VulnerableBank",
        function="withdraw",
        line_start=5,
        line_end=10,
        category="reentrancy",
        confidence=0.9,
        message="External call occurs before the balance is reset.",
        snippet='msg.sender.call{value: amount}("")',
        severity="High",
        swc_id="SWC-107",
    )

    source = """
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }
    """

    context = CodeContext(
        contract_name="VulnerableBank",
        function_name="withdraw",
        function_source=source,
        line_start=5,
        line_end=10,
        modifiers=[],
        state_variables=["balances"],
    )

    # Simulate an AI response that incorrectly claims the state is reset
    # before the external call.
    incorrect_ai_answer = {
        "is_vulnerable": False,
        "confidence": 0.9,
        "explanation": (
            "The balance is reset before the external call."
        ),
        "attack_scenario": "None",
        "recommendation": "None",
        "original_code": source,
        "fixed_code": "",
    }

    response = MagicMock()
    response.json.return_value = {
        "message": {"content": json.dumps(incorrect_ai_answer)}
    }
    response.raise_for_status = MagicMock()

    reasoner = LLMReasoner()

    try:
        with patch.object(
            reasoner.client, "post", new_callable=AsyncMock
        ) as mock_post:
            mock_post.return_value = response

            result = await reasoner.verify_finding(finding, context)

        # This assertion is expected to FAIL with the current implementation.
        # It documents the bug we want to prevent.
        assert result.verification_status != "REJECTED", (
            "AI rejected a reentrancy finding despite source evidence "
            "showing the external call before the state update."
        )
    finally:
        await reasoner.client.aclose()
