import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from lab import AuthorizationEngine, DecisionOutcome, EffectStore, fixture


def test_untrusted_prompt_cannot_supply_identity() -> None:
    assert fixture()["context"].principal_id == "user:alice"


def test_decision_is_bound_to_request_digest() -> None:
    values = fixture()
    decision = AuthorizationEngine().decide(**values, now=__import__("lab").NOW)
    assert decision.request_digest == values["intent"].request_digest


def test_denial_cannot_reach_effect_boundary() -> None:
    values = fixture()
    decision = (
        AuthorizationEngine()
        .decide(**values, now=__import__("lab").NOW)
        .model_copy(update={"outcome": DecisionOutcome.DENY})
    )
    with pytest.raises(PermissionError):
        EffectStore().execute(
            context=values["context"],
            intent=values["intent"],
            decision=decision,
            now=__import__("lab").NOW,
        )
