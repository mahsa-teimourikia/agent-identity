import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).parents[1]))

from lab import build_evidence_chain, sign_checkpoint, verify_evidence


def test_chain_and_checkpoint_verify_together() -> None:
    key = Ed25519PrivateKey.generate()
    chain = build_evidence_chain([{"event": "issue"}, {"event": "authorize"}])
    checkpoint = sign_checkpoint(chain, key)
    assert verify_evidence(chain, checkpoint, key.public_key())
