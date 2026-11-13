"""Basic checks for the initial repository scaffold."""

import sys
from pathlib import Path


def test_python_matches_selected_release_line() -> None:
    assert sys.version_info[:2] == (3, 15)


def test_reference_documents_exist() -> None:
    root = Path(__file__).resolve().parents[3]
    assert (root / "policy_agent_work" / "AGENT_MASTER_PROMPT.md").is_file()
    assert (root / "policy_agent_work" / "POLICY_CONTROLS_PERMISSIONS_AGENT_SPEC.md").is_file()
