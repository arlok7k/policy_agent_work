"""The response lifecycle allows only its explicit mode-specific edges."""

import pytest

from app.response.gate import transition_allowed


@pytest.mark.parametrize(
    "level,mode,expected_initial",
    [
        (0, "advisory", "advised"),
        (1, "automatic", "approved"),
        (2, "automatic", "approved"),
        (2, "manual", "pending_approval"),
        (3, "manual", "pending_approval"),
    ],
)
def test_each_level_has_exactly_one_initial_edge(
    level: int, mode: str, expected_initial: str
) -> None:
    for destination in ("advised", "pending_approval", "approved", "executed", "rejected"):
        assert transition_allowed("requested", destination, mode, level) is (
            destination == expected_initial
        )


def test_illegal_modes_and_terminal_transitions_are_rejected() -> None:
    for level, mode in (
        (0, "automatic"),
        (1, "manual"),
        (3, "automatic"),
        (4, "manual"),
        (2, "bad"),
    ):
        assert not transition_allowed("requested", "approved", mode, level)
    for status in ("advised", "failed", "rejected", "rolled_back", "expired", "unknown"):
        for destination in ("approved", "executing", "executed", "rejected", "rolled_back"):
            assert not transition_allowed(status, destination, "manual", 3)
    assert not transition_allowed("pending_approval", "approved", "automatic", 2)
    assert not transition_allowed("approved", "executed", "manual", 3)
    assert not transition_allowed("executed", "approved", "manual", 3)


def test_manual_execution_path_and_explicit_failure_edges() -> None:
    for before, after in (
        ("requested", "pending_approval"),
        ("pending_approval", "approved"),
        ("approved", "executing"),
        ("executing", "executed"),
        ("executed", "rolled_back"),
        ("pending_approval", "rejected"),
        ("pending_approval", "expired"),
        ("approved", "failed"),
        ("approved", "expired"),
        ("executing", "failed"),
    ):
        assert transition_allowed(before, after, "manual", 3)
