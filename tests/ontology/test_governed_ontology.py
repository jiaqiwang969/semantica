import json
from pathlib import Path

import pytest

from semantica.ontology.governance import (
    GovernanceGateError,
    GovernanceInputError,
    GovernanceWorkspaceError,
    GovernanceWorkspaceExistsError,
    RuntimeSourceIdentityDTO,
    commit_change,
    history_workspace,
    initialize_workspace,
    main,
    propose_change,
    regress_workspace,
)


SOURCE_IDENTITY = RuntimeSourceIdentityDTO(
    runtime_commit="a" * 40,
    runtime_artifact_sha256="b" * 64,
)
T0 = "2026-01-01T00:00:00Z"
T1 = "2026-01-02T00:00:00Z"


def _baseline():
    return {
        "classes": [
            {"name": "PartMode", "comment": "part-only intent"},
            {"name": "AssemblyMode", "comment": "assembly-only intent"},
        ],
        "properties": [{"name": "hasIntentMode", "comment": "mode link"}],
    }


def _write_cq(workspace: Path) -> None:
    (workspace / "cq-bank" / "cq-modes.json").write_text(
        json.dumps(
            {
                "id": "CQ-MODES",
                "question": "Does PartMode remain a class?",
                "ask": True,
                "sparql": """
                    PREFIX dom: <https://example.test/domain#>
                    PREFIX owl: <http://www.w3.org/2002/07/owl#>
                    ASK { dom:PartMode a owl:Class }
                """,
            }
        ),
        encoding="utf-8",
    )


def test_init_is_append_only_and_binds_runtime_lifecycle(tmp_path):
    workspace = tmp_path / "domain"
    result = initialize_workspace(
        workspace,
        name="Domain",
        namespace="https://example.test/domain#",
        baseline=_baseline(),
        source_identity=SOURCE_IDENTITY,
        recorded_at=T0,
    )

    assert result.version.version == 1
    assert result.release.complete
    assert result.semantic_diff.changed
    assert result.receipt.verify_integrity()
    assert result.receipt.provenance_bundle.verify_integrity()
    assert result.receipt.dataset_sha256 == result.version.dataset_sha256
    assert (workspace / "current.json").is_file()
    version = workspace / "versions" / "v0001"
    assert (version / "snapshot.json").is_file()
    assert (version / "diff.json").is_file()
    assert (version / "provenance.json").is_file()
    assert (version / "receipt.json").is_file()
    assert (version / "release.json").is_file()
    assert "https://example.test/domain#PartMode" in (
        version / "snapshot.json"
    ).read_text(encoding="utf-8")

    with pytest.raises(GovernanceWorkspaceExistsError):
        initialize_workspace(workspace, name="Replacement")
    assert history_workspace(workspace)[0].record_sha256 == result.version.record_sha256


def test_propose_and_commit_fail_closed_until_conflict_has_reason(tmp_path):
    workspace = tmp_path / "domain"
    initialize_workspace(
        workspace,
        name="Domain",
        namespace="https://example.test/domain#",
        baseline=_baseline(),
        source_identity=SOURCE_IDENTITY,
        recorded_at=T0,
    )
    delta = {
        "classes": [
            {"name": "PartMode", "comment": "part intent plus collaboration"},
            {"name": "HybridMode", "comment": "hybrid intent"},
        ]
    }
    proposal = propose_change(workspace, delta)
    assert proposal.added_classes == ("HybridMode",)
    assert tuple(item.name for item in proposal.conflicts) == ("PartMode",)
    current_before = (workspace / "current.json").read_bytes()

    with pytest.raises(GovernanceGateError):
        commit_change(workspace, delta, source_identity=SOURCE_IDENTITY)
    with pytest.raises(GovernanceGateError):
        commit_change(
            workspace,
            delta,
            verdicts={"PartMode": {"action": "merge", "reason": ""}},
            source_identity=SOURCE_IDENTITY,
        )
    with pytest.raises(GovernanceGateError, match="does not match"):
        commit_change(
            workspace,
            {"classes": [{"name": "SafeAddition", "comment": "new"}]},
            verdicts={"Typo": {"action": "replace", "reason": "wrong target"}},
            source_identity=SOURCE_IDENTITY,
        )
    assert (workspace / "current.json").read_bytes() == current_before
    assert not (workspace / "versions" / "v0002").exists()

    result = commit_change(
        workspace,
        delta,
        verdicts={
            "PartMode": {
                "action": "merge",
                "reason": "new practice adds collaboration without retracting old meaning",
            }
        },
        attempt="lesson-2",
        source_identity=SOURCE_IDENTITY,
        recorded_at=T1,
    )
    assert result.version.version == 2
    assert result.release.complete
    ontology = json.loads(
        (workspace / "versions" / "v0002" / "ontology.json").read_text()
    )
    assert ontology["classes"]["PartMode"]["comment"] == (
        "part-only intent；part intent plus collaboration"
    )
    history = history_workspace(workspace)
    assert history[1].parent_record_sha256 == history[0].record_sha256


def test_reasoned_removal_can_commit_but_failed_old_cq_blocks_release(tmp_path):
    workspace = tmp_path / "domain"
    initialize_workspace(
        workspace,
        name="Domain",
        namespace="https://example.test/domain#",
        baseline=_baseline(),
        source_identity=SOURCE_IDENTITY,
        recorded_at=T0,
    )
    _write_cq(workspace)
    assert regress_workspace(workspace).passed

    with pytest.raises(GovernanceGateError):
        commit_change(
            workspace,
            {"removes": ["PartMode"]},
            source_identity=SOURCE_IDENTITY,
        )
    result = commit_change(
        workspace,
        {"removes": ["PartMode"]},
        verdicts={
            "PartMode": {
                "reason": "teaching counterexample; impacted CQ intentionally retained"
            }
        },
        attempt="removal-counterexample",
        source_identity=SOURCE_IDENTITY,
        recorded_at=T1,
    )
    assert result.version.version == 2
    assert not result.regression.passed
    assert result.release.status == "blocked"
    assert "report.cq" in result.release.reasons
    assert not regress_workspace(workspace).passed
    assert main(["regress", "--workspace", str(workspace)]) == 1


def test_unknown_removal_and_cross_kind_collision_never_mutate_current(tmp_path):
    workspace = tmp_path / "domain"
    initialize_workspace(
        workspace,
        name="Domain",
        namespace="https://example.test/domain#",
        baseline=_baseline(),
        source_identity=SOURCE_IDENTITY,
        recorded_at=T0,
    )
    current_before = (workspace / "current.json").read_bytes()
    with pytest.raises(GovernanceGateError):
        commit_change(
            workspace,
            {"removes": ["Missing"]},
            verdicts={"Missing": {"reason": "cannot make an unknown entity real"}},
        )
    with pytest.raises(GovernanceInputError):
        commit_change(
            workspace,
            {"properties": [{"name": "PartMode", "comment": "ambiguous pun"}]},
        )
    with pytest.raises(GovernanceInputError, match="add/change and remove"):
        commit_change(
            workspace,
            {
                "classes": [{"name": "PartMode", "comment": "changed"}],
                "removes": ["PartMode"],
            },
        )
    assert (workspace / "current.json").read_bytes() == current_before
    assert len(history_workspace(workspace)) == 1


def test_existing_next_version_and_tamper_are_detected(tmp_path):
    workspace = tmp_path / "domain"
    initialize_workspace(
        workspace,
        name="Domain",
        namespace="https://example.test/domain#",
        baseline=_baseline(),
        source_identity=SOURCE_IDENTITY,
        recorded_at=T0,
    )
    (workspace / "versions" / "v0002").mkdir()
    with pytest.raises(GovernanceWorkspaceError):
        commit_change(workspace, {"classes": [{"name": "New", "comment": "x"}]})
    assert json.loads((workspace / "current.json").read_text())["version"] == 1
    (workspace / "versions" / "v0002").rmdir()

    ontology = workspace / "versions" / "v0001" / "ontology.json"
    ontology.write_text("{}\n", encoding="utf-8")
    with pytest.raises(GovernanceWorkspaceError, match="hash mismatch"):
        history_workspace(workspace)


def test_standalone_cli_preserves_propose_exit_two(tmp_path, capsys):
    workspace = tmp_path / "domain"
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(_baseline()), encoding="utf-8")
    assert (
        main(
            [
                "init",
                "--workspace",
                str(workspace),
                "--name",
                "Domain",
                "--namespace",
                "https://example.test/domain#",
                "--baseline",
                str(baseline),
            ]
        )
        == 0
    )
    delta = tmp_path / "delta.json"
    delta.write_text(
        json.dumps({"classes": [{"name": "PartMode", "comment": "different"}]}),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "propose",
                "--workspace",
                str(workspace),
                "--delta",
                str(delta),
            ]
        )
        == 2
    )
    assert '"requires_verdicts":true' in capsys.readouterr().out
