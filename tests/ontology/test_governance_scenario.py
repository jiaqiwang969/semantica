from semantica.ontology.governance import RuntimeSourceIdentityDTO
from semantica.ontology.governance_scenario import (
    GovernanceAcceptanceResultDTO,
    run_governance_acceptance_scenario,
)


def test_builtin_governance_acceptance_scenario_is_complete_and_pure_data():
    result = run_governance_acceptance_scenario(
        RuntimeSourceIdentityDTO(
            runtime_commit="a" * 40,
            runtime_artifact_sha256="b" * 64,
            runtime_version="test",
        )
    )
    assert isinstance(result, GovernanceAcceptanceResultDTO)
    assert result.passed
    assert result.version_count == 4
    assert result.final_regression_status == "failed"
    assert len(result.checks) == 5
    assert all(item.passed for item in result.checks)
    payload = result.as_dict()
    assert payload["status"] == "passed"
    assert "workspace" not in str(payload).lower()
