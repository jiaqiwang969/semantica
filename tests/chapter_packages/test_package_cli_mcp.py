"""Public CLI/MCP coverage for Semantica's built-in package control plane."""

import json

import pytest
from click.testing import CliRunner

import semantica.cli as cli_module
from semantica import mcp_server


NORMATIVE_ID = "semantica.chapter_packages.vol2.normative"
CHAPTER_ID = "semantica.chapter_packages.vol1.ch03"
ARTIFACT_SHA256 = "a" * 64


class _DTO:
    def __init__(self, payload):
        self._payload = payload

    def as_dict(self):
        return dict(self._payload)


class _Runner:
    def __init__(self):
        self.run_calls = []
        self.verify_calls = []

    def run(self, **kwargs):
        self.run_calls.append(kwargs)
        return _DTO(
            {
                "package_id": kwargs["package_id"],
                "receipt_status": "blocked",
                "scenario_id": kwargs["scenario_id"],
            }
        )

    def verify(self, result):
        self.verify_calls.append(result)
        return _DTO({"releasable": False, "status": "blocked"})


@pytest.fixture(autouse=True)
def _quiet_logging(monkeypatch):
    monkeypatch.setattr(cli_module, "setup_logging", lambda *args, **kwargs: None)


def _cli_json(arguments):
    result = CliRunner().invoke(cli_module.main, arguments)
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def _mcp_tool_payload(name, arguments):
    response = mcp_server._handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    return response, json.loads(response["result"]["content"][0]["text"])


def test_cli_lists_exactly_29_chapters_and_normative_domain_package():
    first = _cli_json(["package", "list", "--json"])
    second = _cli_json(["package", "list", "--json"])

    assert first == second
    assert first["chapter_package_count"] == 29
    assert first["domain_package_count"] == 1
    assert first["package_count"] == 30
    assert len(first["packages"]) == 30
    assert NORMATIVE_ID in {item["package_id"] for item in first["packages"]}
    assert all("manifest_path" not in item for item in first["packages"])


def test_package_group_is_visible_and_has_the_five_public_commands():
    root_help = CliRunner().invoke(cli_module.main, ["--help"])
    package_help = CliRunner().invoke(cli_module.main, ["package", "--help"])
    assert root_help.exit_code == 0
    assert "package" in root_help.output
    assert package_help.exit_code == 0
    for command in ("list", "show", "run", "verify", "verify-books"):
        assert command in package_help.output


def test_cli_show_accepts_normative_id_but_rejects_path_traversal():
    payload = _cli_json(["package", "show", NORMATIVE_ID, "--json"])
    assert payload["package"]["kind"] == "domain"
    assert payload["manifest"]["package_id"] == NORMATIVE_ID

    result = CliRunner().invoke(
        cli_module.main,
        ["package", "show", "../../etc/passwd", "--json"],
    )
    assert result.exit_code == 1
    error = json.loads(result.output)
    assert error["error"]["code"] == "package_not_found"
    assert "manifest" not in error


def test_cli_run_and_verify_bind_runtime_identity_and_emit_dtos(monkeypatch):
    fake = _Runner()
    monkeypatch.setattr(cli_module, "_package_runner", lambda: fake)
    options = [
        CHAPTER_ID,
        "--scenario-id",
        "semantica.vol1.ch03.scenario.cq01",
        "--runtime-commit",
        "commit-123",
        "--runtime-artifact-sha256",
        ARTIFACT_SHA256,
        "--json",
    ]

    run_payload = _cli_json(["package", "run", *options])
    verify_result = CliRunner().invoke(
        cli_module.main, ["package", "verify", *options]
    )
    assert verify_result.exit_code == 1
    verify_payload = json.loads(verify_result.output)

    assert run_payload["result"]["package_id"] == CHAPTER_ID
    assert verify_payload["result"]["release_verdict"]["releasable"] is False
    assert verify_payload["error"]["code"] == "release_blocked"
    assert len(fake.run_calls) == 2
    assert len(fake.verify_calls) == 1
    assert fake.run_calls[0]["runtime_commit"] == "commit-123"
    assert fake.run_calls[0]["runtime_artifact_sha256"] == ARTIFACT_SHA256


def test_cli_rejects_unbound_or_invalid_runtime_artifact(monkeypatch):
    fake = _Runner()
    monkeypatch.setattr(cli_module, "_package_runner", lambda: fake)
    result = CliRunner().invoke(
        cli_module.main,
        [
            "package",
            "run",
            CHAPTER_ID,
            "--runtime-commit",
            "commit-123",
            "--runtime-artifact-sha256",
            "not-a-digest",
            "--json",
        ],
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["error"]["code"] == "invalid_request"
    assert not fake.run_calls

    unbound = CliRunner().invoke(
        cli_module.main,
        ["package", "run", CHAPTER_ID, "--json"],
    )
    assert unbound.exit_code == 1
    unbound_payload = json.loads(unbound.output)
    assert unbound_payload["error"]["code"] == "invalid_request"
    assert unbound_payload["schema_version"] == "1.0"


def test_cli_real_runner_emits_bound_receipt_and_blocked_release_verdict():
    pytest.importorskip("rdflib")
    pytest.importorskip("pyshacl")
    options = [
        CHAPTER_ID,
        "--runtime-commit",
        "integration-commit",
        "--runtime-artifact-sha256",
        ARTIFACT_SHA256,
        "--json",
    ]
    run_result = CliRunner().invoke(
        cli_module.main, ["package", "run", *options]
    )
    assert run_result.exit_code == 0, run_result.output
    run_payload = json.loads(run_result.output)
    assert run_payload["result"]["status"] == "passed"
    assert run_payload["result"]["receipt"]["runtime_commit"] == (
        "integration-commit"
    )
    assert run_payload["result"]["receipt"]["runtime_artifact_sha256"] == (
        ARTIFACT_SHA256
    )
    assert run_payload["result"]["release_verdict"]["status"] == "blocked"

    verify_result = CliRunner().invoke(
        cli_module.main, ["package", "verify", *options]
    )
    assert verify_result.exit_code == 1
    verify_payload = json.loads(verify_result.output)
    assert verify_payload["error"]["code"] == "release_blocked"
    assert verify_payload["result"]["release_verdict"]["status"] == "blocked"


def test_mcp_lists_tools_registry_and_manifest_resources():
    tool_names = {item["name"] for item in mcp_server.TOOLS}
    assert {
        "list_chapter_packages",
        "get_chapter_package",
        "verify_book_sources",
        "run_chapter_package",
        "verify_chapter_package",
    } <= tool_names

    resources = mcp_server._listed_resources()
    uris = {item["uri"] for item in resources}
    assert "semantica://packages/registry" in uris
    assert "semantica://packages/manifest/" + CHAPTER_ID in uris
    assert "semantica://packages/manifest/" + NORMATIVE_ID in uris
    registry = mcp_server._read_resource("semantica://packages/registry")
    assert registry["chapter_package_count"] == 29
    assert registry["domain_package_count"] == 1


def test_mcp_manifest_resource_and_get_tool_reject_path_traversal():
    manifest = mcp_server._read_resource(
        "semantica://packages/manifest/" + CHAPTER_ID
    )
    assert manifest["manifest"]["package_id"] == CHAPTER_ID
    assert "manifest_path" not in manifest["package"]

    blocked = mcp_server._read_resource(
        "semantica://packages/manifest/../../etc/passwd"
    )
    assert blocked["ok"] is False
    assert blocked["error"]["code"] == "package_not_found"

    response, blocked_tool = _mcp_tool_payload(
        "get_chapter_package", {"package_id": "../../etc/passwd"}
    )
    assert response["result"]["isError"] is True
    assert blocked_tool["error"]["code"] == "package_not_found"


def test_mcp_run_and_verify_emit_as_dict_only(monkeypatch):
    fake = _Runner()
    monkeypatch.setattr(mcp_server, "_package_runner", lambda: fake)
    arguments = {
        "package_id": CHAPTER_ID,
        "scenario_id": "semantica.vol1.ch03.scenario.cq01",
        "runtime_commit": "commit-123",
        "runtime_artifact_sha256": ARTIFACT_SHA256,
    }

    run_response, run_payload = _mcp_tool_payload(
        "run_chapter_package", arguments
    )
    verify_response, verify_payload = _mcp_tool_payload(
        "verify_chapter_package", arguments
    )

    assert "isError" not in run_response["result"]
    assert verify_response["result"]["isError"] is True
    assert run_payload["result"]["package_id"] == CHAPTER_ID
    assert verify_payload["result"]["release_verdict"]["status"] == "blocked"
    assert verify_payload["error"]["code"] == "release_blocked"
    assert len(fake.run_calls) == 2
    assert len(fake.verify_calls) == 1


def test_mcp_invalid_digest_fails_closed_without_calling_runner(monkeypatch):
    fake = _Runner()
    monkeypatch.setattr(mcp_server, "_package_runner", lambda: fake)
    response, payload = _mcp_tool_payload(
        "run_chapter_package",
        {
            "package_id": CHAPTER_ID,
            "runtime_commit": "commit-123",
            "runtime_artifact_sha256": "bad",
        },
    )
    assert response["result"]["isError"] is True
    assert payload["error"]["code"] == "invalid_argument"
    assert not fake.run_calls

    response, payload = _mcp_tool_payload(
        "run_chapter_package",
        {
            "package_id": CHAPTER_ID,
            "runtime_commit": "commit-123",
            "runtime_artifact_sha256": ARTIFACT_SHA256,
            "path": "../../etc/passwd",
        },
    )
    assert response["result"]["isError"] is True
    assert payload["error"]["code"] == "invalid_argument"
    assert not fake.run_calls


def test_mcp_internal_errors_do_not_disclose_exception_details(monkeypatch):
    secret = "/private/build/credentials-and-connection-string"

    def fail_closed(_name, _arguments):
        raise RuntimeError(secret)

    monkeypatch.setattr(mcp_server, "call_mcp_tool", fail_closed)
    response = mcp_server.handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "list_chapter_packages", "arguments": {}},
        }
    )

    assert response["error"]["code"] == -32603
    assert "RuntimeError" in response["error"]["message"]
    assert secret not in response["error"]["message"]


def test_mcp_rejects_opaque_runner_objects(monkeypatch):
    class _OpaqueRunner:
        def run(self, **kwargs):
            return object()

    monkeypatch.setattr(mcp_server, "_package_runner", _OpaqueRunner)
    response, payload = _mcp_tool_payload(
        "run_chapter_package",
        {
            "package_id": CHAPTER_ID,
            "runtime_commit": "commit-123",
            "runtime_artifact_sha256": ARTIFACT_SHA256,
        },
    )
    assert response["result"]["isError"] is True
    assert payload["error"]["code"] == "invalid_runner_result"


def test_historical_top_level_mcp_entry_delegates_canonical_protocol():
    from mcp.server import SemanticaMCPServer

    server = SemanticaMCPServer()
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "resources/read",
            "params": {"uri": "semantica://packages/registry"},
        },
    ]
    for request in requests:
        assert server.dispatch(request) == mcp_server.handle_mcp_request(request)


def test_top_level_mcp_compatibility_registries_are_canonical_views():
    from mcp.resources import RESOURCE_DEFINITIONS, handle_resource_read
    from mcp.tools import TOOL_DEFINITIONS, __all__ as compatibility_tool_names

    assert TOOL_DEFINITIONS is mcp_server.TOOLS
    assert "TOOL_DEFINITIONS" in compatibility_tool_names
    assert {item["name"] for item in mcp_server.TOOLS} <= set(
        compatibility_tool_names
    )
    assert RESOURCE_DEFINITIONS == mcp_server.list_mcp_resources()
    compatibility_registry = json.loads(
        handle_resource_read("semantica://packages/registry")["text"]
    )
    assert compatibility_registry == mcp_server.read_mcp_resource(
        "semantica://packages/registry"
    )


def test_cli_mcp_commands_use_canonical_package_tools():
    tools = _cli_json(["mcp", "list-tools", "--json"])["tools"]
    assert "list_chapter_packages" in tools
    assert "verify_chapter_package" in tools

    payload = _cli_json(
        [
            "mcp",
            "call",
            "get_chapter_package",
            "--args",
            json.dumps({"package_id": CHAPTER_ID}),
            "--json",
        ]
    )
    assert payload["package"]["package_id"] == CHAPTER_ID
