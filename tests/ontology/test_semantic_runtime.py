from __future__ import annotations

import json

import pytest
from rdflib import Graph
from rdflib.compare import isomorphic

from semantica.ontology import SemanticRuntime as ExportedSemanticRuntime
from semantica.ontology.runtime import (
    CAP_SHACL_VALIDATE,
    AskResultDTO,
    CapabilityUnavailableError,
    ConstructResultDTO,
    LossySerializationError,
    SelectResultDTO,
    SemanticInputError,
    SemanticRuntime,
    UnsupportedBackendError,
    UnsupportedCapabilityError,
    UnsupportedProfileError,
    UnsupportedQueryTypeError,
)

EX = "http://example.org/"


TRIG_DATASET = """
@prefix ex: <http://example.org/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

_:person ex:name "Alice"@en ;
         ex:age "42"^^xsd:integer .

ex:people {
  ex:record ex:describes _:person ;
            ex:status "active" .
}
"""


PERSON_SHAPE = """
@prefix ex: <http://example.org/> .
@prefix sh: <http://www.w3.org/ns/shacl#> .

ex:PersonShape a sh:NodeShape ;
    sh:targetClass ex:Person ;
    sh:property [
        sh:path ex:name ;
        sh:minCount 1 ;
        sh:message "A person requires a name" ;
    ] .
"""


def test_public_export_and_fail_closed_profiles_and_backend(monkeypatch):
    assert ExportedSemanticRuntime is SemanticRuntime

    runtime = SemanticRuntime(profile="ontology-runtime")
    assert runtime.profile.name == "ontology-runtime"
    assert runtime.profile.backend == "rdflib"
    assert runtime.profile.fail_closed is True
    assert runtime.supports(CAP_SHACL_VALIDATE) is True
    assert runtime.profile.as_dict()["backend"] == "rdflib"

    with pytest.raises(UnsupportedProfileError, match="Unsupported.*profile"):
        SemanticRuntime(profile="best-effort")
    with pytest.raises(UnsupportedBackendError, match="only 'rdflib'"):
        SemanticRuntime(backend="oxigraph")
    with pytest.raises(UnsupportedCapabilityError, match="Unknown.*capability"):
        SemanticRuntime(required_capabilities=["magic.reasoning"])

    rdf_only = SemanticRuntime(profile="rdf")
    with pytest.raises(CapabilityUnavailableError, match="shacl.validate"):
        rdf_only.validate(PERSON_SHAPE)

    import semantica.ontology.runtime as runtime_module

    available = runtime_module._module_available
    monkeypatch.setattr(
        runtime_module,
        "_module_available",
        lambda name: False if name == "pyshacl" else available(name),
    )
    with pytest.raises(CapabilityUnavailableError, match="ontology-runtime"):
        SemanticRuntime(profile="ontology-runtime")
    # The RDF profile remains explicit and usable; there is no silent profile
    # downgrade from ontology-runtime.
    assert SemanticRuntime(profile="rdf").profile.name == "rdf"


def test_lossless_dataset_roundtrip_preserves_context_bnodes_and_literals():
    runtime = SemanticRuntime()
    loaded = runtime.load(TRIG_DATASET, format="trig")

    assert loaded.added == 4
    assert loaded.quad_count == 4
    assert runtime.revision == 1

    selected = runtime.select("""
        PREFIX ex: <http://example.org/>
        SELECT ?person ?name ?age WHERE {
          GRAPH ex:people { ex:record ex:describes ?person }
          ?person ex:name ?name ; ex:age ?age .
        }
        """)
    assert selected.variables == ("person", "name", "age")
    assert len(selected.rows) == 1
    row = selected.rows[0]
    assert row["person"].term_type == "blank_node"
    assert str(row["name"]) == "Alice"
    assert row["name"].language == "en"
    assert row["name"].datatype is None
    assert row["age"].value == "42"
    assert row["age"].datatype == "http://www.w3.org/2001/XMLSchema#integer"
    assert row.as_dict()["name"] == row["name"]

    serialized = runtime.serialize(format="trig")
    restored = SemanticRuntime()
    restored.load(serialized.encode("utf-8"), format="trig")

    restored_row = restored.select("""
        PREFIX ex: <http://example.org/>
        SELECT ?name ?age WHERE {
          GRAPH ex:people { ex:record ex:describes ?person }
          ?person ex:name ?name ; ex:age ?age .
        }
        """).rows[0]
    assert restored_row["name"].language == "en"
    assert restored_row["age"].datatype.endswith("#integer")
    assert restored.ask(
        "ASK { GRAPH <http://example.org/people> { ?s ?p ?o } }"
    ).boolean


def test_named_graph_cannot_be_silently_flattened():
    runtime = SemanticRuntime()
    runtime.load(TRIG_DATASET, format="trig")

    with pytest.raises(LossySerializationError, match="named graphs"):
        runtime.serialize(format="turtle")

    named_graph = runtime.serialize(
        format="turtle", graph_name="http://example.org/people"
    )
    assert "describes" in named_graph
    assert "name" not in named_graph


def test_load_accepts_path_text_bytes_base_uri_and_graph_name(tmp_path):
    source = tmp_path / "relative.ttl"
    source.write_text('<thing> <property> "from-path"@en .\n', encoding="utf-8")
    runtime = SemanticRuntime()

    runtime.load(
        source,
        base_uri="http://example.org/base/",
        graph_name="http://example.org/path-graph",
    )
    runtime.load(
        b'<http://example.org/bytes> <http://example.org/property> "bytes" .',
        format="nt",
    )
    runtime.load(
        '<http://example.org/text> <http://example.org/property> "text" .',
        format="nt",
    )

    assert runtime.ask("""
        ASK { GRAPH <http://example.org/path-graph> {
          <http://example.org/base/thing>
          <http://example.org/base/property> "from-path"@en
        } }
        """).boolean
    assert runtime.ask(
        "ASK { <http://example.org/bytes> ?p ?o . <http://example.org/text> ?p2 ?o2 }"
    ).boolean


def test_malformed_load_is_atomic():
    runtime = SemanticRuntime()
    runtime.load('<http://example.org/a> <http://example.org/p> "ok" .', format="nt")
    revision = runtime.revision

    with pytest.raises(SemanticInputError, match="Failed to parse RDF"):
        runtime.load("this is not turtle {", format="turtle")

    assert runtime.quad_count == 1
    assert runtime.revision == revision


def test_select_ask_cache_and_mutation_invalidation():
    runtime = SemanticRuntime()
    runtime.load('<http://example.org/a> <http://example.org/p> "one" .', format="nt")
    query = "SELECT ?s ?o WHERE { ?s <http://example.org/p> ?o } ORDER BY ?s"

    first = runtime.select(query)
    second = runtime.select(query)
    asked = runtime.ask("ASK { <http://example.org/a> ?p ?o }")

    assert isinstance(first, SelectResultDTO)
    assert first.cache_hit is False
    assert second.cache_hit is True
    assert isinstance(asked, AskResultDTO)
    assert asked.boolean is True

    update = runtime.update("""
        INSERT DATA {
          <http://example.org/b> <http://example.org/p> "two" .
          GRAPH <http://example.org/audit> {
            <http://example.org/change> <http://example.org/type> "insert" .
          }
        }
        """)
    after = runtime.select(query)

    assert update.added == 2
    assert update.revision == 2
    assert after.cache_hit is False
    assert [row["s"].value for row in after.rows] == [
        "http://example.org/a",
        "http://example.org/b",
    ]
    assert runtime.ask("ASK { GRAPH <http://example.org/audit> { ?s ?p ?o } }").boolean

    replaced = runtime.update("""
        DELETE { <http://example.org/a> <http://example.org/p> ?old }
        INSERT { <http://example.org/a> <http://example.org/p> "changed" }
        WHERE  { <http://example.org/a> <http://example.org/p> ?old }
        """)
    assert replaced.revision == 3
    assert runtime.ask(
        'ASK { <http://example.org/a> <http://example.org/p> "changed" }'
    ).boolean


def test_construct_is_stable_serializable_and_reloadable():
    runtime = SemanticRuntime()
    runtime.load(TRIG_DATASET, format="trig")

    constructed = runtime.construct("""
        PREFIX ex: <http://example.org/>
        CONSTRUCT { ?person ex:copiedName ?name ; ex:copiedAge ?age }
        WHERE {
          ?person ex:name ?name ; ex:age ?age .
        }
        """)

    assert isinstance(constructed, ConstructResultDTO)
    assert len(constructed.triples) == 2
    assert any(
        triple.subject.term_type == "blank_node" for triple in constructed.triples
    )
    assert any(triple.object.language == "en" for triple in constructed.triples)
    assert any(
        triple.object.datatype == "http://www.w3.org/2001/XMLSchema#integer"
        for triple in constructed.triples
    )

    turtle = constructed.serialize(format="turtle")
    restored = SemanticRuntime()
    restored.load(constructed)
    restored_turtle = restored.serialize(format="turtle")

    left = Graph().parse(data=turtle, format="turtle")
    right = Graph().parse(data=restored_turtle, format="turtle")
    assert isomorphic(left, right)
    assert restored.ask('ASK { ?s <http://example.org/copiedName> "Alice"@en }').boolean


def test_query_helpers_fail_closed_on_wrong_query_type():
    runtime = SemanticRuntime()
    runtime.load('<http://example.org/a> <http://example.org/p> "one" .', format="nt")

    with pytest.raises(UnsupportedQueryTypeError, match=r"select\(\)"):
        runtime.select("ASK { ?s ?p ?o }")
    with pytest.raises(UnsupportedQueryTypeError, match="SELECT, ASK, and CONSTRUCT"):
        runtime.query("DESCRIBE <http://example.org/a>")


def test_shacl_report_is_normalized_and_positive_after_update():
    runtime = SemanticRuntime()
    runtime.load(
        """
        @prefix ex: <http://example.org/> .
        ex:alice a ex:Person .
        """,
        format="turtle",
    )

    report = runtime.validate(
        PERSON_SHAPE,
        shapes_format="turtle",
        inference="none",
        advanced=True,
        abort_on_first=True,
    )

    assert report.conforms is False
    assert report.text
    assert report.inference == "none"
    assert report.advanced is True
    assert report.abort_on_first is True
    assert report.violation_count == 1
    violation = report.violations[0]
    assert violation.focus == EX + "alice"
    assert violation.focus_node == EX + "alice"
    assert violation.path == EX + "name"
    assert violation.result_path == EX + "name"
    assert violation.source_constraint == "MinCountConstraintComponent"
    assert violation.severity == "Violation"
    assert violation.message == "A person requires a name"

    runtime.update(
        'INSERT DATA { <http://example.org/alice> <http://example.org/name> "Alice" }'
    )
    passing = runtime.validate(PERSON_SHAPE)
    assert passing.conforms is True
    assert passing.violations == ()


def test_shacl_parameters_are_passed_to_backend(monkeypatch):
    import pyshacl

    runtime = SemanticRuntime()
    runtime.load(
        "@prefix ex: <http://example.org/> . ex:alice a ex:Person .",
        format="turtle",
    )
    actual_validate = pyshacl.validate
    captured = {}

    def recording_validate(*args, **kwargs):
        captured.update(kwargs)
        return actual_validate(*args, **kwargs)

    monkeypatch.setattr(pyshacl, "validate", recording_validate)
    runtime.validate(
        PERSON_SHAPE,
        inference="rdfs",
        advanced=True,
        abort_on_first=True,
    )

    assert captured["inference"] == "rdfs"
    assert captured["advanced"] is True
    assert captured["abort_on_first"] is True

    with pytest.raises(SemanticInputError, match="inference mode"):
        runtime.validate(PERSON_SHAPE, inference="guess")


def test_content_bound_package_load_retains_all_assets_and_identity(tmp_path):
    (tmp_path / "ontology.trig").write_text(
        """
        @prefix ex: <http://example.org/package/> .
        ex:data { ex:item ex:status "ready" . }
        """,
        encoding="utf-8",
    )
    (tmp_path / "cq01.rq").write_text(
        "ASK { GRAPH <http://example.org/package/data> { ?s ?p ?o } }\n",
        encoding="utf-8",
    )
    (tmp_path / "shape.ttl").write_text(PERSON_SHAPE, encoding="utf-8")
    manifest = {
        "schema_version": "1.0",
        "package_id": "semantica.chapter.vol1.ch04",
        "version": "1.0.0",
        "namespace": "http://example.org/package/",
        "assets": [
            {
                "asset_id": "ontology",
                "role": "ontology",
                "path": "ontology.trig",
                "format": "trig",
            },
            {"asset_id": "cq-01", "role": "sparql", "path": "cq01.rq"},
            {"asset_id": "shapes", "role": "shapes", "path": "shape.ttl"},
        ],
    }
    manifest_path = tmp_path / "package.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    runtime = SemanticRuntime()
    result = runtime.load_package(manifest_path)

    assert result.identity.package_id == "semantica.chapter.vol1.ch04"
    assert result.identity.version == "1.0.0"
    assert len(result.identity.digest) == 64
    assert result.rdf_added == 1
    assert (
        runtime.package_identity("semantica.chapter.vol1.ch04", "1.0.0")
        == result.identity
    )
    assert (
        runtime.package_asset("semantica.chapter.vol1.ch04", "1.0.0", "cq-01").content
        == (tmp_path / "cq01.rq").read_bytes()
    )
    assert (
        runtime.package_asset(
            "semantica.chapter.vol1.ch04", "1.0.0", "shapes"
        ).loaded_into_dataset
        is False
    )
    assert runtime.ask(
        "ASK { GRAPH <http://example.org/package/data> { ?s ?p ?o } }"
    ).boolean

    # Exact reload is idempotent; same identity with changed bytes is rejected.
    again = runtime.load_package(manifest_path)
    assert again.identity == result.identity
    assert again.rdf_added == 0
    (tmp_path / "cq01.rq").write_text("ASK { ?s ?p ?o }\n", encoding="utf-8")
    with pytest.raises(SemanticInputError, match="different digest"):
        runtime.load_package(manifest_path)


def test_package_rejects_bad_digest_and_path_escape(tmp_path):
    outside = tmp_path.parent / "outside-runtime.ttl"
    outside.write_text(
        '<http://example.org/a> <http://example.org/p> "x" .',
        encoding="utf-8",
    )
    runtime = SemanticRuntime()

    with pytest.raises(SemanticInputError, match="escapes"):
        runtime.load_package(
            {
                "schema_version": "1.0",
                "package_id": "bad.path",
                "version": "1",
                "assets": [
                    {
                        "asset_id": "rdf",
                        "role": "ontology",
                        "path": "../outside-runtime.ttl",
                    }
                ],
            },
            base_path=tmp_path,
        )

    with pytest.raises(SemanticInputError, match="sha256 mismatch"):
        runtime.load_package(
            {
                "schema_version": "1.0",
                "package_id": "bad.digest",
                "version": "1",
                "assets": [
                    {
                        "asset_id": "rdf",
                        "role": "ontology",
                        "data": '<http://example.org/a> <http://example.org/p> "x" .',
                        "format": "nt",
                        "sha256": "0" * 64,
                    }
                ],
            }
        )

    with pytest.raises(SemanticInputError, match="Failed to parse RDF"):
        runtime.load_package(
            {
                "schema_version": "1.0",
                "package_id": "bad.atomic",
                "version": "1",
                "assets": [
                    {
                        "asset_id": "first",
                        "role": "ontology",
                        "data": '<http://example.org/a> <http://example.org/p> "x" .',
                        "format": "nt",
                    },
                    {
                        "asset_id": "second",
                        "role": "data",
                        "data": "not valid turtle {",
                        "format": "turtle",
                    },
                ],
            }
        )
    assert runtime.quad_count == 0
    assert runtime.packages == ()
