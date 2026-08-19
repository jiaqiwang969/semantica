"""Regression checks for ontology-only, offline Semantica initialization."""

from unittest.mock import MagicMock, patch

from semantica.ontology.engine import OntologyEngine
from semantica.ontology.ontology_generator import SHACLGenerator


def test_engine_does_not_initialize_llm_for_ontology_only_use() -> None:
    with patch(
        "semantica.ontology.llm_generator.LLMOntologyGenerator.__init__",
        side_effect=AssertionError("LLM generator must remain lazy"),
    ):
        engine = OntologyEngine(base_uri="https://example.org/ontology#")
        assert engine.llm is None
        assert engine.from_data({"entities": []}, name="offline")["name"] == "offline"


def test_from_text_materializes_llm_once() -> None:
    llm = MagicMock()
    llm.generate_ontology_from_text.return_value = {"name": "generated"}
    engine = OntologyEngine(llm_generator=llm)

    assert engine.from_text("a domain", provider="mock", model="local") == {
        "name": "generated"
    }
    llm.set_provider.assert_called_once_with("mock", model="local")
    llm.generate_ontology_from_text.assert_called_once_with("a domain")


def test_shacl_generator_preserves_fragment_namespace() -> None:
    generator = SHACLGenerator(base_uri="https://example.org/manufacturing#")
    assert generator.base_uri == "https://example.org/manufacturing#"
    assert generator.shapes_uri == "https://example.org/manufacturing#shapes"
