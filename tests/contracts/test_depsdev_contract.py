import pytest
from pydantic import ValidationError

from pipeline.contracts.depsdev import DepsDevGraph


def test_valid_graph_contract():
    graph = DepsDevGraph.model_validate({
        "nodes": [
            {"versionKey": {"system": "PYPI", "name": "root", "version": "1"}, "relation": "SELF"},
            {"versionKey": {"system": "PYPI", "name": "child", "version": "2"}, "relation": "DIRECT"},
        ],
        "edges": [{"fromNode": 0, "toNode": 1}],
    })
    assert len(graph.nodes) == 2


def test_empty_nodes_are_rejected():
    with pytest.raises(ValidationError):
        DepsDevGraph.model_validate({"nodes": [], "edges": []})


def test_invalid_edge_relation_is_rejected():
    with pytest.raises(ValidationError):
        DepsDevGraph.model_validate({"nodes": [
            {"versionKey": {"system": "PYPI", "name": "root", "version": "1"}, "relation": "ROOT"}
        ]})
