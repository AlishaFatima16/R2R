import pytest

from pipeline.transform.depsdev import transform_dependencies


def sample_graph():
    return {
        "nodes": [
            {"versionKey": {"system": "PYPI", "name": "My_Root", "version": "1.0"}, "relation": "SELF"},
            {"versionKey": {"system": "PYPI", "name": "Direct-Pkg", "version": "2.0"}, "relation": "DIRECT"},
            {"versionKey": {"system": "PYPI", "name": "transitive", "version": "3.0"}, "relation": "INDIRECT"},
            {"versionKey": {"system": "PYPI", "name": "orphan", "version": "4.0"}, "relation": "INDIRECT"},
        ],
        "edges": [{"fromNode": 0, "toNode": 1}, {"fromNode": 1, "toNode": 2}],
    }


def test_depth_is_derived_from_edges_and_unreachable_nodes_are_omitted():
    frame = transform_dependencies(sample_graph(), root_name="my-root", root_version="1.0")
    assert list(frame.columns) == [
        "root_canonical_name", "root_version", "canonical_name", "node_version", "relation", "depth"
    ]
    assert frame[["canonical_name", "relation", "depth"]].to_dict("records") == [
        {"canonical_name": "direct-pkg", "relation": "DIRECT", "depth": 1},
        {"canonical_name": "transitive", "relation": "INDIRECT", "depth": 2},
    ]


def test_root_mismatch_is_rejected():
    with pytest.raises(ValueError, match="root package"):
        transform_dependencies(sample_graph(), root_name="different", root_version="1.0")


def test_invalid_edge_index_is_rejected():
    body = sample_graph()
    body["edges"].append({"fromNode": 0, "toNode": 99})
    with pytest.raises(ValueError, match="outside nodes"):
        transform_dependencies(body, root_name="my-root", root_version="1.0")
