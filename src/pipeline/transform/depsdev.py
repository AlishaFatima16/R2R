"""Transform a deps.dev resolved graph into natural-key resolved_node rows."""
from __future__ import annotations

from collections import deque

import pandas as pd
from packaging.utils import canonicalize_name

from pipeline.contracts.depsdev import DepsDevGraph

RESOLVED_NODE_COLUMNS = (
    "root_canonical_name", "root_version", "canonical_name", "node_version", "relation", "depth"
)


def transform_dependencies(body: dict, *, root_name: str, root_version: str) -> pd.DataFrame:
    """Return one row per resolved package version with shortest graph depth.

    Depth is calculated from graph edges (not inferred from the API's DIRECT/INDIRECT label).
    Multiple paths to a node use the shortest path. Root/self is not stored in resolved_node.
    """
    graph = DepsDevGraph.model_validate(body)
    if graph.error:
        raise ValueError(f"deps.dev returned a graph-level error: {graph.error}")
    if graph.nodes[0].versionKey.system != "PYPI":
        raise ValueError("deps.dev root system is not PYPI")
    if canonicalize_name(graph.nodes[0].versionKey.name) != canonicalize_name(root_name):
        raise ValueError("deps.dev root package does not match requested package")
    if graph.nodes[0].versionKey.version != root_version:
        raise ValueError("deps.dev root version does not match requested version")

    adjacency: dict[int, list[int]] = {i: [] for i in range(len(graph.nodes))}
    for edge in graph.edges:
        if edge.fromNode >= len(graph.nodes) or edge.toNode >= len(graph.nodes):
            raise ValueError("deps.dev edge references a node outside nodes[]")
        adjacency[edge.fromNode].append(edge.toNode)

    distances = {0: 0}
    queue = deque([0])
    while queue:
        current = queue.popleft()
        for child in adjacency[current]:
            candidate = distances[current] + 1
            if child not in distances or candidate < distances[child]:
                distances[child] = candidate
                queue.append(child)

    # A package/version can occur at multiple node indexes; retain its shortest depth.
    unique: dict[tuple[str, str], dict] = {}
    for index, node in enumerate(graph.nodes[1:], start=1):
        if index not in distances or node.bundled:
            continue
        key = (canonicalize_name(node.versionKey.name), node.versionKey.version)
        depth = distances[index]
        if depth < 1:
            continue
        row = {
            "root_canonical_name": canonicalize_name(root_name),
            "root_version": root_version,
            "canonical_name": key[0],
            "node_version": key[1],
            "relation": "DIRECT" if depth == 1 else "INDIRECT",
            "depth": depth,
        }
        previous = unique.get(key)
        if previous is None or depth < previous["depth"]:
            unique[key] = row
        elif depth == previous["depth"] and depth == 1:
            previous["relation"] = "DIRECT"

    rows = sorted(unique.values(), key=lambda row: (row["depth"], row["canonical_name"], row["node_version"]))
    return pd.DataFrame(rows, columns=RESOLVED_NODE_COLUMNS)
