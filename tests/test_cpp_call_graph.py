"""Focused C++ call-graph coverage."""

from pathlib import Path

import pytest

from tldr.cross_file_calls import (
    TREE_SITTER_CPP_AVAILABLE,
    build_function_index,
    build_project_call_graph,
    scan_project,
)


pytestmark = pytest.mark.skipif(
    not TREE_SITTER_CPP_AVAILABLE,
    reason="tree-sitter-cpp is not installed",
)


def test_cpp_scan_includes_standard_headers(tmp_path: Path):
    header = tmp_path / "helper.h"
    header.write_text("void Helper();\n")

    assert str(header) in scan_project(tmp_path, language="cpp")


def test_cpp_function_index_includes_qualified_and_simple_names(tmp_path: Path):
    source = tmp_path / "widget.cpp"
    source.write_text("void Widget::Tick() {}\n")

    index = build_function_index(tmp_path, language="cpp")

    assert ("widget", "Widget::Tick") in index
    assert ("widget", "Tick") in index


def test_cpp_call_graph_wires_intra_and_cross_file_calls(tmp_path: Path):
    (tmp_path / "helper.cpp").write_text("void Helper::Run() {}\n")
    (tmp_path / "widget.cpp").write_text(
        "void Local() {}\n" "void Widget::Tick() { Local(); Helper::Run(); }\n"
    )

    graph = build_project_call_graph(tmp_path, language="cpp")

    assert ("widget.cpp", "Widget::Tick", "widget.cpp", "Local") in graph.edges
    assert ("widget.cpp", "Widget::Tick", "helper.cpp", "Helper::Run") in graph.edges
