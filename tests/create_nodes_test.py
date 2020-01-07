#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for graph creation."""
import pytest
from graph_create.create_nodes import CreateNodesInGraph
from tests.conftest import gremlin_post
import requests
import json


def test_label_builder():
    """Test if the labels for nodes are properly built."""
    assert CreateNodesInGraph.label_builder("test") == "g.addV('test')"


def test_property_builder():
    """Test if the .property() portion of query is built properly."""
    assert (
        CreateNodesInGraph.property_builder(testkey1="testval1", testkey2="testval2")
        == ".property('testkey1', 'testval1').property('testkey2', 'testval2')"
    )
    # Check if number/boolean properties are converted to strings.
    assert (
        CreateNodesInGraph.property_builder(testkey1=1, testkey2=False)
        == ".property('testkey1', '1').property('testkey2', 'False')"
    )


def test_create_dependency_version_node(monkeypatch):
    """Test creation query of dependency-version node."""
    monkeypatch.setattr(requests, "post", gremlin_post)
    assert (
        CreateNodesInGraph.create_dependency_version_node(
            "1.0.0.alpha-v1", "github.com/kubernetes/apimachineary"
        )["executed"]
        == "g.addV('dependency_version').property('version', '1.0.0.alpha-v1').property("
        "'dependency_name', 'github.com/kubernetes/apimachineary').property('vertex_label', "
        "'dependency_version').next();"
    )
