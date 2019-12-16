#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Create the nodes in the graph."""
from typing import Dict

from graph_create.types import EventType, Severity, FeedBackType
from gremlin_connect.gremlin_adapter import GremlinAdapter


class CreateNodesInGraph:
    """Create all the nodes in the graph."""

    gremlin_adapter = GremlinAdapter()

    @classmethod
    def create_probable_vuln_node(cls, prob_cve_id: str) -> Dict:
        """Create a new probable vulnerability node."""
        query = cls.label_builder("probable_vulnerability") + cls.property_builder(
            vertex_label="probable_vulnerability", probable_vuln_id=prob_cve_id
        )
        return cls.execute_query(query)

    @classmethod
    def create_dependency_node(cls, dependency_name: str, dependency_path: str) -> Dict:
        """Create a new dependency node."""
        query = cls.label_builder("dependency") + cls.property_builder(
            vertex_label="dependency",
            dependency_name=dependency_name,
            dependency_path=dependency_path,
        )
        return cls.execute_query(query)

    @classmethod
    def create_reported_cve_node(
        cls, cve_id: str, cvss: float, severity: Severity
    ) -> Dict:
        """Create a new reported CVE node."""
        query = cls.label_builder("reported_cve") + cls.property_builder(
            vertex_label="reported_cve", CVE_ID=cve_id, CVSS=cvss, severity=severity
        )
        return cls.execute_query(query)

    @classmethod
    def create_feedback_node(
        cls,
        body: str,
        author: str,
        event_id: str,
        event_type: EventType,
        feedback_type: FeedBackType,
    ) -> Dict:
        """Create a new feedback node."""
        query = cls.label_builder("feedback") + cls.property_builder(
            event_type=event_type, author=author, body=body, feedback_type=feedback_type
        )
        # TODO: Join to the corresponding event node.
        return cls.execute_query(query)

    @classmethod
    def create_security_event_node(
        cls, event_type: EventType, body: str, title: str, event_id: str
    ) -> Dict:
        """Create a new security event node."""
        query = cls.label_builder("security_event") + cls.property_builder(
            event_type=event_type,
            body=body,
            title=title,
            event_id=event_id,
            vertex_label="security_event",
        )
        return cls.execute_query(query)

    @classmethod
    def create_dependency_version_node(cls, version: str, dep_name: str) -> Dict:
        """Create a new dependency version node."""
        # TODO: Don't create if a dependency node is not present.
        query = cls.label_builder("dependency_version") + cls.property_builder(
            version=version, dependency_name=dep_name, vertex_label="dependency_version"
        )
        # TODO: Join to dependency node.
        return cls.execute_query(query)

    @classmethod
    def create_ecosystem_node(cls, ecosystem_name: str) -> Dict:
        """Create a new ecosystem node."""
        query = cls.label_builder("ecosystem") + cls.property_builder(
            ecosystem=ecosystem_name, vertex_label="ecosystem"
        )
        return cls.execute_query(query)

    @classmethod
    def execute_query(cls, query) -> Dict:
        """Execute the gremlin query, but modify it by adding a commit and a .next()."""
        query += ".next();"
        return cls.gremlin_adapter.execute_query(query)

    @staticmethod
    def label_builder(label_name: str) -> str:
        """
        Generate the label name for a node.

        Args:
            label_name: The label name to assign to this node.

        Returns:
            Part of the gremlin query g.V(label_name).

        """
        return "g.addV('{}')".format(label_name)

    @staticmethod
    def property_builder(**kwargs) -> str:
        """Use a variable size list of properties to get back a .property() querystring."""
        prop_str = ""
        for p, val in kwargs.items():
            prop_str = "{}.property('{}', '{}')".format(prop_str, str(p), str(val))
        return prop_str
