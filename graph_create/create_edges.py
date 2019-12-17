#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Create edges between the nodes."""
import logging

import daiquiri

from gremlin_connect.gremlin_adapter import GremlinAdapter

daiquiri.setup(level=logging.INFO)
_logr = daiquiri.getLogger(__name__)


class CreateEdges:
    """Contains all the wrappers to create edges between two nodes."""

    gremlin_adapter = GremlinAdapter()

    @classmethod
    def create_dependency_version_edge(cls, dependency_node, version_node):
        """Link a dependency node to a dependency_version node."""
        query = (
            "from = g.V().has('vertex_label', 'dependency').has('dependency_name', {}).next();"
            "to = g.V().has('vertex_label', 'dependency_version').has('dependency_name', "
            "'{}').toList();"
            "to.each {toNode ->"
            "   g.V(toNode).as('toNode').V(from).addE('has_version').property('edge_label', "
            "'has_version').to('toNode').toList();"
            "}"
        ).format(dependency_node["dependecy_name"], version_node["dependency_name"])
        return cls.gremlin_adapter.execute_query(query)

    @classmethod
    def create_probable_identified_cve_link(cls, probable, identified):
        """Link a probable vulnerability node to an identified CVE."""
        query = (
            "to = g.V().has('vertex_label', 'identified_cve').has('cve_id', '{}').next();"
            "from = g.V().has('vertex_label', 'probable_vulnerability').has('prob_vuln_id', "
            "'{}').next();"
            "g.V(to).as('toNode').V(from).addE('verified_to_cve').property('edge_label', "
            "'verified_to_cve').to('toNode').toList();"
        ).format(identified["CVE_ID"], probable["probable_vuln_id"])
        return cls.gremlin_adapter.execute_query(query)

    @classmethod
    def create_prob_vuln_sec_event_link(cls):
        """Link a probable vulnerability node to an event node."""
        pass

    @classmethod
    def create_dependency_transitive_links(cls):
        """Create a random network of transitive dependencies, starting at this node."""
        pass

    @classmethod
    def create_identified_cve_dependency_version_node(cls):
        """Create an edge between identified CVE node and version node."""
        pass
