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
    def create_probable_reported_cve_link(cls, probable, reported_cve):
        """Link a probable vulnerability node to an reported CVE."""
        query = (
            "to = g.V().has('vertex_label', 'reported_cve').has('cve_id', '{}').next();"
            "from = g.V().has('vertex_label', 'probable_vulnerability').has('prob_vuln_id', "
            "'{}').next();"
            "g.V(to).as('toNode').V(from).addE('verified_to_cve').property('edge_label', "
            "'verified_to_cve').to('toNode').toList();"
        ).format(reported_cve["CVE_ID"], probable["probable_vuln_id"])
        return cls.gremlin_adapter.execute_query(query)

    @classmethod
    def create_prob_vuln_sec_event_link(cls, prob, sec_event):
        """Link a probable vulnerability node to an event node."""
        query = (
            "from = g.V().has('vertex_label','probable_vulnerability').has('prob_vuln_id', "
            "'{}').next(); to = g.V().has('vertex_label', 'security_event').has('event_id', "
            "'{}').next();"
            "g.V(to).as('to').V(to).addE('triaged_to').property('edge_label', 'triaged_to').to("
            "'to').toList();"
        ).format(prob["prob_vuln_id"], sec_event["event_id"])
        return cls.gremlin_adapter.execute_query(query)

    @classmethod
    def create_dependency_dependency_links(cls, dep1, dep2):
        """Link dependencies to create the network of transitives, starting at this node."""
        query = (
            "from = g.V().has('vertex_label', 'dependency').has('dependency_name', "
            "'{}').next(); to = g.V().has('vertex_label', 'dependency').has('dependency_name', "
            "'{}').next();"
            "g.V(to).as('to').V(to).addE('depends_on').property('edge_label', 'depends_on').to("
            "'to').toList();"
        ).format(dep1["dependency_name"], dep2["dependency_name"])
        return cls.gremlin_adapter.execute_query(query)

    @classmethod
    def create_reported_cve_dependency_version_link(cls, cve, version_node):
        """Create an edge between reported CVE node and version node."""
        query = (
            "from = g.V().has('vertex_label', 'reported_cve').has('CVE_ID', '{}').next(); to "
            "= g.V().has('vertex_label', 'dependency_version').has('dependency_name', "
            "'{}').has('version', '{}').next();"
            "g.V(to).as('to').V(to).addE('affects').property('edge_label', 'affects').to("
            "'to').toList();"
        ).format(
            cve["CVE_ID"], version_node["dependency_name"], version_node["version"]
        )
        return cls.gremlin_adapter.execute_query(query)
