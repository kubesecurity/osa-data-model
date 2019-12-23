#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Create edges between the nodes."""
import logging

import daiquiri

from gremlin_connect.gremlin_adapter import GremlinAdapter

daiquiri.setup(level=logging.DEBUG)
_logr = daiquiri.getLogger(__name__)


class CreateEdges:
    """Contains all the wrappers to create edges between two nodes."""

    gremlin_adapter = GremlinAdapter()

    @classmethod
    def execute_query(cls, query):
        """Execute the gremlin query, but modify it by adding a commit and a .next()."""
        # This exists so query can be pre-processed as required.
        query += "g.tx().commit();"
        return cls.gremlin_adapter.execute_query(query)

    @classmethod
    def create_dependency_version_edge(cls, dependency_node, version_node):
        """Link a dependency node to a dependency_version node."""
        query = (
            "from = g.V().has('vertex_label', 'dependency').has('dependency_name', '{}').next();"
            "to = g.V().has('vertex_label', 'dependency_version').has('dependency_name', "
            "'{}').toList();"
            "to.each {{toNode ->"
            "   from.addEdge('has_version', toNode).property('edge_label', 'has_version');"
            "}};"
        ).format(dependency_node["dependency_name"], version_node["dependency_name"])
        return cls.execute_query(query)

    @classmethod
    def create_probable_reported_cve_link(cls, probable, reported_cve):
        """Link a probable vulnerability node to an reported CVE."""
        query = (
            "to = g.V().has('vertex_label', 'reported_cve').has('CVE_ID', '{}').next();"
            "from = g.V().has('vertex_label', 'probable_vulnerability').has('probable_vuln_id', "
            "'{}').next();"
            "from.addEdge('verified_to_cve', to).property('edge_label', 'verified_to_cve');"
        ).format(reported_cve["CVE_ID"], probable["probable_vuln_id"])
        return cls.execute_query(query)

    @classmethod
    def create_prob_vuln_sec_event_link(cls, prob, sec_event):
        """Link a probable vulnerability node to an event node."""
        query = (
            "from = g.V().has('vertex_label','probable_vulnerability').has('probable_vuln_id', "
            "'{}').next(); to = g.V().has('vertex_label', 'security_event').has('event_id', "
            "'{}').next();"
            "from.addEdge('triaged_to', to).property('edge_label', 'triaged_to');"
        ).format(prob["probable_vuln_id"], sec_event["event_id"])
        return cls.execute_query(query)

    @classmethod
    def create_dependency_dependency_links(cls, dep1, dep2):
        """Link dependencies to create the network of transitives, starting at this node."""
        query = (
            "from = g.V().has('vertex_label', 'dependency').has('dependency_name', "
            "'{}').next(); to = g.V().has('vertex_label', 'dependency').has('dependency_name', "
            "'{}').next();"
            "from.addEdge('depends_on', to).property('edge_label', 'depends_on');"
        ).format(dep1["dependency_name"], dep2["dependency_name"])
        return cls.execute_query(query)

    @classmethod
    def create_reported_cve_dependency_version_link(cls, cve, version_node):
        """Create an edge between reported CVE node and version node."""
        query = (
            "from = g.V().has('vertex_label', 'reported_cve').has('CVE_ID', '{}').next(); to "
            "= g.V().has('vertex_label', 'dependency_version').has('dependency_name', "
            "'{}').has('version', '{}').next();"
            "from.addEdge('affects', to).property('edge_label', 'affects');"
        ).format(
            cve["CVE_ID"], version_node["dependency_name"], version_node["version"]
        )
        return cls.execute_query(query)
