#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Pre-process the sample data and call node insertion methods."""
import os

from config import DATA_DIR
from graph_create.create_edges import CreateEdges
from graph_create.create_nodes import CreateNodesInGraph
from utils import decode_json


def create_nodes(*args, **kwargs):
    """Create nodes to the order of magnitude specified by kwargs.magnitude."""
    if len(args) > 0 or "mul_fact" in kwargs:
        if len(args) != 0:
            suffix = args[0]
        else:
            suffix = kwargs["mul_fact"]
        index = suffix
        suffix = str(suffix)
        # First create the dependency node.
        f = open(os.path.join(DATA_DIR, "dependency.json"))
        dependency_node = decode_json(f.read())
        dependency_node["dependency_name"] += "_" + suffix
        dependency_node["dependency_path"] += "_" + suffix
        CreateNodesInGraph.create_dependency_node(
            dependency_name=dependency_node["dependency_name"],
            dependency_path=dependency_node["dependency_path"],
        )
        # Now create two versions for the node.
        f = open(os.path.join(DATA_DIR, "dependency_version.json"))
        dependency_version = decode_json(f.read())
        # Modify this if the number of versions of a dependency needs to be changed.
        for i in range(0, 2):
            CreateNodesInGraph.create_dependency_version_node(
                version="{}_{}".format(dependency_version["version"], str(i)),
                dep_name="{}_{}".format(dependency_version["dependency_name"], suffix),
            )
        # Since this iterates internally, passing one is enough.
        dependency_version["dependency_name"] = "{}_{}".format(
            dependency_version["dependency_name"], suffix
        )
        CreateEdges.create_dependency_version_edge(dependency_node, dependency_version)
        # Create a security event node. This will be equal to the number of dependency nodes.
        f = open(os.path.join(DATA_DIR, "security_event.json"))
        security_event = decode_json(f.read())
        CreateNodesInGraph.create_security_event_node(
            event_id=security_event["event_id"],
            event_type=security_event["event_type"],
            body=security_event["body"],
            title=security_event["title"],
        )
        probable_vuln = None
        # Create a probable vulnerability node. This will be half of all security event nodes.
        if index % 2 == 0:
            f = open(os.path.join(DATA_DIR, "probable_vulnerability.json"))
            probable_vuln = decode_json(f.read())
            CreateNodesInGraph.create_probable_vuln_node(
                probable_vuln["probable_vuln_id"]
            )
            # Link this probable vulnerability to the security event node.
            CreateEdges.create_prob_vuln_sec_event_link(probable_vuln, security_event)
        # Create an identified CVE node for every alternate probable CVE node. This means there'll
        # be half the number of identified CVE nodes as probale CVE nodes.
        if index % 4 == 0:
            f = open(os.path.join(DATA_DIR, "identified_cve.json"))
            identified_cve = decode_json(f.read())
            CreateNodesInGraph.create_reported_cve_node(
                cve_id=identified_cve["CVE_ID"],
                cvss=identified_cve["CVSS"],
                severity=identified_cve["severity"],
            )
            # Link this identified CVE node to the dependency node with version suffix {1}.
            dependency_version["version"] = "{}_{}".format(
                dependency_version["version"], str(1)
            )
            CreateEdges.create_reported_cve_dependency_version_link(
                identified_cve, dependency_version
            )
            # Also link it to the probable CVE node.
            if probable_vuln is not None:
                CreateEdges.create_probable_reported_cve_link(
                    probable_vuln, identified_cve
                )
