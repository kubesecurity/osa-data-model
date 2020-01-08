#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Common test configurations."""
import json


class MockResponse:
    """Class that contains a .json() property similar to response from requests library."""

    def __init__(self, query=""):
        """Initiate a mocked response, which echoes the query that it got back."""
        self._query = query

    def json(self):
        """Mock the json method of the requests.Response class."""
        return {"executed": self._query}


def gremlin_post(*args, **kwargs):
    """Return a mock gremlin server instance."""
    return MockResponse(json.loads(kwargs["data"])["gremlin"])
