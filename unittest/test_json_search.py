"""Functional and access-control tests for :mod:`recursive_json_search`."""

import unittest

from policy import POLICY
from recursive_json_search import json_search
from test_data import data, key1


class json_search_test(unittest.TestCase):
    """Verify recursive matches and field-level role permissions."""

    def test_search_found(self):
        """Find the sample issue summary for a permitted viewer."""
        self.assertEqual(
            json_search(key1, data, role="viewer"),
            ["Network Device 10.10.20.82 Is Unreachable From Controller"],
        )

    def test_search_not_found(self):
        """Return an empty list when the requested key is absent."""
        self.assertEqual(json_search("missingKey", data, role="viewer"), [])

    def test_is_a_list(self):
        """Return matches as a list, including when there is one match."""
        self.assertIsInstance(json_search(key1, data, role="viewer"), list)

    def test_search_aggregates_nested_lists(self):
        """Keep matches from every dictionary and list branch."""
        nested = {"items": [{"target": 1}, {"inner": [{"target": 2}]}]}
        self.assertEqual(json_search("target", nested), [1, 2])

    def test_wrong_role_cannot_read_secret(self):
        """Deny a viewer access to the deeply nested SNMP credential."""
        self.assertEqual(json_search("apiKey", data, role="viewer"), [])

    def test_operator_cannot_read_apiKey(self):
        """Deny an operator access to the admin-only credential."""
        self.assertEqual(json_search("apiKey", data, role="operator"), [])

    def test_admin_can_read_apiKey(self):
        """Allow an admin to read the credential at its nested location."""
        self.assertEqual(
            json_search("apiKey", data, role="admin"),
            ["SNMP-COMMUNITY-STRING-7f3a9c"],
        )

    def test_viewer_cannot_read_managementIpAddress(self):
        """Deny a viewer access to the management IP address."""
        self.assertEqual(
            json_search("managementIpAddress", data, role="viewer"), []
        )

    def test_operator_can_read_managementIpAddress(self):
        """Allow an operator to read the management IP address."""
        self.assertEqual(
            json_search("managementIpAddress", data, role="operator"),
            ["10.10.20.21"],
        )

    def test_no_role_provided_is_denied_for_restricted_field(self):
        """Treat an omitted role as unauthorized for policy-controlled keys."""
        for restricted_key in POLICY:
            with self.subTest(key=restricted_key):
                self.assertEqual(json_search(restricted_key, data), [])

    def test_invalid_role_is_denied_for_restricted_field(self):
        """Deny unknown roles while leaving unrestricted keys searchable."""
        self.assertEqual(json_search("apiKey", data, role="intern"), [])
        self.assertEqual(json_search("status", data, role="intern"), ["NEW"])

    def test_issue_summary_is_available_to_all_policy_roles(self):
        """Allow every role named by policy to search issue summaries."""
        for role in POLICY["issueSummary"]:
            with self.subTest(role=role):
                self.assertEqual(len(json_search(key1, data, role=role)), 1)

    def test_special_key_is_searchable_without_role(self):
        """Allow an unlisted key when no role is supplied."""
        self.assertEqual(json_search("status", data), ["NEW"])


if __name__ == "__main__":
    unittest.main()
