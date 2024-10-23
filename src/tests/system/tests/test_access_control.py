"""
SSSD Access Control Test Cases

:requirement: Access Control
"""

from __future__ import annotations

import pytest
from sssd_test_framework.topology import KnownTopology


@pytest.mark.topology(KnownTopology.AnyProvider)
@pytest.mark.importance("critical")
def test_access_control__disabled_user_cannot_login():
    """ TODO: add enable/disable functionality to user classes """


@pytest.mark.topology(KnownTopology.AnyProvider)
@pytest.mark.importance("critical")
def test_access_control__simple_filter_users():
    """ TODO: """


@pytest.mark.topology(KnownTopology.AnyProvider)
@pytest.mark.importance("critical")
def test_access_control__simple_filter_groups():
    """ TODO: """


@pytest.mark.topology(KnownTopology.AnyProvider)
@pytest.mark.importance("critical")
def test_access_control__simple_filter_nested_groups():
    """ TODO: group1 contains group2 as a member and users in group2 are evaluated properly"""


@pytest.mark.topology(KnownTopology.AnyProvider)
@pytest.mark.parametrize("users", [("user1 user2", False), ("user1, user2", True)])
@pytest.mark.importance("medium")
def test_access_control__simple_filter_valid_strings_in_users_field_work(users: str):
    """ TODO: possible string permutations work as expected """


@pytest.mark.topology(KnownTopology.AnyProvider)
@pytest.mark.importance("critical")
def test_access_control__simple_filter_implicitly_deny_users_and_groups():
    """ TODO: """


@pytest.mark.topology(KnownTopology.AnyProvider)
@pytest.mark.parametrize("groups", [])
@pytest.mark.importance("medium")
def test_access_control__simple_filter_valid_strings_in_group_field_work(groups: str):
    """ TODO: """


@pytest.mark.topology(KnownTopology.AnyProvider)
@pytest.mark.importance("critical")
@pytest.mark.parametrize("attr", [("samAccountName", "ad"), ("cn", "ldap"), ("dn", "")])
def test_access_control__ldap_filter_searches_a_single_attribute(attr: tuple):
    """ TODO: if provider is AD, configure config and use ad_filter, else configure ldap_filter """


@pytest.mark.topology(KnownTopology.AnyProvider)
@pytest.mark.importance("critical")
def test_access_control__ldap_filter_query_contains_conditions_and_or():
    """ TODO: """


@pytest.mark.topology(KnownTopology.AnyProvider)
@pytest.mark.importance("medium")
def test_access_control__ldap_filter_query_contains_arithmetic_operators():
    """ TODO: """
