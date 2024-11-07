"""
SSSD Access Control Test Cases

:requirement: access control
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_access_control__disabled_user_cannot_login():
    # sssd_framework: add enable/disable user account functionality to user classes
    pass


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_access_control__simple_filter_users():
    pass


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_access_control__simple_filter_groups():
    pass


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_access_control__simple_filter_nested_groups():
    pass


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("users", [
    ("user1 user2", False),
    ("user1, user2", True),
    ("user1:user1", False),
])
def test_access_control__simple_filter_valid_strings_in_users_field_work(users: str):
    pass


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("groups", [])
def test_access_control__simple_filter_valid_strings_in_group_field_work(groups: str):
    pass


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_access_control__simple_filter_implicitly_deny_users_and_groups():
    pass


@pytest.mark.topology(KnownTopology.LDAP, KnownTopology.AD)
@pytest.mark.parametrize("attr", [("samAccountName", "ad"), ("cn", "ldap"), ("dn", "")])
def test_access_control__ldap_filter_searches_a_single_attribute(attr: tuple):
    # if provider is AD, configure config and use ad_filter, else configure ldap_filter
    pass


@pytest.mark.topology(KnownTopology.LDAP, KnownTopology.AD)
def test_access_control__ldap_filter_query_contains_conditions_and_or():
    pass


@pytest.mark.topology(KnownTopology.LDAP, KnownTopology.AD)
def test_access_control__ldap_filter_query_contains_arithmetic_operators():
    pass
