"""
Active Directory Provider SSSD Tests

:requirement: AD:

"""

from __future__ import annotations

import pytest

"""
TODO:
* multidomain topology - child, tree domain

"""


@pytest.mark.importance("high")
@pytest.mark.parametrize("domain", ["child", "tree"])
def test_identity_lookup_trusted_ad_users(domain: str):
    """ :TODO: multiple domain infrastructure """
    # parent users in child groups can be searched


@pytest.mark.importance("high")
def test_identity_lookup_trusted_ad_groups():
    """ :TODO: multiple domain infrastructure """

