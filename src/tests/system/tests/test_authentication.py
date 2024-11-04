"""
SSSD Authentication Test Cases

:requirement: authentication
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.importance("critical")
def test_authentication__password_change():
    # test_ldap__password_change_using_ppolicy covers LDAP
    pass


@pytest.mark.importance("critical")
def test_authentication__password_change_new_passwords_do_not_match():
    # test_ldap__password_change_new_passwords_do_not_match_using_ppolicy covers LDAP
    pass


@pytest.mark.importance("critical")
def test_authentication__user_is_locked_after_failed_login_attempts():
    # framework, add functionality to set failed login attempts for provider roles i.e. provider.policy(lockout = n)
    pass


@pytest.mark.importance("critical")
def test_authentication__user_password_meets_complexity_requirements():
    # framework, add functionality to set the password policy i.e. provider.policy(complex=True | None = False)
    pass


@pytest.mark.parametrize(
    "home_key",
    ["user", "uid", "fqn", "domain", "first_char", "upn", "default", "lowercase", "substring", "literal%"],
)
@pytest.mark.importance("medium")
def test_authentication__with_overriding_home_directory(home_key: str):
    """
    :title: Override the user's home directory
    :description:
        For simplicity, the home directory is set to '/home/user1' because some providers homedirs are different.
    :setup:
        1. Create user and set home directory to '/home/user1'
        2. Configure SSSD with 'override_homedir' home_key value and restart SSSD
        3. Get entry for 'user1'
    :steps:
        1. Login as 'user1' and check working directory
    :expectedresults:
        1. Login is successful and working directory matches the expected value
    :customerscenario: False
    """
    pass


@pytest.mark.parametrize("config", [
    ["default_shell", "/bin/bash"],
    ["shell_fallback", "/bin/zsh"],
    ["vetoed_shell", "/bin/bash"],
    ["shell_fallback", "/bin/bash"]
])
@pytest.mark.importance("low")
def test_authentication__homedir_and_shell_parameters(config: list[str]):
    pass


def test_authentication__user_can_login_using_ssh_keys_stored_in_the_directory():
    # add functionality to authentication, i.e. client.auth.ssh.key("$key_path")
    # generic provider may require some framework changes, ipa provider is ready now
    pass


def test_authentication__different_auth_provider():
    # create sssd.common.config with id using local users and krb for auth
    pass


def test_authentication__multiple_domains():
    # create sssd.common.config with two domains
    # i.e. ad.test and ipa.test, both user@ad.test and user@ipa.test work
    pass


@pytest.mark.parametrize("username", [
    ("user123", True),
    ("user%123", False),
    ("user_123", True),
    ("user\\123", True),
    ("user-123", True),
    ("user!123", False)
    # Not the entire list
])
def test_authentication__valid_and_invalid_usernames(username: str):
    # all character combinations work as expected, case-sensitive checking
    # includes intg/test_ldap.py - tset_regression_ticket2163 , "user\\123"
    pass


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_authentication__with_default_settings(
    client: Client, provider: GenericProvider, method: str, sssd_service_user: str
):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create user
        2. Start SSSD
    :steps:
        1. Authenticate user with correct password
        2. Authenticate user with incorrect password
    :expectedresults:
        1. Authentication is successful
        2. Authentication is unsuccessful
    :customerscenario: False
    """
    provider.user("user1").add(password="Secret123")

    client.sssd.start(service_user=sssd_service_user)

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User failed login!"
    assert not client.auth.parametrize(method).password(
        "user1", "NOTSecret123"
    ), "User logged in with an invalid password!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_authentication__default_settings_when_the_provider_is_offline(
    client: Client, provider: GenericProvider, method: str, sssd_service_user: str
):
    """
    :title: Authenticate with default settings when the provider is offline
    :setup:
        1. Create user
        2. Configure SSSD with "cache_credentials = true" and "krb5_store_password_if_offline = true" and
        "offline_credentials_expiration = 0"
        3 Start SSSD
    :steps:
        1. Authenticate user with correct password
        2. Offline user authentication with correct password
        3. Offline user authentication with incorrect password
    :expectedresults:
        1. User authentication is successful
        2. User authentication is successful
        3. User authentication is unsuccessful
    :customerscenario: False
    """
    user = "user1"
    correct = "Secret123"
    wrong = "Wrong123"
    provider.user(user).add(password=correct)

    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.domain["krb5_store_password_if_offline"] = "True"
    client.sssd.pam["offline_credentials_expiration"] = "0"
    client.sssd.start(service_user=sssd_service_user)

    assert client.auth.parametrize(method).password(user, correct), "User failed login!"

    client.firewall.outbound.reject_host(provider)

    # There might be active connections that are not terminated by creating firewall rule.
    # We need to terminate it by forcing SSSD offline.
    client.sssd.bring_offline()

    assert client.auth.parametrize(method).password(user, correct), "User failed login!"
    assert not client.auth.parametrize(method).password(user, wrong), "User logged in with an incorrect password!"


@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(gh=7174)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_authentication__using_the_users_email_address(client: Client, ad: AD, method: str, sssd_service_user: str):
    """
    :title: Login using the user's email address
    :description:
        Testing the feature to login using an email address instead of the userid. The username used,
        must match one of the user's LDAP attribute values, "EmailAddress". The login should be
        case-insensitive and permit special characters.
    :setup:
        1. Add AD users with different email addresses
        2. Start SSSD
    :steps:
        1. Authenticate users using their email address and in different cases
    :expectedresults:
        1. Authentication is successful using the email address and is case-insensitive
    :customerscenario: False
    """
    ad.user("user-1").add(password="Secret123", email=f"user-1@{ad.host.domain}")
    ad.user("user-2").add(password="Secret123", email="user-2@alias-domain.com")
    ad.user("user_3").add(password="Secret123", email="user_3@alias-domain.com")

    client.sssd.start(service_user=sssd_service_user)

    assert client.auth.parametrize(method).password(
        f"user-1@{ad.host.domain}", "Secret123"
    ), f"User user-1@{ad.host.domain} failed login!"
    assert client.auth.parametrize(method).password(
        "user-2@alias-domain.com", "Secret123"
    ), "User user-2@alias-domain.com failed login!"
    assert client.auth.parametrize(method).password(
        "uSEr_3@alias-dOMain.com", "Secret123"
    ), "User uSEr_3@alias-dOMain.com failed login!"
