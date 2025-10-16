
def test_ad__lookup_using_domain_controller_with_no_global_catalog():
    """
    :title: Lookup using a domain controller with no global catalog
    :setup:
        1. Create user ‘user1’
        2. Configure and start SSSD
        3. Block traffic to the domain controller containing the global catalog
    :steps:
        1. Lookup ‘user1’
    :expectedresults:
        1. User found
    :customerscenario: False
    """

def test_ad__user_login_using_another_site():
    """
    :title: User login when the computer resides in another AD site.
    :setup:
        1. Create user ‘user-1’
        2. Create AD site ‘Site-1`
        3. Move second domain controller into ‘site-1’
        4. Move client computer object into ‘site-1’
        5. Start SSSD
    :steps:
        1. Login as user
    :expectedresults:
        1. Login is successful
    :customerscenario: False
    """

def test_ad__user_login_as_using_an_alternative_upn():
    """
    :title: User login using an alternative UPN
    :setup:
        1. Add another UPN suffix to the domain
        2. Create user ‘user-1’ and add alternative UPN
        3. Start SSSD
    :steps:
        1. Login as user using alternative UPN
    :expectedresults:
        1. Login is successful
    :customerscenario: False
    """
def test_ad__user_login_with_ldap_mapping_is_false():
    """
    :title: User login with id mapping disabled
    :setup:
        1. Create user ‘user-1’ with posix attributes, uidNumber, gidNUmber, unixshell
        2. start SSSD
    :steps:
        1. Lookup user
        2. Configure SSSD with ‘ldap_id_mapping = false’, clear cache and restart SSSD
        3. Lookup user
    :expectedresults:
        1. User is found and only the shell matches
        2. SSSD is configured, cached cleared and restarted
        3. User is found and user attributes match posix attributes
    :customerscenario: False
    """

def test_ad__user_login_configured_using_ldap_krb5_providers():
    """
    :title: User login when SSSD is configured using ldap and krb5 id, auth providers
    :setup:
        1. Configure SSSD with ‘id_provider = ldap’ and ‘auth_provider = krb5’
        2. Start SSSD
    :steps:
        1. Login as user
    :expectedresults:
        1. Login successful
    :customerscenario: False
    """


def test_ad__lookup_domain_users_in_global_and_universal_groups():
    """
    :title: Lookup root, child and tree domain users in global and universal groups
    :description: This test is parametrized and will re-run iterating through root, child and tree domains and domain levels.
    :setup:
        1. Create user ‘user1’ in (root|child|tree) domain
        2. Create group (global|universal) ‘group1’, make the user a member
        4. Start SSSD
    :steps:
        1. Lookup user
        2. Lookup group
    :expectedresults:
        1. User is found and is a member of the group
        2. Group is found and user is a member of the group
    :customerscenario: False
    """

def test_ad__lookup_domain_users_in_local_group():
    """
    :title: Lookup root, child and tree domain users in local group
    :description: The user in a local group will only be found for the root domain. This test is parametrized and will re-run      iterating through root, child and tree domain with different assertions for each run.
    :setup:
        1. Create user ‘user1’ in (root|child|tree) domain
        2. Create local group ‘group1’ in (root|child|tree) domains, and add the user a member
        4. Start SSSD
    :steps:
        1. Lookup user
        2. Lookup group
    :expectedresults:
        1. In root domain user is found and is a member of the group
        2. In the root domain group is found and user is a member of the group
    :customerscenario: False
    """
def test_ad__lookup_user_in_nested_groups():
    """
    :title: Lookup users in nested groups
    :setup:
        1. Create users ‘user1’ and ‘user2’
        2. Create groups ‘group’ and ‘nested_group’
        3. Add ‘nested_group’ and ‘user1’ as a member to ‘group’
        4. Add ‘user2’ as a member to ‘nested_group’
        5. Start SSSD
    :steps:
        1. Lookup group
        2. Lookup nested group
    :expectedresults:
        1. Group is found and both users are members
        2. Group is found and ‘user2’ is a member
    :customerscenario: False
    """
def test_ad__user_can_access_cifs_share():
    """
    :title: User can access CIFS share using a password or kerberos credentials
    :setup:
        1. Create user ‘user1’
        2. Create CIFS share and grant ‘user1’ read/write access
        3. Start SSSD
    :steps:
        1. Login as user and maintain an open session
        2. Mount CIFS share using password | krb authentication
        3. Create directory and file on the share
    :expectedresults:
        1. Login is successful
        2. Share is mounted
        3. Directory and file are created
    :customerscenario: False
    """

def test_ad__child_or_tree_domain_user_login():
    """
    :title: User from child or tree domain can login
    :setup:
        1. Create user ‘user1’ in domain(child|tree)
        2. Start SSSD
    :steps:
        1. Login as child or tree domain user
    :expectedresults:
        1. Login is successful
    :customerscenario: False
    """
def test_ad__resolve_domains_by_order_looking_up_shortnames():
    """
    :title: Lookup user
    :setup:
        1. Create user ‘user1’ in root, child and tree domains
        2. Configure SSSD with,
              ‘domain_resolution_order = root, child, tree’
              ‘use_fully_qualified_names = false’
        3. Start SSSD
    :steps:
        1. Lookup users by fully qualified name
        2. Lookup ‘user1’ by shortname
    :expectedresults:
        1. All users found
        2. User is found and is from the root domain
    :customerscenario: False
    """

