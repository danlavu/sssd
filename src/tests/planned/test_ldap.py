
def test_ldap__enumeration_remove_user():
    """
    :title: User is removed from cache after enumeration timeout
    :setup:
         1. Configure enumeration with enumeration timeout
         2. Create an user and wait 2*timeout
    :steps:
         1. Check user presence in getent passwd output
         2. Delete user and wait 2*timeout
         3. Check user presence in getent passwd output
     :expectedresults:
         1. User is present
         2. User was deleted
         3. User is not present
    :customerscenario: False
    """
    
def test_ldap__enumeration_remove_group():
    """
    :title: Group is removed from cache after enumeration timeout
    :setup:
         1. Configure enumeration with enumeration timeout
         2. Create a group and wait 2*timeout
    :steps:
         1. Check group presence in getent group output
         2. Delete group and wait 2*timeout
         3. Check group presence in getent group output
     :expectedresults:
         1. Group is present
         2. Group was deleted
         3. Group is not present
    :customerscenario: False
    """

def test_ldap__enumeration_remove_membership():
    """
    :title: Group membership is removed from cache after enumeration timeout
    :setup:
         1. Configure enumeration with enumeration timeout
         2. Create a group with user as a member and wait 2*timeout
    :steps:
         1. Check user membership in group
         2. Delete membership of user in group and wait 2*timeout
         3. Check user membership in group
     :expectedresults:
         1. User is a member of the group
         2. Membership was removed
         3. User is no longer a member of the group
    :customerscenario: False
    """

def test_ldap__enumeration_add_membership():
    """
    :title: Group membership is added after enumeration timeout
    :setup:
         1. Configure enumeration with enumeration timeout
         2. Create a group and user and wait 2*timeout
    :steps:
         1. Check user membership in group
         2. Add membership of user in group and wait 2*timeout
         3. Check user membership in group
     :expectedresults:
         1. User is no longer a member of the group
         2. Membership was added
         3. User is a member of the group
    :customerscenario: False
    """

def test_ldap__enumeration_auto_private_groups():
    """
    :title: Enumeration works with auto private groups
    :setup:
         1. Configure enumeration with enumeration timeout
         2. Enable auto private groups
         3. Create a group and user as its member and wait 2*timeout
    :steps:
         1. Check user membership in group
         2. Check user membership in automatic group
     :expectedresults:
         1. User is a member of the group
         2. User is a member of the automatic group
    :customerscenario: False
    """


def test_ldap__enumeration_complex_groups():
    """
    :title: Enumeration works with auto private groups
    :setup:
         1. Configure enumeration with enumeration timeout
         2. Create users user1, user2, user3
         3. Create an empty group empty_grp
         4. Create a group1 and add user1 as a member
         5. Create a group2 and add user2 and user3 as members
         6. Create a nested group nested_grp and add group 1 and group 2 as members
         7. Create  mixed group mixed_grp, user1 and group2 as its members
         8. Wait 2*timeout
    :steps:
         1. Check that all groups are present in getent group
         2. Check that memberships match the expectations
     :expectedresults:
         1. All groups are present in the output
         2. All memberships are as expected.
    :customerscenario: False
    """


def test_ldap__ppolicy_password_change_as_user():
    """
    :title: User must change their password during the login prompt
    :setup:
         1. Create user
         2. Configure ‘ldap_pwmodify_mode’ and Start SSSD
    :steps:
         1. Login as user
         2. Issue password change as user and logout
         3. Login with new password
         4. Login with old password
     :expectedresults:
         1. User is authenticated
         2. Password is changed successfully
         3. User can login
         4. User cannot login
    :customerscenario: True
    """

def test_ldap__ppolicy_change_as_user_with_complexity_requirement():
    """
    :title: User must change their password during the login prompt
    :setup:
        1. Create user
        2. Enable password complexity
        3. Start SSSD
    :steps:
         1. Login as user
         2. Issue password change as user with password that does not meet complexity requirements
         3. Issue password change as user with password meeting complexity requirements and logout
         4. Login with old password
     :expectedresults:
         1. User is authenticated
         2. Password is changed successfully
         3. User can login
         4. User cannot login
    :customerscenario: True
    """