
def test_session_recording_none_scope():
	"""
	:title: Verify no session recording with scope=none
	:setup:
    	1. Configure SSSD with session_recording scope=none
    	2. Start SSSD
	:steps:
    	1. Query user information using getpwnam, getpwuid, and getpwent
	:expectedresults:
    	1. All user queries return original shell paths
    	2. No session recording shell substitution occurs
	"""

def test_session_recording_all_scope_getpwnam():
	"""
	:title: Verify all sessions recorded with scope=all using getpwnam
	:setup:
    	1. Configure SSSD with session_recording scope=all
    	2. Start SSSD
	:steps:
    	1. Query user information using getpwnam
	:expectedresults:
    	1. All user queries return session recording shell
    	2. Original shell paths are replaced with session recording shell
	"""

def test_session_recording_all_scope_getpwuid():
	"""
	:title: Verify all sessions recorded with scope=all using getpwuid
	:setup:
    	1. Configure SSSD with session_recording scope=all
    	2. Start SSSD
	:steps:
    	1. Query user information using getpwuid
	:expectedresults:
    	1. All user queries return session recording shell
    	2. Original shell paths are replaced with session recording shell
	"""

def test_session_recording_all_scope_getpwent():
	"""
	:title: Verify all sessions recorded with scope=all using getpwent
	:setup:
    	1. Configure SSSD with session_recording scope=all
    	2. Start SSSD
	:steps:
    	1. Query user information using getpwent
	:expectedresults:
    	1. All user queries return session recording shell
    	2. Original shell paths are replaced with session recording shell
	"""

def test_session_recording_some_empty_users_groups():
	"""
	:title: Verify no recording with scope=some and empty user/group lists
	:setup:
    	1. Configure SSSD with session_recording scope=some and no users/groups specified
    	2. Start SSSD
	:steps:
    	1. Query user information using various methods
	:expectedresults:
    	1. All user queries return original shell paths
    	2. No session recording occurs due to empty inclusion lists
	"""

def test_session_recording_some_users_getpwnam():
	"""
	:title: Verify specific users recorded with scope=some using getpwnam
	:setup:
    	1. Configure SSSD with session_recording scope=some and specific users list
    	2. Start SSSD
	:steps:
    	1. Query user information using getpwnam
	:expectedresults:
    	1. Listed users return session recording shell
    	2. Non-listed users return original shell paths
	"""

def test_session_recording_some_users_getpwuid():
	"""
	:title: Verify specific users recorded with scope=some using getpwuid
	:setup:
    	1. Configure SSSD with session_recording scope=some and specific users list
    	2. Start SSSD
	:steps:
    	1. Query user information using getpwuid
	:expectedresults:
    	1. Listed users return session recording shell
    	2. Non-listed users return original shell paths
	"""

def test_session_recording_some_users_getpwent():
	"""
	:title: Verify specific users recorded with scope=some using getpwent
	:setup:
    	1. Configure SSSD with session_recording scope=some and specific users list
    	2. Start SSSD
	:steps:
    	1. Query user information using getpwent
	:expectedresults:
    	1. Listed users return session recording shell
    	2. Non-listed users return original shell paths
	"""

def test_session_recording_some_users_overridden_names_getpwnam():
	"""
	:title: Verify recording works with overridden user names using getpwnam
	:setup:
    	1. Configure SSSD with session_recording scope=some and user list
    	2. Override some user names using sss_override
    	3. Start SSSD
	:steps:
    	1. Query user information using getpwnam
	:expectedresults:
    	1. Recording follows overridden user names
    	2. Session recording shell applied based on configured user list
	"""

def test_session_recording_some_users_overridden_names_getpwuid():
	"""
	:title: Verify recording works with overridden user names using getpwuid
	:setup:
    	1. Configure SSSD with session_recording scope=some and user list
    	2. Override some user names using sss_override
    	3. Start SSSD
	:steps:
    	1. Query user information using getpwuid
	:expectedresults:
    	1. Recording follows overridden user names
    	2. Session recording shell applied based on configured user list
	"""

def test_session_recording_some_users_overridden_names_getpwent():
	"""
	:title: Verify recording works with overridden user names using getpwent
	:setup:
    	1. Configure SSSD with session_recording scope=some and user list
    	2. Override some user names using sss_override
    	3. Start SSSD
	:steps:
    	1. Query user information using getpwent
	:expectedresults:
    	1. Recording follows overridden user names
    	2. Session recording shell applied based on configured user list
	"""

def test_session_recording_some_groups_supplementary_getpwnam():
	"""
	:title: Verify recording based on supplementary group membership using getpwnam
	:setup:
    	1. Configure SSSD with session_recording scope=some and group list
    	2. Start SSSD
	:steps:
    	1. Query user information for users in listed groups using getpwnam
	:expectedresults:
    	1. Users in listed groups return session recording shell
    	2. Users not in listed groups return original shell paths
	"""

def test_session_recording_some_groups_supplementary_getpwuid():
	"""
	:title: Verify recording based on supplementary group membership using getpwuid
	:setup:
    	1. Configure SSSD with session_recording scope=some and group list
    	2. Start SSSD
	:steps:
    	1. Query user information for users in listed groups using getpwuid
	:expectedresults:
    	1. Users in listed groups return session recording shell
    	2. Users not in listed groups return original shell paths
	"""

def test_session_recording_some_groups_supplementary_getpwent():
	"""
	:title: Verify recording based on supplementary group membership using getpwent
	:setup:
    	1. Configure SSSD with session_recording scope=some and group list
    	2. Start SSSD
	:steps:
    	1. Query user information for users in listed groups using getpwent
	:expectedresults:
    	1. Users in listed groups return session recording shell
    	2. Users not in listed groups return original shell paths
	"""

def test_session_recording_some_groups_user_without_primary_getpwnam():
	"""
	:title: Verify recording for user without primary group in supplementary group using getpwnam
	:setup:
    	1. Configure SSSD with session_recording scope=some and supplementary group list
    	2. Include a user that has no primary group but belongs to listed supplementary group
    	3. Start SSSD
	:steps:
    	1. Query user information for user without primary group using getpwnam
	:expectedresults:
    	1. User without primary group but in listed supplementary group returns session recording shell
    	2. Other users return original shell paths based on group membership
	"""

def test_session_recording_some_groups_user_without_primary_getpwuid():
	"""
	:title: Verify recording for user without primary group in supplementary group using getpwuid
	:setup:
    	1. Configure SSSD with session_recording scope=some and supplementary group list
    	2. Include a user that has no primary group but belongs to listed supplementary group
    	3. Start SSSD
	:steps:
    	1. Query user information for user without primary group using getpwuid
	:expectedresults:
    	1. User without primary group but in listed supplementary group returns session recording shell
    	2. Other users return original shell paths based on group membership
	"""

def test_session_recording_some_groups_user_without_primary_getpwent():
	"""
	:title: Verify recording for user without primary group in supplementary group using getpwent
	:setup:
    	1. Configure SSSD with session_recording scope=some and supplementary group list
    	2. Include a user that has no primary group but belongs to listed supplementary group
    	3. Start SSSD
	:steps:
    	1. Query user information for user without primary group using getpwent
	:expectedresults:
    	1. User without primary group but in listed supplementary group returns session recording shell
    	2. Other users return original shell paths based on group membership
	"""

def test_session_recording_some_groups_overridden_gids_getpwnam():
	"""
	:title: Verify recording with overridden group GIDs using getpwnam
	:setup:
    	1. Configure SSSD with session_recording scope=some and group list
    	2. Override group GIDs using sss_override (swap GIDs between groups)
    	3. Start SSSD
	:steps:
    	1. Query user information for group members using getpwnam
	:expectedresults:
    	1. Recording follows overridden group GIDs
    	2. Session recording shell applied based on configured group list with swapped GIDs
	"""

def test_session_recording_some_groups_overridden_gids_getpwuid():
	"""
	:title: Verify recording with overridden group GIDs using getpwuid
	:setup:
    	1. Configure SSSD with session_recording scope=some and group list
    	2. Override group GIDs using sss_override (swap GIDs between groups)
    	3. Start SSSD
	:steps:
    	1. Query user information for group members using getpwuid
	:expectedresults:
    	1. Recording follows overridden group GIDs
    	2. Session recording shell applied based on configured group list with swapped GIDs
	"""

def test_session_recording_some_groups_overridden_gids_getpwent():
	"""
	:title: Verify recording with overridden group GIDs using getpwent
	:setup:
    	1. Configure SSSD with session_recording scope=some and group list
    	2. Override group GIDs using sss_override (swap GIDs between groups)
    	3. Start SSSD
	:steps:
    	1. Query user information for group members using getpwent
	:expectedresults:
    	1. Recording follows overridden group GIDs
    	2. Session recording shell applied based on configured group list with swapped GIDs
	"""

def test_session_recording_some_groups_user_gid_overridden_getpwnam():
	"""
	:title: Verify recording with overridden user GIDs using getpwnam
	:setup:
    	1. Configure SSSD with session_recording scope=some and group list
    	2. Override user GIDs using sss_override (swap user primary GIDs)
    	3. Start SSSD
	:steps:
    	1. Query user information using getpwnam
	:expectedresults:
    	1. Recording follows overridden user GIDs
    	2. Session recording shell applied based on user's overridden primary group membership
	"""

def test_session_recording_some_groups_user_gid_overridden_getpwuid():
	"""
	:title: Verify recording with overridden user GIDs using getpwuid
	:setup:
    	1. Configure SSSD with session_recording scope=some and group list
    	2. Override user GIDs using sss_override (swap user primary GIDs)
    	3. Start SSSD
	:steps:
    	1. Query user information using getpwuid
	:expectedresults:
    	1. Recording follows overridden user GIDs
    	2. Session recording shell applied based on user's overridden primary group membership
	"""

def test_session_recording_some_groups_user_gid_overridden_getpwent():
	"""
	:title: Verify recording with overridden user GIDs using getpwent
	:setup:
    	1. Configure SSSD with session_recording scope=some and group list
    	2. Override user GIDs using sss_override (swap user primary GIDs)
    	3. Start SSSD
	:steps:
    	1. Query user information using getpwent
	:expectedresults:
    	1. Recording follows overridden user GIDs
    	2. Session recording shell applied based on user's overridden primary group membership
	"""

def test_session_recording_some_users_and_groups_combined():
	"""
	:title: Verify recording with combined user and group lists
	:setup:
    	1. Configure SSSD with session_recording scope=some and both users and groups lists
    	2. Start SSSD
	:steps:
    	1. Query user information for various users
	:expectedresults:
    	1. Users in either users list or group members get session recording shell
    	2. Other users return original shell paths
	"""

def test_session_recording_all_exclude_users():
	"""
	:title: Verify exclude users functionality with scope=all
	:setup:
    	1. Configure SSSD with session_recording scope=all and exclude_users list
    	2. Start SSSD
	:steps:
    	1. Query user information for excluded and non-excluded users
	:expectedresults:
    	1. Excluded users return original shell paths
    	2. Non-excluded users return session recording shell
	"""

def test_session_recording_all_exclude_groups():
	"""
	:title: Verify exclude groups functionality with scope=all
	:setup:
    	1. Configure SSSD with session_recording scope=all and exclude_groups list
    	2. Start SSSD
	:steps:
    	1. Query user information for group members
	:expectedresults:
    	1. Users in excluded groups return original shell paths
    	2. Other users return session recording shell
	"""

def test_session_recording_some_ignore_excludes():
	"""
	:title: Verify exclude options are ignored with scope=some
	:setup:
    	1. Configure SSSD with session_recording scope=some and both include/exclude lists
    	2. Start SSSD
	:steps:
    	1. Query user information
	:expectedresults:
    	1. Only included users/groups get session recording shell
    	2. Exclude lists are ignored when scope=some
	"""

