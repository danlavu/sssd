
def test_infopipe__ping_interface():
	"""
	:title: Call the infopipe ping method
	:setup:
    	1. Start SSSD
	:steps:
    	1. Call ping method
	:expectedresults:
    	1. Ping success
	:customerscenario: False
	"""
    
def test_infopipe__list_component():
	"""
	:title: Call infopipe Listcomponents method
	:setup:
    	1. Start SSSD
	:steps:
    	1. Call ListComponents() method
      2. Verify returned components
	:expectedresults:
    	1. Method returns components
      2. At least monitor component is present
	:customerscenario: False
	"""
    
def test_infopipe__find_monitor():
	"""
	:title: Call infopipe FindMonitor method
	:setup:
    	1. Start SSSD
	:steps:
    	1. Call FindMonitor method
      2. Get monitor properties
	:expectedresults:
    	1. Returns monitor object path
      2. Monitor properties contain expected values
	:customerscenario: False
	"""

def test_infopipe__find_user_by_id():
	"""
	:title: Test FindByID method of Users interface
	:setup:
    	1. Add user 'iduser' with specific UID
    	2. Launch SSSD
	:steps:
    	1. Call FindByID() with user's UID
    	2. Verify returned user object
	:expectedresults:
    	1. Correct user path is returned
    	2. User object has expected properties
	:customerscenario: False
	"""
def test_infopipe__find_group_by_id():
      """
	:title: Test FindByID method of Groups interface
	:setup:
    	1. Add group 'idgroup' with specific gid
    	2. Launch SSSD
	:steps:
    	1. Call FindByID() with group's gid
    	2. Verify returned group object
	:expectedresults:
    	1. Correct group path is returned
    	2. Group object has expected properties
	:customerscenario: False
	"""
def test_infopipe__update_user_groups():
	"""
	:title: Call infopipe UpdateGroupsList method
	:setup:
    	1. Create user and group, with the user as a member
    	2. Start SSSD
	:steps:
    	1. Get user object
    	2. Call UpdateGroupsList method
    	3. Verify groups are updated
	:expectedresults:
    	1. Correct user path is returned
    	2. Returns UpdateGroupsList object path
    	3. Groups are successfully updated with member of group
	:customerscenario: False
	"""




