@pytest.mark.parametrize(
   "type, name",
   [("group", "grp_nowait"), ("netgroup", "netgrp_nowait")],
)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_netgroup__sssd_entry_cache_nowait_percentage(client: Client, provider: GenericProvider, type: str, name: str):
   """
   :title: SSSD entry cache performance with nowait percentage for groups and netgroups
   :setup:
       1. Create a test user
       2. Configure SSSD with:
           - NSS: filter root groups/users, debug level 9, entry cache nowait percentage set to 50%
           - Domain 'test': entry cache timeout set to 30 seconds
       3. Restart SSSD with a clean state
       4. Create a group or netgroup named based on the 'type' parameter, add the test user
          as a member of the group or netgroup
   :steps:
       1. Record the start time for the initial getent lookup
       2. Retrieve the group or netgroup
       3. Calculate the initial response time after the getent call
       4. Add a 50-second delay to the provider using traffic control
       5. Wait 16 seconds to allow cache behavior to take effect
       6. Record the start time and perform a second getent lookup
       7. Calculate the cached response time and remove the delay
   :expectedresults:
       1. The start time is recorded before the initial getent call
       2. The initial getent call returns a non-None result for the group/netgroup
       3. The initial response time is calculated correctly from the first lookup
       4. The 50-second delay is applied to simulate a slow provider response
       5. The 16-second wait occurs without issues, testing cache usage
       6. The second getent call returns a non-None result, indicating cache hit
       7. The cached response time is less than the initial time
   :customerscenario: False
   """
