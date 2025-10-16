def test_ipa_trusts__authentication_with_default_settings ():
    """
    :title: Authenticate IPA and trusted AD users with default settings
    :setup:
        1. Create trusted user
        2. Start SSSD
    :steps:
        1. Authenticate user using their fully qualified name
        2. Authenticate user using the wrong password
    :expectedresults:
        1. Login is successful
        2. Login is unsuccessful
    :customerscenario: False
    """
def test_ipa_trusts__authentication_with_default_domain_suffix_set():
    """
    :title: Authenticate IPA and trusted AD users with default_domain_suffix set to AD
    :setup:
        1. Create trusted user
        2. Set 'default_domain_suffix' value to 'trusted_domain'
        3. Start SSSD
    :steps:
        1. Authenticate user using their fully qualified name
        2. Authenticate users using the wrong password
    :expectedresults:
        1. Logins are successful
        2. Logins are unsuccessful
    :customerscenario: True
    """
