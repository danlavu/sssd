"""
Smart Card tests

:requirement: SSSD Smart Card Support
"""

# Local user only
def test_smartcard__su_with_local_user():
    """
    :title: Use smart card to login with su as a local user account
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Start SSSD
    :steps:
        1. Authenticate user with correct pin
        2. Authenticate user with incorrect pin
    :expectedresults:
        1. Authentication is successful
        2. Authentication is unsuccessful
    :customerscenario: False
    """

# Local user def test_smartcard__su_with_local_useronly
def test_smartcard__ssh_with_local_user():
    """
    :title: Use smart card to login with ssh
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Add certificate with sss_override to a local override
        6. Start SSSD
    :steps:
        1. Authenticate user with correct pin with ssh
        2. Authenticate user with incorrect pin with ssh
        3. Set ssh_use_certificate_keys = False and restart SSSD
        4. Authenticate user with correct pin with ssh
    :expectedresults:
        1. Authentication is successful
        2. Authentication is unsuccessful
        3. SSSD restarts successfully with
        4. Authentication is unsuccessful
    :customerscenario: False
    """

def test_smartcard__login():
    """
    :title: Use smart card to login with su or ssh
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Start SSSD
    :steps:
        1. Authenticate user with correct pin
        2. Authenticate user with incorrect pin
    :expectedresults:
        1. Authentication is successful
        2. Authentication is unsuccessful
    :customerscenario: False
    """


def test_smartcard__login_when_ssh_use_certificate_keys_false():
    """
    :title: Use smart card to login with ssh
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Start SSSD
    :steps:
        1. Authenticate user with correct pin with ssh
        2. Set ssh_use_certificate_keys = False and restart SSSD
        3. Authenticate user with correct pin with ssh
    :expectedresults:
        1. Authentication is successful
        2. SSSD restarts successfully with
        3. Authentication is unsuccessful
    :customerscenario: False
    """


def test_smartcard__login_without_mapped_cert():
    """
    :title: Attempt to use smart card to login without cert mapped to user
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user and set password
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Start SSSD
    :steps:
        1. Authenticate user with correct pin
        2. Remove certificate data from user account
            2.1 switch to offline mode for su test.  See note from Sumit for more details.
        3. Authenticate user with correct pin with cached data
        4. Reset or timeout cache
        5. Authenticate user with password after cache expired
    :expectedresults:
        1. Authentication is successful
        2. Certificate data removed successfully
        3. Authentication with pin is successful
        4. Cache cleared
        5. Authentication prompts for password and is successful
    :customerscenario: False
NOTE: [Sumit] I think you have to switch into offline mode if you want this step to be successful for the 'su' case because during the authentication the user data is refreshed. For 'ssh' this might work because here the authentication is done by sshd and not by SSSD via PAM and the ssh responder will read the data from the cache,
    """


def test_smartcard__login_with_expired_cert():
    """
    :title: Attempt to use smart card to login with expired certificate
    :setup:
        1. Configure provider and client for smart card authentication
        2. Write key and expired certificate to virtual smart card
        3. Start SSSD
    :steps:
        1. Attempt to authenticate with smart card
    :expectedresults:
        1. Authentication prompts for password
    :customerscenario: False
    """

def test_smartcard__login_with_revoked_cert():
    """
    :title: Attempt to use smart card to login with revoked certificate
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        2. Write key and certificate to virtual smart card
        3. Start SSSD
    :steps:
        1. Authenticate as user with pin
        2. Revoke certificate (setting revoke-hold)
        3. Attempt to authenticate as user
        4. Remove revoke-hold for certificate
        5. Athenticate as user with pin
    :expectedresults:
        1. Authentication is successful with pin
        2. certificate revoked
        3. Authentication prompts for password
        4. revoke-hold is removed for certificate
        5. Authentication is successful with pin
    :customerscenario: False
    """

def test_smartcard__login_with_multiple_certs_on_card():
    """
    :title: Use smart card to login with multiple certs on the same card
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Create another key and certificate pair for user
        6. Write new key and certificate to virtual smart card
        7. Start SSSD
    :steps:
        1. Authenticate via sssctl with username with first cert/key pair with correct pin
        2. Authenticate via sssctl without username with second cert/key pair with correct pin
        3. Authenticate via sssctl with user with first cert/key pair with incorrect pin
    :expectedresults:
        1. Authentication is successful
        2. Authentication is successful
        3. Authentication is unsuccessful
    :customerscenario: False
    :notes: This test uses sssctl to handle the authentication so that the more complex
            requirements for GDM authentication are not necessary.
    """


def test_smartcard__login_with_cert_mapped_to_multiple_users():
    """
    :title: Use smart card to login with cert mapped to multiple users
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Add certificate mapping data to another user
        5. Start SSSD
    :steps:
        1. Authenticate user with correct pin
        2. Authenticate other user with correct pin
    :expectedresults:
        1. Authentication is successful
        2. Authentication is successful
    :customerscenario: False
    """

def test_smartcard__login_with_cert_with_special_chars():
    """
    :title: Use smart card to login when certificate subject contains special characters
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user which contains special characters in subject
        4. Write key and certificate to virtual smart card
        5. Add ipacertmapdata or altSecurityIdentities entry with special characters
        6. Add mapping rule using wildcards to match certificate with special characters in subject
        7. Start SSSD
    :steps:
        1. Authenticate user with correct pin
        2. Authenticate user with incorrect pin
    :expectedresults:
        1. Authentication is successful
        2. Authentication is unsuccessful
    :customerscenario: False
    """

def test_smartcard__su_as_root():
    """
    :title: Use smart card to login with su as root user
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create key and certificate for root
        3. Write key and certificate to virtual smart card
        4. Start SSSD
    :steps:
        1. Authenticate root with pin
    :expectedresults:
        1. Authentication is successful
    :customerscenario: False
    """

def test_smartcard__su_gets_kerberos_ticket():
    """
    :title: Use smart card to login with su and get a kerberos ticket
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Start SSSD
    :steps:
        1. Authenticate user with correct pin
        2. Check that user has kerberos ticket
        3. Configure Kerberos client to use KCM
        4. Authenticate user with correct pin
        5. Check that KCM was used
    :expectedresults:
        1. Authentication is successful
        2. User does have kerberos ticket
        3. Null
        4. Authentication is successful
        5. User has kerberos ticket and can see that KCM was used
    :customerscenario: False
    """

def test_smartcard__login_offline():
    """
    :title: Use smart card to login with su or ssh when provider is offline or unreachable
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Start SSSD
    :steps:
        1. Authenticate user with correct pin
        2. Check for Kerberos ticket
        3. Remove Kerberos ticket
        4. Disable access to provider (stop service or block traffic?)
        5. Authenticate user with correct pin
        6. Check for Kerberos ticket
    :expectedresults:
        1. Authentication with pin is successful
        2. kerberos ticket is found
        3. kerberos ticket is removed
        4. provider access disabled
        5. Authentication with pin is successful
        6. kerberos ticket is not found
    :customerscenario: False
    """


def test_smartcard__login_with_soft_crl():
    """
    :title: Use smart card to login when sssd is configured to soft fail CRL verifications
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Configure SSSD to use parametrized("crl_opts")
        6. Use parametrized("crl_opts") to point crl_file to current or expired CRL
        7. Start SSSD
    :steps:
        1. Attempt to authenticate user with smart card pin
            a. if ("", "current"), authn should pass
            b. if ("", "expired"), authn should fail
            c. if ("soft_crl", "current"), authn should pass
            d. if ("soft_crl", "expired"), authn should pass
    :expectedresults:
        1. Attempted results:
            a. authentication successful
            b. authentication fails
            c. authentication successful
            d. authentication successful
    :customerscenario: False
    """


def test_smartcard__login_with_soft_ocsp():
    """
    :title: Use smart card to login when sssd is configured to soft fail OCSP verifications
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Configure SSSD to use parametrized("ocsp_opts")
        6. Use parametrized("ocsp_opts") to disable OCSP access with firewall rule
            6.1 To disable OCSP access, we should create a firewall rule to drop packets so we cover the TCP timeout issue
        7. Start SSSD
    :steps:
        1. Attempt to authenticate user with smart card pin
            a. if ("", "ocsp_up"), authn should pass
            b. if ("", "ocsp_down"), authn should fail
            c. if ("soft_ocsp", "ocsp_up"), authn should pass
            d. if ("soft_ocsp", "ocsp_down"), authn should pass
    :expectedresults:
        1. Attempted results:
            a. authentication successful
            b. authentication fails
            c. authentication successful
            d. authentication successful
    :customerscenario: False
    """

def test_smartcard__login_with_ocsp_digest():
    """
    :title: Use smart card to login when sssd is configured to force OCSP digest
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Configure SSSD to use parametrized("ocsp_opts")
        6. Start SSSD
    :steps:
        1. Attempt to authenticate user with smart card pin
        2. Check digest was used for hashAlgorithm
            a. default == sha1
            b. sha256 == sha256
            c. sha384 == sha384
            d. sha512 == sha512
            e. sha1 == sha1
            f. bad_digest = sha1
    :expectedresults:
        1. Authentication is successful
        2. expected hashAlgorithm
            a. sha1
            b. sha256
            c. sha384
            d. sha512
            e. sha1
            f. sha1
    :customerscenario: False
    """

def test_smartcard__ssh_with_certificate_matching_rules():
    """
    :title: Use smart card to login when ssh uses certificate matching rules
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Create key and smime/email specific certificate for user
        6. Write key and smime/email specific certificate to virtual smart card
        7. Create certmap rules for ssh_pass, ssh_fail, ssh_client, and ssh_email as such:
           a. ssh_pass = '<SUBJECT>.*CN=ipauser1.*'
           b. ssh_fail = '<SUBJECT>.*CN=failuser1.*'
           c. ssh_client = '<EKU>clientAuth'
           d. ssh_email = '<EKU>emailProtection'
        7. Start SSSD
    :steps:
        1. Loop over options:
            [("", True),
            ("ssh_pass", True),
            ("ssh_fail", False),
            ("ssh_client", True),
            ("ssh_email", True),
            ("ssh_dne", True),
            ("all_rules:ssh_pass", True),
            ("all_rules:ssh_fail", False),
            ("no_rules:ssh_pass", True),
            ("no_rules:ssh_fail", "", True)])
        2. Configure SSSD ssh_use_certificate_matching_rules per option[0] and reset
            a. if option[0] is empty, do not add any options to SSSD config
            b. if option[0] containes ':', split and enable certmap rule from option[0].split(':')[1]
        3. Check SSH expected result matches option[1]
    :expectedresults:
        1. Process each option separately in the loop
        2. SSSD is configured and reset
        3. SSH result for each loop interation should match option[1]
    :customerscenario: False
    """

def test_smartcard__ldap_child_ignores_krb5_pkinit_identities():
    """
    :title: ldap_child ignores Kerberos pkinit_identities
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Start SSSD
    :steps:
        1. Configure krb5 pkinit_identities to point to opensc-pkcs11.so
        2. Check for /var/lib/sss/db/ccache_DOMAIN.NAME file and remove if it exists
        3. restart SSSD
        4. Wait until /var/lib/sss/db/ccache_DOMAIN.NAME exists or fail after 120 seconds
        5. Check for errors in journal
    :expectedresults:
        1. krb5 stub config created
        2. File removed if found
        3. SSSD restarted
        4. Continue after file found or fail after 120 seconds
        5. no error message found
    :customerscenario: False
    """

def test_smartcard__login_with_ad_certmapping():
    """
    :title: Use smart card to login with strong AD certmapping rules
    :setup:
        1. Configure provider and client for smart card authentication against AD
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Start SSSD
    :steps:
        1. Create certmap rule based on map_opts[0]
            a. serial_number = 'LDAPU1:(altSecurityIdentities=X509:<I>{issuer_dn!ad_x500}<SR>{serial_number!hex_ur})'
            b. subject_key_id = 'LDAPU1:(altSecurityIdentities=X509:<SKI>{subject_key_id!hex_u})'
            c. user_sid = 'LDAPU1:(objectsid={sid})'
        2. Add certmapdata to altSecurityIdentities
            a. If map_opts[1] is False, truncate certmapdata before adding
        3. Authenticate user with correct pin
    :expectedresults:
        1. certmaprule created successfully
        2. certmapdata added to altSecurityIdentities
        3. Authentication is successful
    :customerscenario: False
    """

def test_smartcard__login_with_softhsm_token():
    """
    :title: Use softhsm token to login with su or ssh
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Setup SoftHSM token
        4. Write key and certificate to SoftHSM token
        5. Start SSSD
    :steps:
        1. Authenticate user with correct pin
    :expectedresults:
        1. Authentication is successful
    :customerscenario: False
    """

def test_smartcard__login_with_empty_pin():
    """
    :title: Use smart card and fail to login with empty pin
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Setup SoftHSM token
        5. Write key and certificate to SoftHSM token
        6. Start SSSD
    :steps:
        1. Attempt to authenticate user with empty pin
    :expectedresults:
        1. Authentication fails
    :customerscenario: False
    """

def test_smartcard__login_when_card_is_not_inserted():
    """
    :title: Login as user with password when smart card is not inserted
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user and set password
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Start SSSD
        6. Remove smart card (stop virtual smart card service)
    :steps:
        1. Authenticate user with password
        2. check ldb does not contain localSmartcardAuth for user
        3. insert card (start virtual smart card service)
        4. login as user with pin
        5. check ldb does contain localSmartcardAuth for user
    :expectedresults:
        1. Authentication is successful and does not prompt for pin
        2. localSmartcardAuth not found in ldb
        3. card inserted
        4. Authentication successful with pin
        5. localSmartcardAuth found in ldb
    :customerscenario: False
    """

def test_smartcard__login_with_smartcard_required():
    """
    :title: Use smart card to login when authselect enables with-smartcard-required
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. authselct enable with-smartcard-required
        6. Start SSSD
    :steps:
        1. Remove smart card (stop virtual smart card service)
        2. Attempt to authenticate using sssctl with gdm-smartcard
    :expectedresults:
        1. smart card no longer available from the os
        2. Authentication should prompt to insert smart card
    :customerscenario: False
    """

def test_smartcard__login_with_multiple_certs_for_one_key():
    """
    :title: Use smart card to login with multiple certs for one key
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create two users
        3. Create key and certificate for first user
        4. Write key and certificate to virtual smart card
        5. Use first key to create a second certificate for first and second users
        6. Write certificate to virtual smart card
        7. Add second certificate to second user
        7. Start SSSD
    :steps:
        1. Authenticate as the first user with first cert/key pair with correct pin
        2. Authenticate as the first user with second cert with correct pin
        3. Authenticate as the second user with the second cert without a cert selection prompt
    :expectedresults:
        1. Authentication is successful
        2. Authentication is successful
        3. Authentication is successful and no prompt presented to choose a certificate
    :customerscenario: False
    """

def test_smartcard__login_with_multiple_cards():
    """
    :title: Use smart card to login with multiple smart cards
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create two users
        3. Create key and certificate for first user
        4. Write key and certificate to virtual smart card
        5. Create key and certificate for second user
        6. Write key and certificate to a different virtual smart card
        7. Add second certificate to first user
        8. Start SSSD
    :steps:
        1. Authenticate as the first user with the first card with correct pin
        2. Authenticate as the first user with the second card with correct pin
        3. Authenticate as the second user with the second card with correct pin
        4. Authenticate as the second user with the first card with correct pin
    :expectedresults:
        1. Authentication is successful
        2. Authentication is successful
        3. Authentication is successful and no prompt presented to choose a certificate
        4. Authentication is not successful
    :customerscenario: False
    """

def test_smartcard__p11_child_preauth_returns_certificate():
    """
    :title: p11_child preauth command returns certificate
    :setup:
        1. Configure provider and client for smart card authentication
        2. Create user
        3. Create key and certificate for user
        4. Write key and certificate to virtual smart card
        5. Start SSSD
    :steps:
        1. Run p11_child pre-auth with –uri to limit certificates returned
    :expectedresults:
        1. User certificate is returned
    :customerscenario: False
Note on above test from Sumit:
```
To limit the number of returned certificates p11_child can use PKCS#11 URIs with the `--uri` option. Additionally there are the `--module_name`, `--token_name`, `--key_id` and `--label` options to select the certificate used for authentication. The latter are still used because the MIT Kerberos pkinit module uses the same. If the module supports PKCS#11 URIs as well, it would be possible to switch to PKCS#11 URIs completely.
```
    """


def test_smartcard__unlock_console_with_vlock():
    """
    :title: Use smart card to unlock console with vlock
    :setup:
        1. Configure provider and client for smart card authentication
        2. Install vlock
        3. Create user
        4. Create key and certificate for user
        5. Write key and certificate to virtual smart card
        6. Start SSSD
    :steps:
        1. login as user and lock terminal with vlock
        2. Enter incorrect pin
        3. Enter correct pin
    :expectedresults:
        1. user logged in and vlock locks the terminal and prompts for PIN
        2. Authentication is unsuccessful
        3. Authentication is successful
    :customerscenario: False
    """

