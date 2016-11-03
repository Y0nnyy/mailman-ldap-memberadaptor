# Mailman LDAP Member Adaptor
A LDAP Membership Adaptor for Mailman 2.1

This work is based on https://bugs.launchpad.net/mailman/+bug/558106

This code is in beta! Feel free to open issues or submit patches.
The adaptor is currently testet with Mailman 2.1.15

## PREREQUISITES
This module requires the "ldap" module, aka python-ldap,
obtainable from http://python-ldap.sourceforge.net/.

## USAGE
To use this module, place it in the ~mailman/Mailman directory.
Create a normal Mailman mailing list with no members.  Create an
"extend.py" file in the list's directory (~mailman/lists/yourlist)
with the following in it:

```python
from Mailman.LDAP2Memberships import LDAP2Memberships

def extend(list):
    ldap = LDAP2Memberships(list)
    ldap.ldapserver = 'ldap://ldap.example.net:389' # your LDAP server
    ldap.ldapbasedn = 'dc=example,dc=net'           # your base DN
    ldap.ldapbinddn = 'cn=admin,dc=example,dc=net'  # bind DN that can access 'mail' field
    ldap.ldappasswd = ''                            # bind password for ldapbinddn
    ldap.ldaprefresh = 300                          # refresh time in seconds
    ldap.ldaptls = False                            # use TLS, must be set to True or False
    ldap.ldapsearch = '(objectClass=*)'             # your LDAP search here
    ldap.ldapgroupdn = None                         # an optional groupdn if you want only members
                                                    # of a specific group
    ldap.ldapgroupattr = 'memberUid'                # if using groups, attribute that holds member uid info.
                                                    # omit or set to null string if not using groups.
    ldap.ldapfullname = 'displayName'               # the attribute that should be used for the fullname
    ldap.ldapmodgroupdn = None                      # OPTIONAL a group that do not have the moderation flag
                                                    # (all other will get the default flag)
                                                    # if set to None, the moderation flag can be control via
                                                    # the admin interface
    ldap.alwaysDeliver = False                      # OPTIONAL set to true to disable bounces, user deactivation and topics
                                                    # Disabling delivery via the admin interface is always possible
    ldap.defaults()                                 # Sets missing options (should always be called)
    list._memberadaptor = ldap
```

## KNOWN BUGS and LIMITATIONS

1. This module does not support for adding/remove users.

2. Bounce processing is only partially supported.  If `alwaysDeliver` is
   set to `False`, users will be deactivated but not removed (see 1.).
   If it is set to `True` bounce processing is completely disabled.

3. The Mailman Web interface does not detect that we do not implement the
   add/remove function and will show a useless error message.

4. The LDAP settings themselves (e.g. ldapsearch) are only administrable
   by editing extend.py, not over the Web.

5. Assumption:  The email address of subscribers is in the 'mail' field in
   their LDAP records.  If it is somewhere else, kick your LDAP admin for
   not being compliant with inetOrgPerson ...
   
