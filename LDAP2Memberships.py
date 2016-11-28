#
# Mailman.LDAPMemberships -- Netscape-style LDAP-search-based mailing lists
#
# (c) 2016 Sebastian Rettenberger
# (c) 2003, 2005 Karl A. Krueger and Woods Hole Oceanographic Institution
# Mailman interfaces (c) 2001-2003 Free Software Foundation
#
# This file is a derivative work of Mailman, and for this reason
# distributed under the same terms as Mailman itself, which follow:
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

"""This module implements LDAP search-based mailing lists.  That is,
the membership of the mailing list is defined by the results of a
search against an LDAP directory. This is good for internal mailing
lists in organizations which use LDAP for staff and user directories.

Please visit https://github.com/rettenbs/mailman-ldap-memberadaptor
for details.
"""

# Not sure why we need to do this to find ldap
try:
	import ldap
except ImportError:
	import sys
	sys.path.append('/usr/lib/python2.7/dist-packages')
	import ldap
import ldap.modlist

import time
from types import StringType

from Mailman import mm_cfg
from Mailman import Utils
from Mailman import Errors
from Mailman import MemberAdaptor
from Mailman.Logging.Syslog import syslog

DEBUG = False



class LDAP2Memberships(MemberAdaptor.MemberAdaptor):
    def __init__(self, mlist):
        self.__mlist = mlist

        self.__updatetime = 0
        self.__ldap_conn = None

        self.__regularmembers = None
        self.__digestmembers = None
        self.__member_map = {}
        self.__member_names = {}
        self.__mod_members = {}


    #
    # LDAP utility functions
    #
    def __ldap_bind(self):
        if not self.__ldap_conn:
            l = ldap.initialize(self.ldapserver)
            if self.ldaptls:
                l.start_tls_s()
            l.simple_bind_s(self.ldapbinddn, self.ldappasswd)
            self.__ldap_conn = l
        return self.__ldap_conn

    def __loadmembers(self, result, moderator=False):
        for (dn, attrs) in result:
            if 'mail' in attrs:
                mail = attrs['mail'][0].strip()
                if moderator:
                    self.__mod_members[dn] = True
                else:
                    if dn in self.__mlist.digest_members or not self.__mlist.nondigestable:
                        self.__digestmembers[dn] = mail
                    else:
                        self.__regularmembers[dn] = mail
                    if DEBUG:
                        syslog('debug','adding members[lce] = %s' % mail)
                    # mail can have multiple values -- the_olo
                    for maddr in attrs['mail']:
                        self.__member_map[maddr.strip().lower()] = dn
                    if self.ldapfullname and attrs.has_key(self.ldapfullname):
                        # set full name if defined
                        fullname = attrs[self.ldapfullname][0].decode('utf8')
                        self.__member_names[dn] = fullname

    def __ldap_load_members(self, l=None):
        if ( (self.__regularmembers is None)
            or (self.__digestmembers is None)
            or (self.__updatetime + self.ldaprefresh < time.time()) ):
            self.__regularmembers = {}
            self.__digestmembers = {}
            self.__updatetime = time.time()
            if not l:
                l = self.__ldap_bind()
            self.__ldap_load_members2(l)

            if self.ldapmodgroupdn:
                self.__ldap_load_members2(l, True)

            if self.alwaysDeliver:
                # FIXME for some reason this not working ...
                # Manually disable it from the admin interface
                self.__mlist.bounce_processing = False

    def __ldap_load_members2(self, l, moderator=False):
        attr = ['mail']
        if not moderator and self.ldapfullname:
            attr.append(self.ldapfullname)
        if self.ldapgroupattr or moderator:
            # group attribute or moderator flag has been set. Let's get the uids.
            if moderator:
                assert self.ldapmodgroupdn
                groupdn = self.ldapmodgroupdn
            else:
                groupdn = self.ldapgroupdn
            members = l.search_s(groupdn, ldap.SCOPE_SUBTREE,
                self.ldapsearch, [self.ldapgroupattr])
            for (dn,attrs) in members:
                if self.ldapgroupattr in attrs:
                    memberids = attrs[self.ldapgroupattr]
                    if DEBUG:
                        syslog('debug','regular groupdns = %s' % groupdns)
                    for memberid in memberids:
                        try:
                            res2 = l.search_s(self.ldapbasedn,
                                              ldap.SCOPE_SUBTREE,
                                              '(&(objectClass=*)('+self.ldapmemberuid+'='+memberid+'))',
                                              attr)
                            self.__loadmembers(res2, moderator)
                        except ldap.NO_SUCH_OBJECT:
                            syslog('warn',"can't process %s: no such object (accountDisabled?)" % memberid)

        else:
            members = l.search_s(self.ldapbasedn,
                                ldap.SCOPE_SUBTREE,
                                self.ldapsearch,
                                attr)
            self.__loadmembers(members)

        
    def __ldap_member_to_key(self, member):
        key = self.__member_map.get(member.lower(), None)
        if key:
            return key
        # Might alreay be a key ...
        return member

    def __ldap_get_member_cpe(self, member):
        self.__ldap_load_members()
        member = self.__ldap_member_to_key(member)
        cpe = self.__regularmembers.get(member, None)
        if cpe:
            return cpe
        return self.__digestmembers.get(member, None)

    def __ldap_mail_to_cn(self, member):
        self.__ldap_load_members()
        member = self.__ldap_member_to_key(member)
        return self.__member_names.get(member, None)

    def __ldap_update_mail(self, member, newaddress):
        l = self.__ldap_bind()
        dn = self.__ldap_member_to_key(member)
        oldaddress = self.getMemberCPAddress(member)
        modlist = ldap.modlist.modifyModlist({'mail': oldaddress},
                                             {'mail': newaddress})
        l.modify_s(dn, modlist)

        # Load new values
        self.__updatetime = 0
        self.__ldap_load_members(l)

    def __addOldStyleMember(self, member):
        """Initializes additional data for this member"""
        assert self.__mlist.Locked()

        self.setMemberPassword(member, Utils.MakeRandomPassword())
        self.setMemberLanguage(member, self.__mlist.preferred_language)
        if self.__mlist.new_member_options:
            self.__mlist.user_options[member] = self.__mlist.new_member_options

    def __delOldStyleMember(self, member):
        """Remove all referencing member from the old style storage"""
        assert self.__mlist.Locked()

        # Delete the appropriate entries from the various MailList attributes.
        # Remember that not all of them will have an entry (only those with
        # values different than the default).
        for attr in ('passwords', 'user_options',
                     'language',  'topics_userinterest',
                     'bounce_info', 'delivery_status',
                     ):
            dict = getattr(self.__mlist, attr)
            if dict.has_key(member):
                del dict[member]

    def __syncOldStyleStorage(self):
        """Synchronize OldStyle data with LDAP"""

        # LDAP list (loads current data from LDAP)
        ldapMembers = set(self.__regularmembers.keys() + self.__digestmembers.keys())
        # Old style members
        oldStyleMembers = set(self.__mlist.members.keys() + self.__mlist.digest_members.keys())
        # Members we need to add to the old style storage
        newMembers = ldapMembers - oldStyleMembers
        # Members we need to delete from the old style storage
        oldMembers = oldStyleMembers - ldapMembers

        # Now lock the list and update the old style storge
        if self.__mlist.Locked():
            unlock = False
        else:
            self.__mlist.Lock()
            unlock = True

        try:
            for member in newMembers:
                self.__addOldStyleMember(member)
            for member in oldMembers:
                self.__delOldStyleMember(member)

            # Update regular/digest list
            self.__mlist.members = self.__regularmembers
            self.__mlist.digest_members = self.__digestmembers

            self.__mlist.Save()
        finally:
           if unlock:
               self.__mlist.Unlock()

    def defaults(self):
        """Set default values for options"""
        if not hasattr(self, 'ldapmemberuid'):
            self.ldapmemberuid = 'uid'
        if not hasattr(self, 'ldapmodgroupdn'):
            self.ldapmodgroupdn = None
        if not hasattr(self, 'alwaysDeliver'):
            self.alwaysDeliver = False

    #
    # Read interface
    #
            
    def getMembers(self):
        self.__ldap_load_members()
        v = self.__regularmembers.values() + self.__digestmembers.values()
        if not v:
            return []
        return map(str.lower, v)

    def getRegularMemberKeys(self):
        self.__ldap_load_members()
        v = self.__regularmembers.values()
        if not v:
            return []
        return map(str.lower, v)

    def getDigestMemberKeys(self):
        self.__ldap_load_members()
        v = self.__digestmembers.values()
        if not v:
            return []
        return map(str.lower, v)

    def isMember(self, member):
        self.__ldap_load_members()
        member = self.__ldap_member_to_key(member)
        return (member in self.__regularmembers) or (member in self.__digestmembers)
               
    def __assertIsMember(self, member):
        if not self.isMember(member):
            raise Errors.NotAMemberError, member

    def getMemberKey(self, member):
        self.__assertIsMember(member)
        return self.__ldap_member_to_key(member)

    def getMemberCPAddress(self, member):
        cpaddr = self.__ldap_get_member_cpe(member)
        if cpaddr is None:
            raise Errors.NotAMemberError, member
        return cpaddr

    def getMemberCPAddresses(self, members):
        return [self.__ldap_get_member_cpe(member) for member in members]

    def getMemberPassword(self, member):
        self.__ldap_load_members()
        self.__syncOldStyleStorage()

        member = self.__ldap_member_to_key(member)
        secret = self.__mlist.passwords.get(member)
        if secret is None:
            raise Errors.NotAMemberError, member
        return secret

    def authenticateMember(self, member, response):
        secret = self.getMemberPassword(member)
        if secret == response:
            return secret
        return False

    def getMemberLanguage(self, member):
        member = self.__ldap_member_to_key(member)
        lang = self.__mlist.language.get(
            member, self.__mlist.preferred_language)
        if lang in self.__mlist.GetAvailableLanguages():
            return lang
        return self.__mlist.preferred_language

    def getMemberOption(self, member, flag):
        self.__assertIsMember(member)

        member = self.__ldap_member_to_key(member)
        if flag == mm_cfg.Digests:
            return member in self.__digestmembers.keys()
        if flag == mm_cfg.Moderate and self.ldapmodgroupdn:
            if member in self.__mod_members:
                 return False
            return self.__mlist.default_member_moderation
        option = self.__mlist.user_options.get(member,
            self.__mlist.new_member_options)
        return not not (option & flag)

    def getMemberName(self, member):
        self.__assertIsMember(member)
        try:
            return self.__ldap_mail_to_cn(member)
        except ldap.LDAPError:
            raise NotAMemberError

    def getMemberTopics(self, member):
        self.__assertIsMember(member)
        if self.alwaysDeliver:
             return []
        member = self.__ldap_member_to_key(member)
        return self.__mlist.topics_userinterest.get(member, [])

    def __getDelivery(self, member):
        self.__assertIsMember(member)
        member = self.__ldap_member_to_key(member)
        status = self.__mlist.delivery_status.get(member,
            # Values are tuples, so the default should also be a tuple.  The
            # second item will be ignored.
            (MemberAdaptor.ENABLED, 0))
        if status[0] == MemberAdaptor.BYADMIN:
            return status
        if self.alwaysDeliver:
            return (MemberAdaptor.ENABLED, 0)
        return status

    def getDeliveryStatus(self, member):
        return self.__getDelivery(member)[0]

    def getDeliveryStatusChangeTime(self, member):
        return self.__getDelivery(member)[1]

    def getDeliveryStatusMembers(self, status=(MemberAdaptor.UNKNOWN,
                                               MemberAdaptor.BYUSER,
                                               MemberAdaptor.BYADMIN,
                                               MemberAdaptor.BYBOUNCE)):
        return [member for member in self.getMembers()
                if self.getDeliveryStatus(member) in status]

    def getBouncingMembers(self):
        if self.alwaysDeliver:
             return []
        return [member for member in self.__mlist.bounce_info.keys()]

    def getBounceInfo(self, member):
        self.__assertIsMember(member)
        if self.alwaysDeliver:
             return None
        member = self.__ldap_member_to_key(member)
        return self.__mlist.bounce_info.get(member)

    #
    # Write interface
    #
    def addNewMember(self, member, **kws):
        raise NotImplementedError

    def removeMember(self, member):
        raise NotImplementedError

    def changeMemberAddress(self, member, newaddress, nodelete=0):
        if nodelete:
            # Can modify the address but not create a new one
            raise NotImplementedError

        assert self.__mlist.Locked()

        # Make sure the old address is a member
        self.__assertIsMember(member)

        # Get old values
        member = self.__ldap_member_to_key(member)
        digestsp = self.getMemberOption(member, mm_cfg.Digests)
        password = self.__mlist.passwords.get(member, None)
        lang = self.getMemberLanguage(member)
        flags = self.__mlist.user_options.get(member, 0)
        delivery = self.__getDelivery(member)
        topics = self.getMemberTopics(member)

        # Update LDAP
        self.__ldap_update_mail(member, newaddress)

        # Save old values for new member
        newmember = newaddress.lower()
        if digestsp:
            self.__mlist.digest_members[newmember] = newaddress
        else:
            self.__mlist.members[newmember] = newaddress
        if password:
            self.__mlist.passwords[newmember] = password
        self.__mlist.language[newmember] = lang
        if flags:
            self.__mlist.user_options[newmember] = flags
        if delivery[0] in (MemberAdaptor.BYUSER, MemberAdaptor.BYADMIN):
            self.__mlist.delivery_status[newmember] = delivery
        if topics:
            self.__mlist.topics_userinterest[newmember] = topics

        # Delete the old user data
        self.__syncOldStyleStorage()

    def setMemberPassword(self, memberkey, password):
        assert self.__mlist.Locked()
        self.__assertIsMember(memberkey)
        memberkey = self.__ldap_member_to_key(memberkey)
        self.__mlist.passwords[memberkey] = password

    def setMemberLanguage(self, memberkey, language):
        assert self.__mlist.Locked()
        self.__assertIsMember(memberkey)
        memberkey = self.__ldap_member_to_key(memberkey)
        self.__mlist.language[memberkey] = language

    def setMemberOption(self, member, flag, value):
        assert self.__mlist.Locked()
        self.__assertIsMember(member)
        member = self.__ldap_member_to_key(member)
        # There's one extra gotcha we have to deal with.  If the user is
        # toggling the Digests flag, then we need to move their entry from
        # mlist.members to mlist.digest_members or vice versa.  Blarg.  Do
        # this before the flag setting below in case it fails.
        if flag == mm_cfg.Digests:
            if value:
                # Be sure the list supports digest delivery
                if not self.__mlist.digestable:
                    raise Errors.CantDigestError
                # The user is turning on digest mode
                if self.__digestmembers.has_key(member):
                    raise Errors.AlreadyReceivingDigests, member
                cpuser = self.__regularmembers.get(member)
                if cpuser is None:
                    raise Errors.NotAMemberError, member
                del self.__regularmembers[member]
                self.__digestmembers[member] = cpuser
                # If we recently turned off digest mode and are now
                # turning it back on, the member may be in one_last_digest.
                # If so, remove it so the member doesn't get a dup of the
                # next digest.
                if self.__mlist.one_last_digest.has_key(member):
                    del self.__mlist.one_last_digest[member]
            else:
                # Be sure the list supports regular delivery
                if not self.__mlist.nondigestable:
                    raise Errors.MustDigestError
                # The user is turning off digest mode
                if self.__regularmembers.has_key(member):
                    raise Errors.AlreadyReceivingRegularDeliveries, member
                cpuser = self.__digestmembers.get(member)
                if cpuser is None:
                    raise Errors.NotAMemberError, member
                del self.__digestmembers[member]
                self.__regularmembers[member] = cpuser
                # When toggling off digest delivery, we want to be sure to set
                # things up so that the user receives one last digest,
                # otherwise they may lose some email
                self.__mlist.one_last_digest[member] = cpuser
            self.__mlist.members = self.__regularmembers
            self.__mlist.digest_members = self.__digestmembers
            # We don't need to touch user_options because the digest state
            # isn't kept as a bitfield flag.
            return
        # This is a bit kludgey because the semantics are that if the user has
        # no options set (i.e. the value would be 0), then they have no entry
        # in the user_options dict.  We use setdefault() here, and then del
        # the entry below just to make things (questionably) cleaner.
        self.__mlist.user_options.setdefault(member, 0)
        if value:
            self.__mlist.user_options[member] |= flag
        else:
            self.__mlist.user_options[member] &= ~flag
        if not self.__mlist.user_options[member]:
            del self.__mlist.user_options[member]

    def setMemberName(self, member, realname):
        # Silently ignore this function (otherwise we can not change other options
        # via the admin interface)
        pass
        #raise NotImplementedError

    def setMemberTopics(self, member, topics):
        if self.alwaysDeliver:
             raise NotImplementedError

        assert self.__mlist.Locked()
        self.__assertIsMember(member)
        member = self.__ldap_member_to_key(member)
        if topics:
            self.__mlist.topics_userinterest[member] = topics
        # if topics is empty, then delete the entry in this dictionary
        elif self.__mlist.topics_userinterest.has_key(member):
            del self.__mlist.topics_userinterest[member]

    def setDeliveryStatus(self, member, status):
        assert status in (MemberAdaptor.ENABLED,  MemberAdaptor.UNKNOWN,
                          MemberAdaptor.BYUSER,   MemberAdaptor.BYADMIN,
                          MemberAdaptor.BYBOUNCE)
        if self.alwaysDeliver and status not in (MemberAdaptor.ENABLED, MemberAdaptor.BYADMIN):
             raise NotImplementedError

        assert self.__mlist.Locked()
        self.__assertIsMember(member)
        member = self.__ldap_member_to_key(member)
        if status == MemberAdaptor.ENABLED:
            # Enable by resetting their bounce info.
            self.setBounceInfo(member, None)
        else:
            self.__mlist.delivery_status[member] = (status, time.time())

    def setBounceInfo(self, member, info):
        assert self.__mlist.Locked()
        self.__assertIsMember(member)
        assert self.__mlist.Locked()
        if info is None:
            if self.__mlist.bounce_info.has_key(member):
                del self.__mlist.bounce_info[member]
            if self.__mlist.delivery_status.has_key(member):
                del self.__mlist.delivery_status[member]
        else:
            if self.alwaysDeliver:
                 raise NotImplementedError
            self.__mlist.bounce_info[member] = info
