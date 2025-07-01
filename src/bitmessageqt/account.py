"""
Account related functions.

"""

import inspect
import re
import sys
import time
import sqlite3

from unqstr import ustr, unic
from dbcompat import dbstr

import queues
from addresses import decodeAddress
from bmconfigparser import config
from helper_ackPayload import genAckPayload
from helper_sql import sqlQuery, sqlExecute
from .foldertree import AccountMixin
from .utils import str_broadcast_subscribers
from tr import _translate


def getSortedSubscriptions(count=False):
    """
    Actually return a grouped dictionary rather than a sorted list

    :param count: Whether to count messages for each fromaddress in the inbox
    :type count: bool, default False
    :retuns: dict keys are addresses, values are dicts containing settings
    :rtype: dict, default {}
    """
    print("DEBUG: getSortedSubscriptions called with count=", count)
    
    queryreturn = sqlQuery(
        'SELECT label, address, enabled FROM subscriptions'
        ' ORDER BY label COLLATE NOCASE ASC')
    print("DEBUG: Retrieved", len(queryreturn), "subscriptions from database")
    
    ret = {}
    for label, address, enabled in queryreturn:
        label = label.decode("utf-8", "replace")
        address = address.decode("utf-8", "replace")
        print(f"DEBUG: Processing subscription - Label: {label}, Address: {address}, Enabled: {enabled}")
        ret[address] = {'inbox': {}}
        ret[address]['inbox'].update(label=label, enabled=enabled, count=0)
    
    if count:
        print("DEBUG: Counting unread messages for each subscription")
        queryreturn = sqlQuery(
            'SELECT fromaddress, folder, count(msgid) AS cnt'
            ' FROM inbox, subscriptions'
            ' ON subscriptions.address = inbox.fromaddress WHERE read = 0'
            ' AND toaddress = ? GROUP BY inbox.fromaddress, folder',
            dbstr(str_broadcast_subscribers))
        
        for address, folder, cnt in queryreturn:
            address = address.decode("utf-8", "replace")
            folder = folder.decode("utf-8", "replace")
            print(f"DEBUG: Unread count - Address: {address}, Folder: {folder}, Count: {cnt}")
            
            if folder not in ret[address]:
                ret[address][folder] = {
                    'label': ret[address]['inbox']['label'],
                    'enabled': ret[address]['inbox']['enabled']
                }
            ret[address][folder]['count'] = cnt
    
    print("DEBUG: Returning", len(ret), "subscriptions")
    return ret


def accountClass(address):
    """Return a BMAccount for the address"""
    print("DEBUG: accountClass called for address:", address)
    
    if not config.has_section(address):
        print("DEBUG: No config section found for address")
        if address == str_broadcast_subscribers:
            print("DEBUG: Processing broadcast address")
            subscription = BroadcastAccount(address)
            if subscription.type != AccountMixin.BROADCAST:
                print("DEBUG: Invalid broadcast account type")
                return None
        else:
            print("DEBUG: Processing subscription address")
            subscription = SubscriptionAccount(address)
            if subscription.type != AccountMixin.SUBSCRIPTION:
                print("DEBUG: Invalid subscription account type, returning NoAccount")
                return NoAccount(address)
        return subscription
    
    try:
        gateway = config.get(address, "gateway")
        print("DEBUG: Found gateway:", gateway)
        
        for _, cls in inspect.getmembers(
                sys.modules[__name__], inspect.isclass):
            if issubclass(cls, GatewayAccount) and cls.gatewayName == gateway:
                print("DEBUG: Found matching gateway class:", cls.__name__)
                return cls(address)
        
        print("DEBUG: Using general GatewayAccount")
        return GatewayAccount(address)
    except Exception as e:
        print("DEBUG: Exception in accountClass:", str(e))
    
    print("DEBUG: No gateway found, using BMAccount")
    return BMAccount(address)


class AccountColor(AccountMixin):
    """Set the type of account"""

    def __init__(self, address, address_type=None):
        print("DEBUG: AccountColor.__init__ called for address:", address)
        self.isEnabled = True
        self.address = address
        if address_type is None:
            if address is None:
                self.type = AccountMixin.ALL
                print("DEBUG: Account type set to ALL")
            elif config.safeGetBoolean(self.address, 'mailinglist'):
                self.type = AccountMixin.MAILINGLIST
                print("DEBUG: Account type set to MAILINGLIST")
            elif config.safeGetBoolean(self.address, 'chan'):
                self.type = AccountMixin.CHAN
                print("DEBUG: Account type set to CHAN")
            elif sqlQuery(
                'SELECT label FROM subscriptions WHERE address=?',
                dbstr(self.address)
            ):
                self.type = AccountMixin.SUBSCRIPTION
                print("DEBUG: Account type set to SUBSCRIPTION")
            else:
                self.type = AccountMixin.NORMAL
                print("DEBUG: Account type set to NORMAL")
        else:
            self.type = address_type
            print("DEBUG: Account type set to custom:", address_type)


class NoAccount(object):
    """Minimal account like object (All accounts)"""
    # pylint: disable=too-many-instance-attributes
    def __init__(self, address=None):
        print("DEBUG: NoAccount.__init__ called for address:", address)
        self.address = address
        self.type = AccountMixin.NORMAL
        self.toAddress = self.fromAddress = ''
        self.subject = self.message = ''
        self.fromLabel = self.toLabel = ''

    def getLabel(self, address=None):
        """Get a label for this bitmessage account"""
        print("DEBUG: NoAccount.getLabel called for address:", address)
        return address or self.address

    def parseMessage(self, toAddress, fromAddress, subject, message):
        """Set metadata and address labels on self"""
        print("DEBUG: NoAccount.parseMessage called with:")
        print("DEBUG: - toAddress:", toAddress)
        print("DEBUG: - fromAddress:", fromAddress)
        print("DEBUG: - subject:", subject)
        print("DEBUG: - message length:", len(message))
        
        self.toAddress = ustr(toAddress)
        self.fromAddress = ustr(fromAddress)
        self.subject = ustr(subject)
        self.message = ustr(message)
        self.fromLabel = ustr(self.getLabel(fromAddress))
        self.toLabel = ustr(self.getLabel(toAddress))


class BMAccount(NoAccount):
    """Encapsulate a Bitmessage account"""

    def __init__(self, address=None):
        print("DEBUG: BMAccount.__init__ called for address:", address)
        super(BMAccount, self).__init__(address)
        if config.has_section(address):
            print("DEBUG: Config section found for address")
            if config.safeGetBoolean(self.address, 'chan'):
                self.type = AccountMixin.CHAN
                print("DEBUG: Account type set to CHAN")
            elif config.safeGetBoolean(self.address, 'mailinglist'):
                self.type = AccountMixin.MAILINGLIST
                print("DEBUG: Account type set to MAILINGLIST")
        elif self.address == str_broadcast_subscribers:
            self.type = AccountMixin.BROADCAST
            print("DEBUG: Account type set to BROADCAST")
        elif sqlQuery(
            'SELECT label FROM subscriptions WHERE address=?', dbstr(self.address)
        ):
            self.type = AccountMixin.SUBSCRIPTION
            print("DEBUG: Account type set to SUBSCRIPTION")

    def getLabel(self, address=None):
        """Get a label for this bitmessage account"""
        print("DEBUG: BMAccount.getLabel called for address:", address)
        address = super(BMAccount, self).getLabel(address)
        label = config.safeGet(address, 'label', address)
        
        queryreturn = sqlQuery(
            'SELECT label FROM addressbook WHERE address=?', dbstr(address))
        if queryreturn:
            print("DEBUG: Found label in addressbook")
            label = queryreturn[-1][0]
        else:
            queryreturn = sqlQuery(
                'SELECT label FROM subscriptions WHERE address=?', dbstr(address))
            if queryreturn:
                print("DEBUG: Found label in subscriptions")
                label = queryreturn[-1][0]
        
        print("DEBUG: Returning label:", label)
        return unic(ustr(label))


class SubscriptionAccount(BMAccount):
    """Encapsulate a subscription account"""
    pass


class BroadcastAccount(BMAccount):
    """Encapsulate a broadcast account"""
    pass


class GatewayAccount(BMAccount):
    """Encapsulate a gateway account"""

    gatewayName = None
    ALL_OK = 0
    REGISTRATION_DENIED = 1

    def send(self):
        """The send method for gateway accounts"""
        print("DEBUG: GatewayAccount.send called")
        streamNumber, ripe = decodeAddress(self.toAddress)[2:]
        stealthLevel = config.safeGetInt(
            'bitmessagesettings', 'ackstealthlevel')
        print("DEBUG: - streamNumber:", streamNumber)
        print("DEBUG: - ripe:", ripe)
        print("DEBUG: - stealthLevel:", stealthLevel)
        
        ackdata = genAckPayload(streamNumber, stealthLevel)
        print("DEBUG: Generated ackdata of length:", len(ackdata))
        
        current_time = int(time.time())
        ttl = min(config.getint('bitmessagesettings', 'ttl'), 86400 * 2)
        print("DEBUG: - current_time:", current_time)
        print("DEBUG: - ttl:", ttl)
        
        sqlExecute(
            '''INSERT INTO sent VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            sqlite3.Binary(b''),
            dbstr(self.toAddress),
            sqlite3.Binary(ripe),
            dbstr(self.fromAddress),
            dbstr(self.subject),
            dbstr(self.message),
            sqlite3.Binary(ackdata),
            current_time,  # sentTime (this will never change)
            current_time,  # lastActionTime
            0,  # sleepTill time. This will get set when the POW gets done.
            dbstr('msgqueued'),
            0,  # retryNumber
            dbstr('sent'),  # folder
            2,  # encodingtype
            ttl
        )
        print("DEBUG: Message inserted into sent table")

        queues.workerQueue.put(('sendmessage', self.toAddress))
        print("DEBUG: Added sendmessage task to workerQueue")


class MailchuckAccount(GatewayAccount):
    """Encapsulate a particular kind of gateway account"""

    # set "gateway" in keys.dat to this
    gatewayName = "mailchuck"
    registrationAddress = "BM-2cVYYrhaY5Gbi3KqrX9Eae2NRNrkfrhCSA"
    unregistrationAddress = "BM-2cVMAHTRjZHCTPMue75XBK5Tco175DtJ9J"
    relayAddress = "BM-2cWim8aZwUNqxzjMxstnUMtVEUQJeezstf"
    regExpIncoming = re.compile(r"(.*)MAILCHUCK-FROM::(\S+) \| (.*)")
    regExpOutgoing = re.compile(r"(\S+) (.*)")

    def __init__(self, address):
        print("DEBUG: MailchuckAccount.__init__ called for address:", address)
        super(MailchuckAccount, self).__init__(address)
        self.feedback = self.ALL_OK
        print("DEBUG: feedback initialized to ALL_OK")

    def createMessage(self, toAddress, fromAddress, subject, message):
        """createMessage specific to a MailchuckAccount"""
        print("DEBUG: MailchuckAccount.createMessage called")
        print("DEBUG: - Original toAddress:", toAddress)
        print("DEBUG: - Original subject:", subject)
        
        self.subject = toAddress + " " + subject
        self.toAddress = self.relayAddress
        self.fromAddress = fromAddress
        self.message = message
        
        print("DEBUG: - Modified toAddress:", self.toAddress)
        print("DEBUG: - Modified subject:", self.subject)

    def register(self, email):
        """register specific to a MailchuckAccount"""
        print("DEBUG: MailchuckAccount.register called with email:", email)
        self.toAddress = self.registrationAddress
        self.subject = email
        self.message = ""
        self.fromAddress = self.address
        self.send()

    def unregister(self):
        """unregister specific to a MailchuckAccount"""
        print("DEBUG: MailchuckAccount.unregister called")
        self.toAddress = self.unregistrationAddress
        self.subject = ""
        self.message = ""
        self.fromAddress = self.address
        self.send()

    def status(self):
        """status specific to a MailchuckAccount"""
        print("DEBUG: MailchuckAccount.status called")
        self.toAddress = self.registrationAddress
        self.subject = "status"
        self.message = ""
        self.fromAddress = self.address
        self.send()

    def settings(self):
        """settings specific to a MailchuckAccount"""
        print("DEBUG: MailchuckAccount.settings called")
        self.toAddress = self.registrationAddress
        self.subject = "config"
        self.message = _translate(
            "Mailchuck",
            """# You can use this to configure your email gateway account
# Uncomment the setting you want to use
# Here are the options:
#
# pgp: server
# The email gateway will create and maintain PGP keys for you and sign, verify,
# encrypt and decrypt on your behalf. When you want to use PGP but are lazy,
# use this. Requires subscription.
#
# pgp: local
# The email gateway will not conduct PGP operations on your behalf. You can
# either not use PGP at all, or use it locally.
#
# attachments: yes
# Incoming attachments in the email will be uploaded to MEGA.nz, and you can
# download them from there by following the link. Requires a subscription.
#
# attachments: no
# Attachments will be ignored.
#
# archive: yes
# Your incoming emails will be archived on the server. Use this if you need
# help with debugging problems or you need a third party proof of emails. This
# however means that the operator of the service will be able to read your
# emails even after they have been delivered to you.
#
# archive: no
# Incoming emails will be deleted from the server as soon as they are relayed
# to you.
#
# masterpubkey_btc: BIP44 xpub key or electrum v1 public seed
# offset_btc: integer (defaults to 0)
# feeamount: number with up to 8 decimal places
# feecurrency: BTC, XBT, USD, EUR or GBP
# Use these if you want to charge people who send you emails. If this is on and
# an unknown person sends you an email, they will be requested to pay the fee
# specified. As this scheme uses deterministic public keys, you will receive
# the money directly. To turn it off again, set "feeamount" to 0. Requires
# subscription.
""")
        self.fromAddress = self.address

    def parseMessage(self, toAddress, fromAddress, subject, message):
        """parseMessage specific to a MailchuckAccount"""
        print("DEBUG: MailchuckAccount.parseMessage called")
        print("DEBUG: - toAddress:", toAddress)
        print("DEBUG: - fromAddress:", fromAddress)
        print("DEBUG: - subject:", subject)
        print("DEBUG: - message length:", len(message))
        
        super(MailchuckAccount, self).parseMessage(
            toAddress, fromAddress, subject, message
        )
        
        if fromAddress == self.relayAddress:
            print("DEBUG: Processing message from relayAddress")
            matches = self.regExpIncoming.search(subject)
            if matches is not None:
                print("DEBUG: Found matching incoming pattern")
                self.subject = ""
                if not matches.group(1) is None:
                    self.subject += matches.group(1)
                if not matches.group(3) is None:
                    self.subject += matches.group(3)
                if not matches.group(2) is None:
                    self.fromLabel = matches.group(2)
                    self.fromAddress = matches.group(2)
                    print("DEBUG: Updated fromLabel and fromAddress to:", matches.group(2))
        
        if toAddress == self.relayAddress:
            print("DEBUG: Processing message to relayAddress")
            matches = self.regExpOutgoing.search(subject)
            if matches is not None:
                print("DEBUG: Found matching outgoing pattern")
                if not matches.group(2) is None:
                    self.subject = matches.group(2)
                if not matches.group(1) is None:
                    self.toLabel = matches.group(1)
                    self.toAddress = matches.group(1)
                    print("DEBUG: Updated toLabel and toAddress to:", matches.group(1))
        
        self.feedback = self.ALL_OK
        if fromAddress == self.registrationAddress \
                and self.subject == "Registration Request Denied":
            print("DEBUG: Registration was denied")
            self.feedback = self.REGISTRATION_DENIED
        
        print("DEBUG: Returning feedback code:", self.feedback)
        return self.feedback
