# Copyright (c) 2012-2016 Jonathan Warren
# Copyright (c) 2012-2023 The Bitmessage developers

"""
This is not what you run to start the Bitmessage API.
Instead, `enable the API <https://bitmessage.org/wiki/API>`_
and optionally `enable daemon mode <https://bitmessage.org/wiki/Daemon>`_
then run the PyBitmessage.

The PyBitmessage API is provided either as
`XML-RPC <http://xmlrpc.scripting.com/spec.html>`_ or
`JSON-RPC <https://www.jsonrpc.org/specification>`_ like in bitcoin.
It's selected according to 'apivariant' setting in config file.

Special value ``apivariant=legacy`` is to mimic the old pre 0.6.3
behaviour when any results are returned as strings of json.

.. list-table:: All config settings related to API:
  :header-rows: 0

  * - apienabled = true
    - if 'false' the `singleAPI` wont start
  * - apiinterface = 127.0.0.1
    - this is the recommended default
  * - apiport = 8442
    - the API listens apiinterface:apiport if apiport is not used,
      random in range (32767, 65535) otherwice
  * - apivariant = xml
    - current default for backward compatibility, 'json' is recommended
  * - apiusername = username
    - set the username
  * - apipassword = password
    - and the password
  * - apinotifypath =
    - not really the API setting, this sets a path for the executable to be ran
      when certain internal event happens

To use the API concider such simple example:

.. code-block:: python

    from jsonrpclib import jsonrpc

    from pybitmessage import helper_startup
    from pybitmessage.bmconfigparser import config

    helper_startup.loadConfig()  # find and load local config file
    api_uri = "http://%s:%s@127.0.0.1:%s/" % (
        config.safeGet('bitmessagesettings', 'apiusername'),
        config.safeGet('bitmessagesettings', 'apipassword'),
        config.safeGet('bitmessagesettings', 'apiport')
    )
    api = jsonrpc.ServerProxy(api_uri)
    print(api.clientStatus())


For further examples please reference `.tests.test_api`.
"""

import base64
import errno
import hashlib
import json
import random
import socket
import subprocess  # nosec B404
import time
from binascii import hexlify, unhexlify
from struct import pack, unpack
import sqlite3

import six
from six.moves import configparser, http_client, xmlrpc_server
from six.moves.reprlib import repr
from dbcompat import dbstr

import helper_inbox
import helper_sent
import protocol
import proofofwork
import queues
import shared

import shutdown
import state
from addresses import (
    addBMIfNotPresent,
    decodeAddress,
    decodeVarint,
    varintDecodeError
)
from bmconfigparser import config
from debug import logger
from defaults import (
    networkDefaultProofOfWorkNonceTrialsPerByte,
    networkDefaultPayloadLengthExtraBytes)
from helper_sql import (
    SqlBulkExecute, sqlExecute, sqlQuery, sqlStoredProcedure, sql_ready)
from highlevelcrypto import calculateInventoryHash

try:
    from network import connectionpool
except ImportError:
    connectionpool = None

from network import stats, StoppableThread, invQueue
from version import softwareVersion

try:  # TODO: write tests for XML vulnerabilities
    from defusedxml.xmlrpc import monkey_patch
except ImportError:
    logger.warning(
        'defusedxml not available, only use API on a secure, closed network.')
else:
    monkey_patch()


str_chan = '[chan]'
str_broadcast_subscribers = '[Broadcast subscribers]'


class ErrorCodes(type):
    """Metaclass for :class:`APIError` documenting error codes."""
    _CODES = {
        0: 'Invalid command parameters number',
        1: 'The specified passphrase is blank.',
        2: 'The address version number currently must be 3, 4, or 0'
        ' (which means auto-select).',
        3: 'The stream number must be 1 (or 0 which means'
        ' auto-select). Others aren\'t supported.',
        4: 'Why would you ask me to generate 0 addresses for you?',
        5: 'You have (accidentally?) specified too many addresses to'
        ' make. Maximum 999. This check only exists to prevent'
        ' mischief; if you really want to create more addresses than'
        ' this, contact the Bitmessage developers and we can modify'
        ' the check or you can do it yourself by searching the source'
        ' code for this message.',
        6: 'The encoding type must be 2 or 3.',
        7: 'Could not decode address',
        8: 'Checksum failed for address',
        9: 'Invalid characters in address',
        10: 'Address version number too high (or zero)',
        11: 'The address version number currently must be 2, 3 or 4.'
        ' Others aren\'t supported. Check the address.',
        12: 'The stream number must be 1. Others aren\'t supported.'
        ' Check the address.',
        13: 'Could not find this address in your keys.dat file.',
        14: 'Your fromAddress is disabled. Cannot send.',
        15: 'Invalid ackData object size.',
        16: 'You are already subscribed to that address.',
        17: 'Label is not valid UTF-8 data.',
        18: 'Chan name does not match address.',
        19: 'The length of hash should be 32 bytes (encoded in hex'
        ' thus 64 characters).',
        20: 'Invalid method:',
        21: 'Unexpected API Failure',
        22: 'Decode error',
        23: 'Bool expected in eighteenByteRipe',
        24: 'Chan address is already present.',
        25: 'Specified address is not a chan address.'
        ' Use deleteAddress API call instead.',
        26: 'Malformed varint in address: ',
        27: 'Message is too long.'
    }

    def __new__(mcs, name, bases, namespace):
        result = super(ErrorCodes, mcs).__new__(mcs, name, bases, namespace)
        for code in six.iteritems(mcs._CODES):
            # beware: the formatting is adjusted for list-table
            result.__doc__ += """   * - %04i
         - %s
    """ % code
        return result


class APIError(xmlrpc_server.Fault):
    """
    APIError exception class

    .. list-table:: Possible error values
       :header-rows: 1
       :widths: auto

       * - Error Number
         - Message
    """
    __metaclass__ = ErrorCodes

    def __str__(self):
        return "API Error %04i: %s" % (self.faultCode, self.faultString)


# This thread, of which there is only one, runs the API.
class singleAPI(StoppableThread):
    """API thread"""

    name = "singleAPI"

    def stopThread(self):
        logger.debug("DEBUG: Stopping API thread")
        super(singleAPI, self).stopThread()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            logger.debug("DEBUG: Attempting to connect to API socket to shutdown")
            s.connect((
                config.get('bitmessagesettings', 'apiinterface'),
                config.getint('bitmessagesettings', 'apiport')
            ))
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            logger.debug("DEBUG: Successfully shut down API socket")
        except BaseException as e:
            logger.debug("DEBUG: Error shutting down API socket: %s", str(e))
            pass

    def run(self):
        """
        The instance of `SimpleXMLRPCServer.SimpleXMLRPCServer` or
        :class:`jsonrpclib.SimpleJSONRPCServer` is created and started here
        with `BMRPCDispatcher` dispatcher.
        """
        logger.debug("DEBUG: Starting API thread")
        port = config.getint('bitmessagesettings', 'apiport')
        try:
            getattr(errno, 'WSAEADDRINUSE')
        except AttributeError:
            errno.WSAEADDRINUSE = errno.EADDRINUSE

        RPCServerBase = xmlrpc_server.SimpleXMLRPCServer
        ct = 'text/xml'
        if config.safeGet(
                'bitmessagesettings', 'apivariant') == 'json':
            try:
                from jsonrpclib.SimpleJSONRPCServer import (
                    SimpleJSONRPCServer as RPCServerBase)
                logger.debug("DEBUG: Using JSON-RPC server")
            except ImportError:
                logger.warning(
                    'jsonrpclib not available, failing back to XML-RPC')
                logger.debug("DEBUG: Falling back to XML-RPC server")
            else:
                ct = 'application/json-rpc'

        # Nested class. FIXME not found a better solution.
        class StoppableRPCServer(RPCServerBase):
            """A SimpleXMLRPCServer that honours state.shutdown"""
            allow_reuse_address = True
            content_type = ct

            def serve_forever(self, poll_interval=None):
                """Start the RPCServer"""
                logger.debug("DEBUG: Waiting for SQL to be ready")
                sql_ready.wait()
                logger.debug("DEBUG: Starting API server loop")
                while state.shutdown == 0:
                    self.handle_request()
                logger.debug("DEBUG: API server loop ended")

        for attempt in range(50):
            try:
                if attempt > 0:
                    logger.warning(
                        'Failed to start API listener on port %s', port)
                    logger.debug("DEBUG: Attempt %d to start API listener", attempt)
                    port = random.randint(32767, 65535)  # nosec B311
                logger.debug("DEBUG: Trying to start API server on port %s", port)
                se = StoppableRPCServer(
                    (config.get(
                        'bitmessagesettings', 'apiinterface'),
                     port),
                    BMXMLRPCRequestHandler, True, encoding='UTF-8')
                logger.debug("DEBUG: Successfully started API server")
            except socket.error as e:
                logger.debug("DEBUG: Socket error starting API: %s", str(e))
                if e.errno in (errno.EADDRINUSE, errno.WSAEADDRINUSE):
                    continue
            else:
                if attempt > 0:
                    logger.warning('Setting apiport to %s', port)
                    logger.debug("DEBUG: Updating config with new port %s", port)
                    config.set(
                        'bitmessagesettings', 'apiport', str(port))
                    config.save()
                break

        logger.debug("DEBUG: Registering API dispatcher")
        se.register_instance(BMRPCDispatcher())
        se.register_introspection_functions()

        apiNotifyPath = config.safeGet(
            'bitmessagesettings', 'apinotifypath')

        if apiNotifyPath:
            logger.info('Trying to call %s', apiNotifyPath)
            logger.debug("DEBUG: Attempting to call API notify path: %s", apiNotifyPath)
            try:
                subprocess.call([apiNotifyPath, "startingUp"])  # nosec B603
                logger.debug("DEBUG: Successfully called API notify path")
            except OSError:
                logger.warning(
                    'Failed to call %s, removing apinotifypath setting',
                    apiNotifyPath)
                logger.debug("DEBUG: Failed to call API notify path, removing setting")
                config.remove_option(
                    'bitmessagesettings', 'apinotifypath')

        logger.debug("DEBUG: Starting API server main loop")
        se.serve_forever()
        logger.debug("DEBUG: API server main loop ended")


class CommandHandler(type):
    """
    The metaclass for `BMRPCDispatcher` which fills _handlers dict by
    methods decorated with @command
    """
    def __new__(mcs, name, bases, namespace):
        # pylint: disable=protected-access
        logger.debug("DEBUG: Creating CommandHandler for %s", name)
        result = super(CommandHandler, mcs).__new__(
            mcs, name, bases, namespace)
        result.config = config
        result._handlers = {}
        apivariant = result.config.safeGet('bitmessagesettings', 'apivariant')
        logger.debug("DEBUG: API variant is %s", apivariant)
        for func in namespace.values():
            try:
                for alias in getattr(func, '_cmd'):
                    try:
                        prefix, alias = alias.split(':')
                        if apivariant != prefix:
                            logger.debug("DEBUG: Skipping alias %s for different variant", alias)
                            continue
                    except ValueError:
                        pass
                    logger.debug("DEBUG: Registering handler for %s", alias)
                    result._handlers[alias] = func
            except AttributeError:
                pass
        logger.debug("DEBUG: Registered %d handlers", len(result._handlers))
        return result


class testmode(object):  # pylint: disable=too-few-public-methods
    """Decorator to check testmode & route to command decorator"""

    def __init__(self, *aliases):
        logger.debug("DEBUG: Creating testmode decorator with aliases: %s", aliases)
        self.aliases = aliases

    def __call__(self, func):
        """Testmode call method"""
        logger.debug("DEBUG: Checking testmode for function %s", func.__name__)

        if not state.testmode:
            logger.debug("DEBUG: Testmode disabled, returning None")
            return None
        logger.debug("DEBUG: Testmode enabled, creating command decorator")
        return command(self.aliases[0]).__call__(func)


class command(object):  # pylint: disable=too-few-public-methods
    """Decorator for API command method"""
    def __init__(self, *aliases):
        logger.debug("DEBUG: Creating command decorator with aliases: %s", aliases)
        self.aliases = aliases

    def __call__(self, func):
        logger.debug("DEBUG: Applying command decorator to %s", func.__name__)

        if config.safeGet(
                'bitmessagesettings', 'apivariant') == 'legacy':
            def wrapper(*args):
                """
                A wrapper for legacy apivariant which dumps the result
                into string of json
                """
                logger.debug("DEBUG: Legacy API variant wrapper called for %s", func.__name__)
                result = func(*args)
                logger.debug("DEBUG: Legacy API result type: %s", type(result))
                return result if isinstance(result, (int, str)) \
                    else json.dumps(result, indent=4)
            wrapper.__doc__ = func.__doc__
        else:
            wrapper = func
        # pylint: disable=protected-access
        wrapper._cmd = self.aliases
        wrapper.__doc__ = """Commands: *%s*

        """ % ', '.join(self.aliases) + wrapper.__doc__.lstrip()
        logger.debug("DEBUG: Finished decorating %s", func.__name__)
        return wrapper


# This is one of several classes that constitute the API
# This class was written by Vaibhav Bhatia.
# Modified by Jonathan Warren (Atheros).
# Further modified by the Bitmessage developers
# http://code.activestate.com/recipes/501148
class BMXMLRPCRequestHandler(xmlrpc_server.SimpleXMLRPCRequestHandler):
    """The main API handler"""

    # pylint: disable=protected-access
    def do_POST(self):
        """
        Handles the HTTP POST request.

        Attempts to interpret all HTTP POST requests as XML-RPC calls,
        which are forwarded to the server's _dispatch method for handling.

        .. note:: this method is the same as in
          `SimpleXMLRPCServer.SimpleXMLRPCRequestHandler`,
          just hacked to handle cookies
        """
        logger.debug("DEBUG: Received POST request")

        # Check that the path is legal
        if not self.is_rpc_path_valid():
            logger.debug("DEBUG: Invalid RPC path")
            self.report_404()
            return

        try:
            # Get arguments by reading body of request.
            # We read this in chunks to avoid straining
            # socket.read(); around the 10 or 15Mb mark, some platforms
            # begin to have problems (bug #792570).
            max_chunk_size = 10 * 1024 * 1024
            size_remaining = int(self.headers["content-length"])
            L = []
            logger.debug("DEBUG: Reading request body, size: %d", size_remaining)
            while size_remaining:
                chunk_size = min(size_remaining, max_chunk_size)
                chunk = self.rfile.read(chunk_size)
                if not chunk:
                    break
                L.append(chunk)
                size_remaining -= len(L[-1])
            data = b''.join(L)
            logger.debug("DEBUG: Read %d bytes of request data", len(data))

            # data = self.decode_request_content(data)
            # pylint: disable=attribute-defined-outside-init
            self.cookies = []

            validuser = self.APIAuthenticateClient()
            if not validuser:
                logger.debug("DEBUG: Authentication failed")
                time.sleep(2)
                self.send_response(http_client.UNAUTHORIZED)
                self.end_headers()
                return
                # "RPC Username or password incorrect or HTTP header"
                # " lacks authentication at all."
            else:
                logger.debug("DEBUG: Authentication successful")
                # In previous versions of SimpleXMLRPCServer, _dispatch
                # could be overridden in this class, instead of in
                # SimpleXMLRPCDispatcher. To maintain backwards compatibility,
                # check to see if a subclass implements _dispatch and dispatch
                # using that method if present.

                logger.debug("DEBUG: Dispatching request")
                response = self.server._marshaled_dispatch(
                    data, getattr(self, '_dispatch', None))
                logger.debug("DEBUG: Request dispatched, response length: %d", len(response))
        except Exception as e:  # This should only happen if the module is buggy
            logger.debug("DEBUG: Internal error in POST handler: %s", str(e))
            # internal error, report as HTTP server error
            self.send_response(http_client.INTERNAL_SERVER_ERROR)
            self.end_headers()
        else:
            # got a valid XML RPC response
            logger.debug("DEBUG: Sending successful response")
            self.send_response(http_client.OK)
            self.send_header("Content-type", self.server.content_type)
            self.send_header("Content-length", str(len(response)))

            # HACK :start -> sends cookies here
            if self.cookies:
                for cookie in self.cookies:
                    self.send_header('Set-Cookie', cookie.output(header=''))
            # HACK :end

            self.end_headers()
            self.wfile.write(response)

            # shut down the connection
            self.wfile.flush()
            self.connection.shutdown(1)

            # actually handle shutdown command after sending response
            if state.shutdown is False:
                logger.debug("DEBUG: Initiating clean shutdown")
                shutdown.doCleanShutdown()

    def APIAuthenticateClient(self):
        """
        Predicate to check for valid API credentials in the request header
        """
        logger.debug("DEBUG: Authenticating client")

        if 'Authorization' in self.headers:
            # handle Basic authentication
            encstr = self.headers.get('Authorization').split()[1]
            emailid, password = base64.b64decode(
                encstr).decode('utf-8').split(':')
            logger.debug("DEBUG: Received credentials for %s", emailid)
            return (
                emailid == config.get(
                    'bitmessagesettings', 'apiusername'
                ) and password == config.get(
                    'bitmessagesettings', 'apipassword'))
        else:
            logger.warning(
                'Authentication failed because header lacks'
                ' Authentication field')
            logger.debug("DEBUG: No Authorization header found")
            time.sleep(2)

        return False


# pylint: disable=no-self-use,no-member,too-many-public-methods
@six.add_metaclass(CommandHandler)
class BMRPCDispatcher(object):
    """This class is used to dispatch API commands"""

    @staticmethod
    def _decode(text, decode_type):
        logger.debug("DEBUG: Decoding text with type %s", decode_type)
        try:
            if decode_type == 'hex':
                result = unhexlify(text)
            elif decode_type == 'base64':
                result = base64.b64decode(text)
            logger.debug("DEBUG: Successfully decoded text")
            return result
        except Exception as e:
            logger.debug("DEBUG: Decode error: %s", str(e))
            raise APIError(
                22, 'Decode error - %s. Had trouble while decoding string: %r'
                % (e, text)
            )

    def _verifyAddress(self, address):
        logger.debug("DEBUG: Verifying address: %s", address)
        status, addressVersionNumber, streamNumber, ripe = \
            decodeAddress(address)
        if status != 'success':
            if status == 'checksumfailed':
                logger.debug("DEBUG: Checksum failed for address")
                raise APIError(8, 'Checksum failed for address: ' + address)
            if status == 'invalidcharacters':
                logger.debug("DEBUG: Invalid characters in address")
                raise APIError(9, 'Invalid characters in address: ' + address)
            if status == 'versiontoohigh':
                logger.debug("DEBUG: Address version too high")
                raise APIError(
                    10, 'Address version number too high (or zero) in address: '
                    + address)
            if status == 'varintmalformed':
                logger.debug("DEBUG: Malformed varint in address")
                raise APIError(26, 'Malformed varint in address: ' + address)
            logger.debug("DEBUG: Could not decode address: %s", status)
            raise APIError(
                7, 'Could not decode address: %s : %s' % (address, status))
        if addressVersionNumber < 2 or addressVersionNumber > 4:
            logger.debug("DEBUG: Invalid address version number")
            raise APIError(
                11, 'The address version number currently must be 2, 3 or 4.'
                ' Others aren\'t supported. Check the address.'
            )
        if streamNumber != 1:
            logger.debug("DEBUG: Invalid stream number")
            raise APIError(
                12, 'The stream number must be 1. Others aren\'t supported.'
                ' Check the address.'
            )

        logger.debug("DEBUG: Address verification successful")
        return {
            'status': status,
            'addressVersion': addressVersionNumber,
            'streamNumber': streamNumber,
            'ripe': base64.b64encode(ripe)
        } if self._method == 'decodeAddress' else (
            status, addressVersionNumber, streamNumber, ripe)

    @staticmethod
    def _dump_inbox_message(  # pylint: disable=too-many-arguments
            msgid, toAddress, fromAddress, subject, received,
            message, encodingtype, read):
        logger.debug("DEBUG: Dumping inbox message with ID: %s", hexlify(msgid))
        subject = shared.fixPotentiallyInvalidUTF8Data(subject)
        message = shared.fixPotentiallyInvalidUTF8Data(message)
        return {
            'msgid': hexlify(msgid),
            'toAddress': toAddress.decode("utf-8", "replace"),
            'fromAddress': fromAddress.decode("utf-8", "replace"),
            'subject': base64.b64encode(subject),
            'message': base64.b64encode(message),
            'encodingType': encodingtype,
            'receivedTime': received.decode("utf-8", "replace"),
            'read': read
        }

    @staticmethod
    def _dump_sent_message(  # pylint: disable=too-many-arguments
            msgid, toAddress, fromAddress, subject, lastactiontime,
            message, encodingtype, status, ackdata):
        logger.debug("DEBUG: Dumping sent message with ID: %s", hexlify(msgid))
        subject = shared.fixPotentiallyInvalidUTF8Data(subject)
        message = shared.fixPotentiallyInvalidUTF8Data(message)
        return {
            'msgid': hexlify(msgid),
            'toAddress': toAddress,
            'fromAddress': fromAddress,
            'subject': base64.b64encode(subject),
            'message': base64.b64encode(message),
            'encodingType': encodingtype,
            'lastActionTime': lastactiontime,
            'status': status,
            'ackData': hexlify(ackdata)
        }

    # Request Handlers

    @command('decodeAddress')
    def HandleDecodeAddress(self, address):
        """
        Decode given address and return dict with
        status, addressVersion, streamNumber and ripe keys
        """
        logger.debug("DEBUG: Handling decodeAddress for %s", address)
        return self._verifyAddress(address)

    @command('listAddresses', 'listAddresses2')
    def HandleListAddresses(self):
        """
        Returns dict with a list of all used addresses with their properties
        in the *addresses* key.
        """
        logger.debug("DEBUG: Handling listAddresses")
        data = []
        for address in self.config.addresses():
            streamNumber = decodeAddress(address)[2]
            label = self.config.get(address, 'label')
            if self._method == 'listAddresses2':
                label = base64.b64encode(label)
            data.append({
                'label': label,
                'address': address,
                'stream': streamNumber,
                'enabled': self.config.safeGetBoolean(address, 'enabled'),
                'chan': self.config.safeGetBoolean(address, 'chan')
            })
        logger.debug("DEBUG: Found %d addresses", len(data))
        return {'addresses': data}

    # the listAddressbook alias should be removed eventually.
    @command('listAddressBookEntries', 'legacy:listAddressbook')
    def HandleListAddressBookEntries(self, label=None):
        """
        Returns dict with a list of all address book entries (address and label)
        in the *addresses* key.
        """
        logger.debug("DEBUG: Handling listAddressBookEntries, label: %s", label)
        queryreturn = sqlQuery(
            "SELECT label, address from addressbook WHERE label = ?",
            dbstr(label)
        ) if label else sqlQuery("SELECT label, address from addressbook")
        data = []
        for label, address in queryreturn:
            label = shared.fixPotentiallyInvalidUTF8Data(label)
            address = address.decode("utf-8", "replace")
            data.append({
                'label': base64.b64encode(label),
                'address': address
            })
        logger.debug("DEBUG: Found %d address book entries", len(data))
        return {'addresses': data}

    # the addAddressbook alias should be deleted eventually.
    @command('addAddressBookEntry', 'legacy:addAddressbook')
    def HandleAddAddressBookEntry(self, address, label):
        """Add an entry to address book. label must be base64 encoded."""
        logger.debug("DEBUG: Handling addAddressBookEntry for %s", address)
        label = self._decode(label, "base64")
        address = addBMIfNotPresent(address)
        self._verifyAddress(address)
        # TODO: add unique together constraint in the table
        queryreturn = sqlQuery(
            "SELECT address FROM addressbook WHERE address=?", dbstr(address))
        if queryreturn != []:
            logger.debug("DEBUG: Address already exists in address book")
            raise APIError(
                16, 'You already have this address in your address book.')

        sqlExecute("INSERT INTO addressbook VALUES(?,?)", dbstr(label), dbstr(address))
        queues.UISignalQueue.put(('rerenderMessagelistFromLabels', ''))
        queues.UISignalQueue.put(('rerenderMessagelistToLabels', ''))
        queues.UISignalQueue.put(('rerenderAddressBook', ''))
        logger.debug("DEBUG: Added address %s to address book", address)
        return "Added address %s to address book" % address

    # the deleteAddressbook alias should be deleted eventually.
    @command('deleteAddressBookEntry', 'legacy:deleteAddressbook')
    def HandleDeleteAddressBookEntry(self, address):
        """Delete an entry from address book."""
        logger.debug("DEBUG: Handling deleteAddressBookEntry for %s", address)
        address = addBMIfNotPresent(address)
        self._verifyAddress(address)
        sqlExecute('DELETE FROM addressbook WHERE address=?', dbstr(address))
        queues.UISignalQueue.put(('rerenderMessagelistFromLabels', ''))
        queues.UISignalQueue.put(('rerenderMessagelistToLabels', ''))
        queues.UISignalQueue.put(('rerenderAddressBook', ''))
        logger.debug("DEBUG: Deleted address book entry for %s", address)
        return "Deleted address book entry for %s if it existed" % address

    @command('createRandomAddress')
    def HandleCreateRandomAddress(
        self, label, eighteenByteRipe=False, totalDifficulty=0,
        smallMessageDifficulty=0
    ):
        """
        Create one address using the random number generator.

        :param str label: base64 encoded label for the address
        :param bool eighteenByteRipe: is telling Bitmessage whether to
          generate an address with an 18 byte RIPE hash
          (as opposed to a 19 byte hash).
        """
        logger.debug("DEBUG: Handling createRandomAddress")

        nonceTrialsPerByte = self.config.get(
            'bitmessagesettings', 'defaultnoncetrialsperbyte'
        ) if not totalDifficulty else int(
            networkDefaultProofOfWorkNonceTrialsPerByte * totalDifficulty)
        payloadLengthExtraBytes = self.config.get(
            'bitmessagesettings', 'defaultpayloadlengthextrabytes'
        ) if not smallMessageDifficulty else int(
            networkDefaultPayloadLengthExtraBytes * smallMessageDifficulty)

        if not isinstance(eighteenByteRipe, bool):
            logger.debug("DEBUG: Invalid type for eighteenByteRipe")
            raise APIError(
                23, 'Bool expected in eighteenByteRipe, saw %s instead'
                % type(eighteenByteRipe))
        label = self._decode(label, "base64")
        try:
            label.decode('utf-8')
        except UnicodeDecodeError:
            logger.debug("DEBUG: Label is not valid UTF-8")
            raise APIError(17, 'Label is not valid UTF-8 data.')
        queues.apiAddressGeneratorReturnQueue.queue.clear()
        # FIXME hard coded stream no
        streamNumberForAddress = 1
        queues.addressGeneratorQueue.put((
            'createRandomAddress', 4, streamNumberForAddress, label, 1, "",
            eighteenByteRipe, nonceTrialsPerByte, payloadLengthExtraBytes
        ))
        result = queues.apiAddressGeneratorReturnQueue.get()
        logger.debug("DEBUG: Address generation result: %s", result)
        return result

    # pylint: disable=too-many-arguments
    @command('createDeterministicAddresses')
    def HandleCreateDeterministicAddresses(
        self, passphrase, numberOfAddresses=1, addressVersionNumber=0,
        streamNumber=0, eighteenByteRipe=False, totalDifficulty=0,
        smallMessageDifficulty=0
    ):
        """
        Create many addresses deterministically using the passphrase.

        :param str passphrase: base64 encoded passphrase
        :param int numberOfAddresses: number of addresses to create,
          up to 999

        *addressVersionNumber* and *streamNumber* may be set to 0
        which will tell Bitmessage to use the most up-to-date
        address version and the most available stream.
        """
        logger.debug("DEBUG: Handling createDeterministicAddresses")

        nonceTrialsPerByte = self.config.get(
            'bitmessagesettings', 'defaultnoncetrialsperbyte'
        ) if not totalDifficulty else int(
            networkDefaultProofOfWorkNonceTrialsPerByte * totalDifficulty)
        payloadLengthExtraBytes = self.config.get(
            'bitmessagesettings', 'defaultpayloadlengthextrabytes'
        ) if not smallMessageDifficulty else int(
            networkDefaultPayloadLengthExtraBytes * smallMessageDifficulty)

        if not passphrase:
            logger.debug("DEBUG: Blank passphrase")
            raise APIError(1, 'The specified passphrase is blank.')
        if not isinstance(eighteenByteRipe, bool):
            logger.debug("DEBUG: Invalid type for eighteenByteRipe")
            raise APIError(
                23, 'Bool expected in eighteenByteRipe, saw %s instead'
                % type(eighteenByteRipe))
        passphrase = self._decode(passphrase, "base64")
        # 0 means "just use the proper addressVersionNumber"
        if addressVersionNumber == 0:
            addressVersionNumber = 4
        if addressVersionNumber not in (3, 4):
            logger.debug("DEBUG: Invalid address version number")
            raise APIError(
                2, 'The address version number currently must be 3, 4, or 0'
                ' (which means auto-select). %i isn\'t supported.'
                % addressVersionNumber)
        if streamNumber == 0:  # 0 means "just use the most available stream"
            streamNumber = 1  # FIXME hard coded stream no
        if streamNumber != 1:
            logger.debug("DEBUG: Invalid stream number")
            raise APIError(
                3, 'The stream number must be 1 (or 0 which means'
                ' auto-select). Others aren\'t supported.')
        if numberOfAddresses == 0:
            logger.debug("DEBUG: Zero addresses requested")
            raise APIError(
                4, 'Why would you ask me to generate 0 addresses for you?')
        if numberOfAddresses > 999:
            logger.debug("DEBUG: Too many addresses requested")
            raise APIError(
                5, 'You have (accidentally?) specified too many addresses to'
                ' make. Maximum 999. This check only exists to prevent'
                ' mischief; if you really want to create more addresses than'
                ' this, contact the Bitmessage developers and we can modify'
                ' the check or you can do it yourself by searching the source'
                ' code for this message.')
        queues.apiAddressGeneratorReturnQueue.queue.clear()
        logger.debug(
            'Requesting that the addressGenerator create %s addresses.',
            numberOfAddresses)
        queues.addressGeneratorQueue.put((
            'createDeterministicAddresses', addressVersionNumber, streamNumber,
            'unused API address', numberOfAddresses, passphrase,
            eighteenByteRipe, nonceTrialsPerByte, payloadLengthExtraBytes
        ))

        result = queues.apiAddressGeneratorReturnQueue.get()
        logger.debug("DEBUG: Generated %d addresses", len(result))
        return {'addresses': result}

    @command('getDeterministicAddress')
    def HandleGetDeterministicAddress(
            self, passphrase, addressVersionNumber, streamNumber):
        """
        Similar to *createDeterministicAddresses* except that the one
        address that is returned will not be added to the Bitmessage
        user interface or the keys.dat file.
        """
        logger.debug("DEBUG: Handling getDeterministicAddress")

        numberOfAddresses = 1
        eighteenByteRipe = False
        if not passphrase:
            logger.debug("DEBUG: Blank passphrase")
            raise APIError(1, 'The specified passphrase is blank.')
        passphrase = self._decode(passphrase, "base64")
        if addressVersionNumber not in (3, 4):
            logger.debug("DEBUG: Invalid address version number")
            raise APIError(
                2, 'The address version number currently must be 3 or 4. %i'
                ' isn\'t supported.' % addressVersionNumber)
        if streamNumber != 1:
            logger.debug("DEBUG: Invalid stream number")
            raise APIError(
                3, ' The stream number must be 1. Others aren\'t supported.')
        queues.apiAddressGeneratorReturnQueue.queue.clear()
        logger.debug(
            'Requesting that the addressGenerator create %s addresses.',
            numberOfAddresses)
        queues.addressGeneratorQueue.put((
            'getDeterministicAddress', addressVersionNumber, streamNumber,
            'unused API address', numberOfAddresses, passphrase,
            eighteenByteRipe
        ))
        result = queues.apiAddressGeneratorReturnQueue.get()
        logger.debug("DEBUG: Generated deterministic address")
        return result

    @command('createChan')
    def HandleCreateChan(self, passphrase):
        """
        Creates a new chan. passphrase must be base64 encoded.
        Returns the corresponding Bitmessage address.
        """
        logger.debug("DEBUG: Handling createChan")

        passphrase = self._decode(passphrase, "base64")
        if not passphrase:
            logger.debug("DEBUG: Blank passphrase")
            raise APIError(1, 'The specified passphrase is blank.')
        # It would be nice to make the label the passphrase but it is
        # possible that the passphrase contains non-utf-8 characters.
        try:
            passphrase.decode('utf-8')
            label = str_chan + ' ' + passphrase
        except UnicodeDecodeError:
            label = str_chan + ' ' + repr(passphrase)

        addressVersionNumber = 4
        streamNumber = 1
        queues.apiAddressGeneratorReturnQueue.queue.clear()
        logger.debug(
            'Requesting that the addressGenerator create chan %s.', passphrase)
        queues.addressGeneratorQueue.put((
            'createChan', addressVersionNumber, streamNumber, label,
            passphrase, True
        ))
        queueReturn = queues.apiAddressGeneratorReturnQueue.get()
        try:
            logger.debug("DEBUG: Created chan address")
            return queueReturn[0]
        except IndexError:
            logger.debug("DEBUG: Chan address already exists")
            raise APIError(24, 'Chan address is already present.')

    @command('joinChan')
    def HandleJoinChan(self, passphrase, suppliedAddress):
        """
        Join a chan. passphrase must be base64 encoded. Returns 'success'.
        """
        logger.debug("DEBUG: Handling joinChan for address %s", suppliedAddress)

        passphrase = self._decode(passphrase, "base64")
        if not passphrase:
            logger.debug("DEBUG: Blank passphrase")
            raise APIError(1, 'The specified passphrase is blank.')
        # It would be nice to make the label the passphrase but it is
        # possible that the passphrase contains non-utf-8 characters.
        try:
            passphrase.decode('utf-8')
            label = str_chan + ' ' + passphrase
        except UnicodeDecodeError:
            label = str_chan + ' ' + repr(passphrase)

        self._verifyAddress(suppliedAddress)
        suppliedAddress = addBMIfNotPresent(suppliedAddress)
        queues.apiAddressGeneratorReturnQueue.queue.clear()
        queues.addressGeneratorQueue.put((
            'joinChan', suppliedAddress, label, passphrase, True
        ))
        queueReturn = queues.apiAddressGeneratorReturnQueue.get()
        try:
            if queueReturn[0] == 'chan name does not match address':
                logger.debug("DEBUG: Chan name doesn't match address")
                raise APIError(18, 'Chan name does not match address.')
        except IndexError:
            logger.debug("DEBUG: Chan address already exists")
            raise APIError(24, 'Chan address is already present.')

        logger.debug("DEBUG: Successfully joined chan")
        return "success"

    @command('leaveChan')
    def HandleLeaveChan(self, address):
        """
        Leave a chan. Returns 'success'.

        .. note:: at this time, the address is still shown in the UI
          until a restart.
        """
        logger.debug("DEBUG: Handling leaveChan for address %s", address)
        self._verifyAddress(address)
        address = addBMIfNotPresent(address)
        if not self.config.safeGetBoolean(address, 'chan'):
            logger.debug("DEBUG: Address is not a chan address")
            raise APIError(
                25, 'Specified address is not a chan address.'
                ' Use deleteAddress API call instead.')
        try:
            self.config.remove_section(address)
        except configparser.NoSectionError:
            logger.debug("DEBUG: Address not found in keys.dat")
            raise APIError(
                13, 'Could not find this address in your keys.dat file.')
        self.config.save()
        queues.UISignalQueue.put(('rerenderMessagelistFromLabels', ''))
        queues.UISignalQueue.put(('rerenderMessagelistToLabels', ''))
        logger.debug("DEBUG: Successfully left chan")
        return "success"

    @command('deleteAddress')
    def HandleDeleteAddress(self, address):
        """
        Permanently delete the address from keys.dat file. Returns 'success'.
        """
        logger.debug("DEBUG: Handling deleteAddress for %s", address)
        self._verifyAddress(address)
        address = addBMIfNotPresent(address)
        try:
            self.config.remove_section(address)
        except configparser.NoSectionError:
            logger.debug("DEBUG: Address not found in keys.dat")
            raise APIError(
                13, 'Could not find this address in your keys.dat file.')
        self.config.save()
        queues.UISignalQueue.put(('writeNewAddressToTable', ('', '', '')))
        shared.reloadMyAddressHashes()
        logger.debug("DEBUG: Successfully deleted address")
        return "success"

    @command('enableAddress')
    def HandleEnableAddress(self, address, enable=True):
        """Enable or disable the address depending on the *enable* value"""
        logger.debug("DEBUG: Handling enableAddress for %s, enable: %s", address, enable)
        self._verifyAddress(address)
        address = addBMIfNotPresent(address)
        config.set(address, 'enabled', str(enable))
        self.config.save()
        shared.reloadMyAddressHashes()
        logger.debug("DEBUG: Successfully set address enabled state to %s", enable)
        return "success"

    @command('getAllInboxMessages')
    def HandleGetAllInboxMessages(self):
        """
        Returns a dict with all inbox messages in the *inboxMessages* key.
        The message is a dict with such keys:
        *msgid*, *toAddress*, *fromAddress*, *subject*, *message*,
        *encodingType*, *receivedTime*, *read*.
        *msgid* is hex encoded string.
        *subject* and *message* are base64 encoded.
        """
        logger.debug("DEBUG: Handling getAllInboxMessages")
        queryreturn = sqlQuery(
            "SELECT msgid, toaddress, fromaddress, subject, received, message,"
            " encodingtype, read FROM inbox WHERE folder='inbox'"
            " ORDER BY received"
        )
        result = {"inboxMessages": [
            self._dump_inbox_message(*data) for data in queryreturn
        ]}
        logger.debug("DEBUG: Found %d inbox messages", len(result["inboxMessages"]))
        return result

    @command('getAllInboxMessageIds', 'getAllInboxMessageIDs')
    def HandleGetAllInboxMessageIds(self):
        """
        The same as *getAllInboxMessages* but returns only *msgid*s,
        result key - *inboxMessageIds*.
        """
        logger.debug("DEBUG: Handling getAllInboxMessageIds")
        queryreturn = sqlQuery(
            "SELECT msgid FROM inbox where folder='inbox' ORDER BY received")

        result = {"inboxMessageIds": [
            {'msgid': hexlify(msgid)} for msgid, in queryreturn
        ]}
        logger.debug("DEBUG: Found %d inbox message IDs", len(result["inboxMessageIds"]))
        return result

    @command('getInboxMessageById', 'getInboxMessageByID')
    def HandleGetInboxMessageById(self, hid, readStatus=None):
        """
        Returns a dict with list containing single message in the result
        key *inboxMessage*. May also return None if message was not found.

        :param str hid: hex encoded msgid
        :param bool readStatus: sets the message's read status if present
        """
        logger.debug("DEBUG: Handling getInboxMessageById for %s", hid)
        msgid = self._decode(hid, "hex")
        if readStatus is not None:
            if not isinstance(readStatus, bool):
                logger.debug("DEBUG: Invalid type for readStatus")
                raise APIError(
                    23, 'Bool expected in readStatus, saw %s instead.'
                    % type(readStatus))
            queryreturn = sqlQuery(
                "SELECT read FROM inbox WHERE msgid=?", sqlite3.Binary(msgid))
            if len(queryreturn) < 1:
                queryreturn = sqlQuery(
                    "SELECT read FROM inbox WHERE msgid=CAST(? AS TEXT)", msgid)
            # UPDATE is slow, only update if status is different
            try:
                if (queryreturn[0][0] == 1) != readStatus:
                    rowcount = sqlExecute(
                        "UPDATE inbox set read = ? WHERE msgid=?",
                        readStatus, sqlite3.Binary(msgid))
                    if rowcount < 1:
                        rowcount = sqlExecute(
                            "UPDATE inbox set read = ? WHERE msgid=CAST(? AS TEXT)",
                            readStatus, msgid)
                    queues.UISignalQueue.put(('changedInboxUnread', None))
                    logger.debug("DEBUG: Updated read status for message")
            except IndexError:
                logger.debug("DEBUG: Message not found when updating read status")
                pass
        queryreturn = sqlQuery(
            "SELECT msgid, toaddress, fromaddress, subject, received, message,"
            " encodingtype, read FROM inbox WHERE msgid=?", sqlite3.Binary(msgid)
        )
        if len(queryreturn) < 1:
            queryreturn = sqlQuery(
                "SELECT msgid, toaddress, fromaddress, subject, received, message,"
                " encodingtype, read FROM inbox WHERE msgid=CAST(? AS TEXT)", msgid
            )
        try:
            logger.debug("DEBUG: Found message by ID")
            return {"inboxMessage": [
                self._dump_inbox_message(*queryreturn[0])]}
        except IndexError:
            logger.debug("DEBUG: Message not found by ID")
            pass  # FIXME inconsistent

    @command('getAllSentMessages')
    def HandleGetAllSentMessages(self):
        """
        The same as *getAllInboxMessages* but for sent,
        result key - *sentMessages*. Message dict keys are:
        *msgid*, *toAddress*, *fromAddress*, *subject*, *message*,
        *encodingType*, *lastActionTime*, *status*, *ackData*.
        *ackData* is also a hex encoded string.
        """
        logger.debug("DEBUG: Handling getAllSentMessages")
        queryreturn = sqlQuery(
            "SELECT msgid, toaddress, fromaddress, subject, lastactiontime,"
            " message, encodingtype, status, ackdata FROM sent"
            " WHERE folder='sent' ORDER BY lastactiontime"
        )
        result = {"sentMessages": [
            self._dump_sent_message(*data) for data in queryreturn
        ]}
        logger.debug("DEBUG: Found %d sent messages", len(result["sentMessages"]))
        return result

    @command('getAllSentMessageIds', 'getAllSentMessageIDs')
    def HandleGetAllSentMessageIds(self):
        """
        The same as *getAllInboxMessageIds* but for sent,
        result key - *sentMessageIds*.
        """
        logger.debug("DEBUG: Handling getAllSentMessageIds")
        queryreturn = sqlQuery(
            "SELECT msgid FROM sent WHERE folder='sent'"
            " ORDER BY lastactiontime"
        )
        result = {"sentMessageIds": [
            {'msgid': hexlify(msgid)} for msgid, in queryreturn
        ]}
        logger.debug("DEBUG: Found %d sent message IDs", len(result["sentMessageIds"]))
        return result

    # after some time getInboxMessagesByAddress should be removed
    @command('getInboxMessagesByReceiver', 'legacy:getInboxMessagesByAddress')
    def HandleInboxMessagesByReceiver(self, toAddress):
        """
        The same as *getAllInboxMessages* but returns only messages
        for toAddress.
        """
        logger.debug("DEBUG: Handling getInboxMessagesByReceiver for %s", toAddress)
        queryreturn = sqlQuery(
            "SELECT msgid, toaddress, fromaddress, subject, received,"
            " message, encodingtype, read FROM inbox WHERE folder='inbox'"
            " AND toAddress=?", dbstr(toAddress))
        result = {"inboxMessages": [
            self._dump_inbox_message(*data) for data in queryreturn
        ]}
        logger.debug("DEBUG: Found %d messages for receiver", len(result["inboxMessages"]))
        return result

    @command('getSentMessageById', 'getSentMessageByID')
    def HandleGetSentMessageById(self, hid):
        """
        Similiar to *getInboxMessageById* but doesn't change message's
        read status (sent messages have no such field).
        Result key is *sentMessage*
        """
        logger.debug("DEBUG: Handling getSentMessageById for %s", hid)
        msgid = self._decode(hid, "hex")
        queryreturn = sqlQuery(
            "SELECT msgid, toaddress, fromaddress, subject, lastactiontime,"
            " message, encodingtype, status, ackdata FROM sent WHERE msgid=?",
            sqlite3.Binary(msgid)
        )
        if len(queryreturn) < 1:
            queryreturn = sqlQuery(
                "SELECT msgid, toaddress, fromaddress, subject, lastactiontime,"
                " message, encodingtype, status, ackdata FROM sent WHERE msgid=CAST(? AS TEXT)",
                msgid
            )
        try:
            logger.debug("DEBUG: Found sent message by ID")
            return {"sentMessage": [
                self._dump_sent_message(*queryreturn[0])
            ]}
        except IndexError:
            logger.debug("DEBUG: Sent message not found by ID")
            pass  # FIXME inconsistent

    @command('getSentMessagesByAddress', 'getSentMessagesBySender')
    def HandleGetSentMessagesByAddress(self, fromAddress):
        """
        The same as *getAllSentMessages* but returns only messages
        from fromAddress.
        """
        logger.debug("DEBUG: Handling getSentMessagesByAddress for %s", fromAddress)
        queryreturn = sqlQuery(
            "SELECT msgid, toaddress, fromaddress, subject, lastactiontime,"
            " message, encodingtype, status, ackdata FROM sent"
            " WHERE folder='sent' AND fromAddress=? ORDER BY lastactiontime",
            dbstr(fromAddress)
        )
        result = {"sentMessages": [
            self._dump_sent_message(*data) for data in queryreturn
        ]}
        logger.debug("DEBUG: Found %d messages from sender", len(result["sentMessages"]))
        return result

    @command('getSentMessageByAckData')
    def HandleGetSentMessagesByAckData(self, ackData):
        """
        Similiar to *getSentMessageById* but searches by ackdata
        (also hex encoded).
        """
        logger.debug("DEBUG: Handling getSentMessagesByAckData for %s", ackData)
        ackData = self._decode(ackData, "hex")
        queryreturn = sqlQuery(
            "SELECT msgid, toaddress, fromaddress, subject, lastactiontime,"
            " message, encodingtype, status, ackdata FROM sent"
            " WHERE ackdata=?", sqlite3.Binary(ackData)
        )
        if len(queryreturn) < 1:
            queryreturn = sqlQuery(
                "SELECT msgid, toaddress, fromaddress, subject, lastactiontime,"
                " message, encodingtype, status, ackdata FROM sent"
                " WHERE ackdata=CAST(? AS TEXT)", ackData
            )

        try:
            logger.debug("DEBUG: Found sent message by ackdata")
            return {"sentMessage": [
                self._dump_sent_message(*queryreturn[0])
            ]}
        except IndexError:
            logger.debug("DEBUG: Sent message not found by ackdata")
            pass  # FIXME inconsistent

    @command('trashMessage')
    def HandleTrashMessage(self, msgid):
        """
        Trash message by msgid (encoded in hex). Returns a simple message
        saying that the message was trashed assuming it ever even existed.
        Prior existence is not checked.
        """
        logger.debug("DEBUG: Handling trashMessage for %s", msgid)
        msgid = self._decode(msgid, "hex")
        # Trash if in inbox table
        helper_inbox.trash(msgid)
        # Trash if in sent table
        rowcount = sqlExecute("UPDATE sent SET folder='trash' WHERE msgid=?", sqlite3.Binary(msgid))
        if rowcount < 1:
            sqlExecute("UPDATE sent SET folder='trash' WHERE msgid=CAST(? AS TEXT)", msgid)
        logger.debug("DEBUG: Trashed message")
        return 'Trashed message (assuming message existed).'

    @command('trashInboxMessage')
    def HandleTrashInboxMessage(self, msgid):
        """Trash inbox message by msgid (encoded in hex)."""
        logger.debug("DEBUG: Handling trashInboxMessage for %s", msgid)
        msgid = self._decode(msgid, "hex")
        helper_inbox.trash(msgid)
        logger.debug("DEBUG: Trashed inbox message")
        return 'Trashed inbox message (assuming message existed).'

    @command('trashSentMessage')
    def HandleTrashSentMessage(self, msgid):
        """Trash sent message by msgid (encoded in hex)."""
        logger.debug("DEBUG: Handling trashSentMessage for %s", msgid)
        msgid = self._decode(msgid, "hex")
        rowcount = sqlExecute('''UPDATE sent SET folder='trash' WHERE msgid=?''', sqlite3.Binary(msgid))
        if rowcount < 1:
            sqlExecute('''UPDATE sent SET folder='trash' WHERE msgid=CAST(? AS TEXT)''', msgid)
        logger.debug("DEBUG: Trashed sent message")
        return 'Trashed sent message (assuming message existed).'

    @command('sendMessage')
    def HandleSendMessage(
        self, toAddress, fromAddress, subject, message,
        encodingType=2, TTL=4 * 24 * 60 * 60
    ):
        """
        Send the message and return ackdata (hex encoded string).
        subject and message must be encoded in base64 which may optionally
        include line breaks. TTL is specified in seconds; values outside
        the bounds of 3600 to 2419200 will be moved to be within those
        bounds. TTL defaults to 4 days.
        """
        # pylint: disable=too-many-locals
        logger.debug("DEBUG: Handling sendMessage from %s to %s", fromAddress, toAddress)
        if encodingType not in (2, 3):
            logger.debug("DEBUG: Invalid encoding type")
            raise APIError(6, 'The encoding type must be 2 or 3.')
        subject = self._decode(subject, "base64")
        message = self._decode(message, "base64")
        if len(subject + message) > (2 ** 18 - 500):
            logger.debug("DEBUG: Message too long")
            raise APIError(27, 'Message is too long.')
        if TTL < 60 * 60:
            TTL = 60 * 60
        if TTL > 28 * 24 * 60 * 60:
            TTL = 28 * 24 * 60 * 60
        toAddress = addBMIfNotPresent(toAddress)
        fromAddress = addBMIfNotPresent(fromAddress)
        self._verifyAddress(fromAddress)
        try:
            fromAddressEnabled = self.config.getboolean(fromAddress, 'enabled')
        except configparser.NoSectionError:
            logger.debug("DEBUG: From address not found in keys.dat")
            raise APIError(
                13, 'Could not find your fromAddress in the keys.dat file.')
        if not fromAddressEnabled:
            logger.debug("DEBUG: From address is disabled")
            raise APIError(14, 'Your fromAddress is disabled. Cannot send.')

        ackdata = helper_sent.insert(
            toAddress=toAddress, fromAddress=fromAddress,
            subject=subject, message=message, encoding=encodingType, ttl=TTL)

        toLabel = ''
        queryreturn = sqlQuery(
            "SELECT label FROM addressbook WHERE address=?", dbstr(toAddress))
        try:
            toLabel = queryreturn[0][0].decode("utf-8", "replace")
        except IndexError:
            pass

        queues.UISignalQueue.put(('displayNewSentMessage', (
            toAddress, toLabel, fromAddress, subject, message, ackdata)))
        queues.workerQueue.put(('sendmessage', toAddress))

        logger.debug("DEBUG: Successfully sent message, ackdata: %s", hexlify(ackdata))
        return hexlify(ackdata)

    @command('sendBroadcast')
    def HandleSendBroadcast(
        self, fromAddress, subject, message, encodingType=2,
            TTL=4 * 24 * 60 * 60):
        """Send the broadcast message. Similiar to *sendMessage*."""
        logger.debug("DEBUG: Handling sendBroadcast from %s", fromAddress)

        if encodingType not in (2, 3):
            logger.debug("DEBUG: Invalid encoding type")
            raise APIError(6, 'The encoding type must be 2 or 3.')

        subject = self._decode(subject, "base64")
        message = self._decode(message, "base64")
        if len(subject + message) > (2 ** 18 - 500):
            logger.debug("DEBUG: Message too long")
            raise APIError(27, 'Message is too long.')
        if TTL < 60 * 60:
            TTL = 60 * 60
        if TTL > 28 * 24 * 60 * 60:
            TTL = 28 * 24 * 60 * 60
        fromAddress = addBMIfNotPresent(fromAddress)
        self._verifyAddress(fromAddress)
        try:
            fromAddressEnabled = self.config.getboolean(fromAddress, 'enabled')
        except configparser.NoSectionError:
            logger.debug("DEBUG: From address not found in keys.dat")
            raise APIError(
                13, 'Could not find your fromAddress in the keys.dat file.')
        if not fromAddressEnabled:
            logger.debug("DEBUG: From address is disabled")
            raise APIError(14, 'Your fromAddress is disabled. Cannot send.')

        toAddress = str_broadcast_subscribers

        ackdata = helper_sent.insert(
            fromAddress=fromAddress, subject=subject,
            message=message, status='broadcastqueued',
            encoding=encodingType)

        toLabel = str_broadcast_subscribers
        queues.UISignalQueue.put(('displayNewSentMessage', (
            toAddress, toLabel, fromAddress, subject, message, ackdata)))
        queues.workerQueue.put(('sendbroadcast', ''))

        logger.debug("DEBUG: Successfully sent broadcast, ackdata: %s", hexlify(ackdata))
        return hexlify(ackdata)

    @command('getStatus')
    def HandleGetStatus(self, ackdata):
        """
        Get the status of sent message by its ackdata (hex encoded).
        Returns one of these strings: notfound, msgqueued,
        broadcastqueued, broadcastsent, doingpubkeypow, awaitingpubkey,
        doingmsgpow, forcepow, msgsent, msgsentnoackexpected or ackreceived.
        """
        logger.debug("DEBUG: Handling getStatus for %s", ackdata)

        if len(ackdata) < 76:
            # The length of ackData should be at least 38 bytes (76 hex digits)
            logger.debug("DEBUG: Invalid ackdata size")
            raise APIError(15, 'Invalid ackData object size.')
        ackdata = self._decode(ackdata, "hex")
        queryreturn = sqlQuery(
            "SELECT status FROM sent where ackdata=?", sqlite3.Binary(ackdata))
        if len(queryreturn) < 1:
            queryreturn = sqlQuery(
                "SELECT status FROM sent where ackdata=CAST(? AS TEXT)", ackdata)
        try:
            status = queryreturn[0][0].decode("utf-8", "replace")
            logger.debug("DEBUG: Message status: %s", status)
            return status
        except IndexError:
            logger.debug("DEBUG: Message not found")
            return 'notfound'

    @command('addSubscription')
    def HandleAddSubscription(self, address, label=''):
        """Subscribe to the address. label must be base64 encoded."""
        logger.debug("DEBUG: Handling addSubscription for %s", address)

        if label:
            label = self._decode(label, "base64")
            try:
                label.decode('utf-8')
            except UnicodeDecodeError:
                logger.debug("DEBUG: Label is not valid UTF-8")
                raise APIError(17, 'Label is not valid UTF-8 data.')
        self._verifyAddress(address)
        address = addBMIfNotPresent(address)
        # First we must check to see if the address is already in the
        # subscriptions list.
        queryreturn = sqlQuery(
            "SELECT * FROM subscriptions WHERE address=?", dbstr(address))
        if queryreturn:
            logger.debug("DEBUG: Already subscribed to address")
            raise APIError(16, 'You are already subscribed to that address.')
        sqlExecute(
            "INSERT INTO subscriptions VALUES (?,?,?)", dbstr(label), dbstr(address), True)
        shared.reloadBroadcastSendersForWhichImWatching()
        queues.UISignalQueue.put(('rerenderMessagelistFromLabels', ''))
        queues.UISignalQueue.put(('rerenderSubscriptions', ''))
        logger.debug("DEBUG: Successfully added subscription")
        return 'Added subscription.'

    @command('deleteSubscription')
    def HandleDeleteSubscription(self, address):
        """
        Unsubscribe from the address. The program does not check whether
        you were subscribed in the first place.
        """
        logger.debug("DEBUG: Handling deleteSubscription for %s", address)

        address = addBMIfNotPresent(address)
        sqlExecute("DELETE FROM subscriptions WHERE address=?", dbstr(address))
        shared.reloadBroadcastSendersForWhichImWatching()
        queues.UISignalQueue.put(('rerenderMessagelistFromLabels', ''))
        queues.UISignalQueue.put(('rerenderSubscriptions', ''))
        logger.debug("DEBUG: Successfully deleted subscription")
        return 'Deleted subscription if it existed.'

    @command('listSubscriptions')
    def ListSubscriptions(self):
        """
        Returns dict with a list of all subscriptions
        in the *subscriptions* key.
        """
        logger.debug("DEBUG: Handling listSubscriptions")
        queryreturn = sqlQuery(
            "SELECT label, address, enabled FROM subscriptions")
        data = []
        for label, address, enabled in queryreturn:
            label = shared.fixPotentiallyInvalidUTF8Data(label)
            address = address.decode("utf-8", "replace")
            data.append({
                'label': base64.b64encode(label),
                'address': address,
                'enabled': enabled == 1
            })
        logger.debug("DEBUG: Found %d subscriptions", len(data))
        return {'subscriptions': data}

    @command('disseminatePreEncryptedMsg', 'disseminatePreparedObject')
    def HandleDisseminatePreparedObject(
        self, encryptedPayload,
        nonceTrialsPerByte=networkDefaultProofOfWorkNonceTrialsPerByte,
        payloadLengthExtraBytes=networkDefaultPayloadLengthExtraBytes
    ):
        """
        Handle a request to disseminate an encrypted message.

        The device issuing this command to PyBitmessage supplies an object
        that has already been encrypted but which may still need the PoW
        to be done. PyBitmessage accepts this object and sends it out
        to the rest of the Bitmessage network as if it had generated
        the message itself.

        *encryptedPayload* is a hex encoded string starting with the nonce,
        8 zero bytes in case of no PoW done.
        """
        logger.debug("DEBUG: Handling disseminatePreparedObject")
        encryptedPayload = self._decode(encryptedPayload, "hex")

        nonce, = unpack('>Q', encryptedPayload[:8])
        objectType, toStreamNumber, expiresTime = \
            protocol.decodeObjectParameters(encryptedPayload)

        if nonce == 0:  # Let us do the POW and attach it to the front
            encryptedPayload = encryptedPayload[8:]
            TTL = expiresTime - time.time() + 300  # a bit of extra padding
            # Let us do the POW and attach it to the front
            logger.debug("expiresTime: %s", expiresTime)
            logger.debug("TTL: %s", TTL)
            logger.debug("objectType: %s", objectType)
            logger.info(
                '(For msg message via API) Doing proof of work. Total required'
                ' difficulty: %s\nRequired small message difficulty: %s',
                float(nonceTrialsPerByte)
                / networkDefaultProofOfWorkNonceTrialsPerByte,
                float(payloadLengthExtraBytes)
                / networkDefaultPayloadLengthExtraBytes,
            )
            powStartTime = time.time()
            target = 2**64 / (
                nonceTrialsPerByte * (
                    len(encryptedPayload) + 8 + payloadLengthExtraBytes + ((
                        TTL * (
                            len(encryptedPayload) + 8 + payloadLengthExtraBytes
                        )) / (2 ** 16))
                ))
            initialHash = hashlib.sha512(encryptedPayload).digest()
            trialValue, nonce = proofofwork.run(target, initialHash)
            logger.info(
                '(For msg message via API) Found proof of work %s\nNonce: %s\n'
                'POW took %s seconds. %s nonce trials per second.',
                trialValue, nonce, int(time.time() - powStartTime),
                nonce / (time.time() - powStartTime)
            )
            encryptedPayload = pack('>Q', nonce) + encryptedPayload

        inventoryHash = calculateInventoryHash(encryptedPayload)
        state.Inventory[inventoryHash] = (
            objectType, toStreamNumber, encryptedPayload,
            expiresTime, b''
        )
        logger.info(
            'Broadcasting inv for msg(API disseminatePreEncryptedMsg'
            ' command): %s', hexlify(inventoryHash))
        invQueue.put((toStreamNumber, inventoryHash))
        logger.debug("DEBUG: Disseminated object with hash: %s", hexlify(inventoryHash))
        return hexlify(inventoryHash).decode()

    @command('trashSentMessageByAckData')
    def HandleTrashSentMessageByAckDAta(self, ackdata):
        """Trash a sent message by ackdata (hex encoded)"""
        logger.debug("DEBUG: Handling trashSentMessageByAckData for %s", ackdata)
        # This API method should only be used when msgid is not available
        ackdata = self._decode(ackdata, "hex")
        rowcount = sqlExecute("UPDATE sent SET folder='trash' WHERE ackdata=?", sqlite3.Binary(ackdata))
        if rowcount < 1:
            sqlExecute("UPDATE sent SET folder='trash' WHERE ackdata=CAST(? AS TEXT)", ackdata)
        logger.debug("DEBUG: Trashed sent message by ackdata")
        return 'Trashed sent message (assuming message existed).'

    @command('disseminatePubkey')
    def HandleDissimatePubKey(self, payload):
        """Handle a request to disseminate a public key"""
        logger.debug("DEBUG: Handling disseminatePubkey")

        # The device issuing this command to PyBitmessage supplies a pubkey
        # object to be disseminated to the rest of the Bitmessage network.
        # PyBitmessage accepts this pubkey object and sends it out to the rest
        # of the Bitmessage network as if it had generated the pubkey object
        # itself. Please do not yet add this to the api doc.
        payload = self._decode(payload, "hex")

        # Let us do the POW
        target = 2 ** 64 / ((
            len(payload) + networkDefaultPayloadLengthExtraBytes + 8
        ) * networkDefaultProofOfWorkNonceTrialsPerByte)
        logger.info('(For pubkey message via API) Doing proof of work...')
        initialHash = hashlib.sha512(payload).digest()
        trialValue, nonce = proofofwork.run(target, initialHash)
        logger.info(
            '(For pubkey message via API) Found proof of work %s Nonce: %s',
            trialValue, nonce
        )
        payload = pack('>Q', nonce) + payload

        pubkeyReadPosition = 8  # bypass the nonce
        if payload[pubkeyReadPosition:pubkeyReadPosition + 4] == \
                '\x00\x00\x00\x00':  # if this pubkey uses 8 byte time
            pubkeyReadPosition += 8
        else:
            pubkeyReadPosition += 4
        addressVersionLength = decodeVarint(
            payload[pubkeyReadPosition:pubkeyReadPosition + 10])[1]
        pubkeyReadPosition += addressVersionLength
        pubkeyStreamNumber = decodeVarint(
            payload[pubkeyReadPosition:pubkeyReadPosition + 10])[0]
        inventoryHash = calculateInventoryHash(payload)
        objectType = 1  # .. todo::: support v4 pubkeys
        TTL = 28 * 24 * 60 * 60
        state.Inventory[inventoryHash] = (
            objectType, pubkeyStreamNumber, payload, int(time.time()) + TTL, ''
        )
        logger.info(
            'broadcasting inv within API command disseminatePubkey with'
            ' hash: %s', hexlify(inventoryHash))
        invQueue.put((pubkeyStreamNumber, inventoryHash))
        logger.debug("DEBUG: Disseminated pubkey with hash: %s", hexlify(inventoryHash))

    @command(
        'getMessageDataByDestinationHash', 'getMessageDataByDestinationTag')
    def HandleGetMessageDataByDestinationHash(self, requestedHash):
        """Handle a request to get message data by destination hash"""
        logger.debug("DEBUG: Handling getMessageDataByDestinationHash for %s", requestedHash)

        # Method will eventually be used by a particular Android app to
        # select relevant messages. Do not yet add this to the api
        # doc.
        if len(requestedHash) != 32:
            logger.debug("DEBUG: Invalid hash length")
            raise APIError(
                19, 'The length of hash should be 32 bytes (encoded in hex'
                ' thus 64 characters).')
        requestedHash = self._decode(requestedHash, "hex")

        # This is not a particularly commonly used API function. Before we
        # use it we'll need to fill out a field in our inventory database
        # which is blank by default (first20bytesofencryptedmessage).
        queryreturn = sqlQuery(
            "SELECT hash, payload FROM inventory WHERE tag = ?"
            " and objecttype = 2", sqlite3.Binary(b""))
        if len(queryreturn) < 1:
            queryreturn = sqlQuery(
                "SELECT hash, payload FROM inventory WHERE tag = CAST(? AS TEXT)"
                " and objecttype = 2", b"")
        with SqlBulkExecute() as sql:
            for hash01, payload in queryreturn:
                readPosition = 16  # Nonce length + time length
                # Stream Number length
                readPosition += decodeVarint(
                    payload[readPosition:readPosition + 10])[1]
                t = (sqlite3.Binary(payload[readPosition:readPosition + 32]), sqlite3.Binary(hash01))
                _, rowcount = sql.execute("UPDATE inventory SET tag=? WHERE hash=?", *t)
                if rowcount < 1:
                    t = (sqlite3.Binary(payload[readPosition:readPosition + 32]), hash01)
                    sql.execute("UPDATE inventory SET tag=? WHERE hash=CAST(? AS TEXT)", *t)

        queryreturn = sqlQuery(
            "SELECT payload FROM inventory WHERE tag = ?", sqlite3.Binary(requestedHash))
        if len(queryreturn) < 1:
            queryreturn = sqlQuery(
                "SELECT payload FROM inventory WHERE tag = CAST(? AS TEXT)", requestedHash)
        result = {"receivedMessageDatas": [
            {'data': hexlify(payload)} for payload, in queryreturn
        ]}
        logger.debug("DEBUG: Found %d messages by destination hash", len(result["receivedMessageDatas"]))
        return result

    @command('clientStatus')
    def HandleClientStatus(self):
        """
        Returns the bitmessage status as dict with keys *networkConnections*,
        *numberOfMessagesProcessed*, *numberOfBroadcastsProcessed*,
        *numberOfPubkeysProcessed*, *pendingDownload*, *networkStatus*,
        *softwareName*, *softwareVersion*. *networkStatus* will be one of
        these strings: "notConnected",
        "connectedButHaveNotReceivedIncomingConnections",
        or "connectedAndReceivingIncomingConnections".
        """
        logger.debug("DEBUG: Handling clientStatus")
        connections_num = len(stats.connectedHostsList())

        if connections_num == 0:
            networkStatus = 'notConnected'
        elif state.clientHasReceivedIncomingConnections:
            networkStatus = 'connectedAndReceivingIncomingConnections'
        else:
            networkStatus = 'connectedButHaveNotReceivedIncomingConnections'
        result = {
            'networkConnections': connections_num,
            'numberOfMessagesProcessed': state.numberOfMessagesProcessed,
            'numberOfBroadcastsProcessed': state.numberOfBroadcastsProcessed,
            'numberOfPubkeysProcessed': state.numberOfPubkeysProcessed,
            'pendingDownload': stats.pendingDownload(),
            'networkStatus': networkStatus,
            'softwareName': 'PyBitmessage',
            'softwareVersion': softwareVersion
        }
        logger.debug("DEBUG: Client status: %s", result)
        return result

    @command('listConnections')
    def HandleListConnections(self):
        """
        Returns bitmessage connection information as dict with keys *inbound*,
        *outbound*.
        """
        logger.debug("DEBUG: Handling listConnections")
        if connectionpool is None:
            logger.debug("DEBUG: BMConnectionPool not available")
            raise APIError(21, 'Could not import BMConnectionPool.')
        inboundConnections = []
        outboundConnections = []
        for i in connectionpool.pool.inboundConnections.values():
            inboundConnections.append({
                'host': i.destination.host,
                'port': i.destination.port,
                'fullyEstablished': i.fullyEstablished,
                'userAgent': str(i.userAgent)
            })
        for i in connectionpool.pool.outboundConnections.values():
            outboundConnections.append({
                'host': i.destination.host,
                'port': i.destination.port,
                'fullyEstablished': i.fullyEstablished,
                'userAgent': str(i.userAgent)
            })
        result = {
            'inbound': inboundConnections,
            'outbound': outboundConnections
        }
        logger.debug("DEBUG: Found %d inbound and %d outbound connections", 
                   len(result['inbound']), len(result['outbound']))
        return result

    @command('helloWorld')
    def HandleHelloWorld(self, a, b):
        """Test two string params"""
        logger.debug("DEBUG: Handling helloWorld with %s and %s", a, b)
        return a + '-' + b

    @command('add')
    def HandleAdd(self, a, b):
        """Test two numeric params"""
        logger.debug("DEBUG: Handling add with %s and %s", a, b)
        return a + b

    @command('statusBar')
    def HandleStatusBar(self, message):
        """Update GUI statusbar message"""
        logger.debug("DEBUG: Handling statusBar with message: %s", message)
        queues.UISignalQueue.put(('updateStatusBar', message))
        return "success"

    @testmode('undeleteMessage')
    def HandleUndeleteMessage(self, msgid):
        """Undelete message"""
        logger.debug("DEBUG: Handling undeleteMessage for %s", msgid)
        msgid = self._decode(msgid, "hex")
        helper_inbox.undeleteMessage(msgid)
        return "Undeleted message"

    @command('deleteAndVacuum')
    def HandleDeleteAndVacuum(self):
        """Cleanup trashes and vacuum messages database"""
        logger.debug("DEBUG: Handling deleteAndVacuum")
        sqlStoredProcedure('deleteandvacuume')
        return 'done'

    @command('shutdown')
    def HandleShutdown(self):
        """Shutdown the bitmessage. Returns 'done'."""
        logger.debug("DEBUG: Handling shutdown")
        # backward compatible trick because False == 0 is True
        state.shutdown = False
        return 'done'

    def _handle_request(self, method, params):
        try:
            # pylint: disable=attribute-defined-outside-init
            self._method = method
            logger.debug("DEBUG: Handling request for method %s with params %s", method, params)
            func = self._handlers[method]
            result = func(self, *params)
            logger.debug("DEBUG: Method %s returned: %s", method, result)
            return result
        except KeyError:
            logger.debug("DEBUG: Invalid method requested: %s", method)
            raise APIError(20, 'Invalid method: %s' % method)
        except TypeError as e:
            msg = 'Unexpected API Failure - %s' % e
            if 'argument' not in str(e):
                logger.debug("DEBUG: Unexpected API failure: %s", msg)
                raise APIError(21, msg)
            argcount = len(params)
            maxcount = func.func_code.co_argcount
            if argcount > maxcount:
                msg = (
                    'Command %s takes at most %s parameters (%s given)'
                    % (method, maxcount, argcount))
            else:
                mincount = maxcount - len(func.func_defaults or [])
                if argcount < mincount:
                    msg = (
                        'Command %s takes at least %s parameters (%s given)'
                        % (method, mincount, argcount))
            logger.debug("DEBUG: Parameter count mismatch: %s", msg)
            raise APIError(0, msg)
        finally:
            state.last_api_response = time.time()
            logger.debug("DEBUG: Updated last API response time")

    def _dispatch(self, method, params):
        _fault = None

        try:
            return self._handle_request(method, params)
        except APIError as e:
            _fault = e
            logger.debug("DEBUG: APIError occurred: %s", str(e))
        except varintDecodeError as e:
            logger.error(e)
            _fault = APIError(
                26, 'Data contains a malformed varint. Some details: %s' % e)
            logger.debug("DEBUG: Varint decode error occurred: %s", str(e))
        except Exception as e:
            logger.exception(e)
            _fault = APIError(21, 'Unexpected API Failure - %s' % e)
            logger.debug("DEBUG: Unexpected error occurred: %s", str(e))

        if _fault:
            if self.config.safeGet(
                    'bitmessagesettings', 'apivariant') == 'legacy':
                logger.debug("DEBUG: Returning legacy error format")
                return str(_fault)
            else:
                logger.debug("DEBUG: Raising APIError")
                raise _fault  # pylint: disable=raising-bad-type

    def _listMethods(self):
        """List all API commands"""
        logger.debug("DEBUG: Listing all API methods")
        return self._handlers.keys()

    def _methodHelp(self, method):
        logger.debug("DEBUG: Getting help for method %s", method)
        return self._handlers[method].__doc__
