"""
Startup operations.
"""
# pylint: disable=too-many-branches,too-many-statements

import ctypes
import logging
import os
import platform
import socket
import sys
import time
from distutils.version import StrictVersion
from struct import pack
from six.moves import configparser
if sys.platform.startswith('openbsd'):
    socket.has_ipv6 = False  # Informiert andere Module, dass IPv6 nicht verfügbar ist
    socket.AF_INET6 = None   # Deaktiviert IPv6 komplett
    socket.IPPROTO_IPV6 = None
    socket.IPV6_V6ONLY = None


try:
    import defaults
    import helper_random
    import paths
    import state
    from bmconfigparser import config, config_ready
except ImportError:
    from . import defaults, helper_random, paths, state
    from .bmconfigparser import config, config_ready

try:
    from plugins.plugin import get_plugin
except ImportError:
    get_plugin = None


logger = logging.getLogger('default')

# The user may de-select Portable Mode in the settings if they want
# the config files to stay in the application data folder.
StoreConfigFilesInSameDirectoryAsProgramByDefault = False


def loadConfig():
    """Load the config"""
    logger.debug("DEBUG: Entering loadConfig()")
    
    if state.appdata:
        logger.debug("DEBUG: appdata path is already set: %s", state.appdata)
        config.read(state.appdata + 'keys.dat')
        needToCreateKeysFile = config.safeGet(
            'bitmessagesettings', 'settingsversion') is None
        if not needToCreateKeysFile:
            logger.debug("DEBUG: Loading existing config from startup directory")
            logger.info(
                'Loading config files from directory specified'
                ' on startup: %s', state.appdata)
    else:
        logger.debug("DEBUG: No appdata path set, looking in exe folder")
        config.read(paths.lookupExeFolder() + 'keys.dat')

        if config.safeGet('bitmessagesettings', 'settingsversion'):
            logger.debug("DEBUG: Found valid config in exe folder")
            logger.info('Loading config files from same directory as program.')
            needToCreateKeysFile = False
            state.appdata = paths.lookupExeFolder()
        else:
            logger.debug("DEBUG: No config in exe folder, trying appdata")
            state.appdata = paths.lookupAppdataFolder()
            config.read(state.appdata + 'keys.dat')
            needToCreateKeysFile = config.safeGet(
                'bitmessagesettings', 'settingsversion') is None
            if not needToCreateKeysFile:
                logger.debug("DEBUG: Found valid config in appdata folder")
                logger.info(
                    'Loading existing config files from %s', state.appdata)

    if needToCreateKeysFile:
        logger.debug("DEBUG: Need to create new config file")
        config.read()
        config.set('bitmessagesettings', 'settingsversion', '10')
        
        if 'linux' in sys.platform:
            logger.debug("DEBUG: Linux platform detected")
            config.set('bitmessagesettings', 'minimizetotray', 'false')
        else:
            logger.debug("DEBUG: Non-Linux platform detected")
            config.set('bitmessagesettings', 'minimizetotray', 'true')
            
        config.set(
            'bitmessagesettings', 'defaultnoncetrialsperbyte',
            str(defaults.networkDefaultProofOfWorkNonceTrialsPerByte))
        config.set(
            'bitmessagesettings', 'defaultpayloadlengthextrabytes',
            str(defaults.networkDefaultPayloadLengthExtraBytes))
        config.set('bitmessagesettings', 'dontconnect', 'true')

        if StoreConfigFilesInSameDirectoryAsProgramByDefault:
            logger.debug("DEBUG: Using program directory for config")
            state.appdata = ''
            logger.info(
                'Creating new config files in same directory as program.')
        else:
            logger.debug("DEBUG: Using appdata directory for config")
            logger.info('Creating new config files in %s', state.appdata)
            if not os.path.exists(state.appdata):
                logger.debug("DEBUG: Creating appdata directory")
                os.makedirs(state.appdata)
                
        if not sys.platform.startswith('win'):
            logger.debug("DEBUG: Setting umask for non-Windows platform")
            os.umask(0o077)
            
        config.save()
        logger.debug("DEBUG: New config file created and saved")
    else:
        logger.debug("DEBUG: Existing config found, updating if needed")
        updateConfig()
        
    config_ready.set()
    logger.debug("DEBUG: Exiting loadConfig()")


def updateConfig():
    """Save the config"""
    logger.debug("DEBUG: Entering updateConfig()")
    
    settingsversion = config.getint('bitmessagesettings', 'settingsversion')
    logger.debug("DEBUG: Current settings version: %d", settingsversion)
    
    if settingsversion == 1:
        logger.debug("DEBUG: Upgrading from version 1 to 2")
        config.set('bitmessagesettings', 'socksproxytype', 'none')
        config.set('bitmessagesettings', 'sockshostname', 'localhost')
        config.set('bitmessagesettings', 'socksport', '9050')
        config.set('bitmessagesettings', 'socksauthentication', 'false')
        config.set('bitmessagesettings', 'socksusername', '')
        config.set('bitmessagesettings', 'sockspassword', '')
        config.set('bitmessagesettings', 'sockslisten', 'false')
        config.set('bitmessagesettings', 'keysencrypted', 'false')
        config.set('bitmessagesettings', 'messagesencrypted', 'false')
        settingsversion = 2
        
    elif settingsversion == 4:
        logger.debug("DEBUG: Upgrading from version 4 to 5")
        config.set(
            'bitmessagesettings', 'defaultnoncetrialsperbyte',
            str(defaults.networkDefaultProofOfWorkNonceTrialsPerByte))
        config.set(
            'bitmessagesettings', 'defaultpayloadlengthextrabytes',
            str(defaults.networkDefaultPayloadLengthExtraBytes))
        settingsversion = 5

    if settingsversion == 5:
        logger.debug("DEBUG: Upgrading from version 5 to 7")
        config.set(
            'bitmessagesettings', 'maxacceptablenoncetrialsperbyte', '0')
        config.set(
            'bitmessagesettings', 'maxacceptablepayloadlengthextrabytes', '0')
        settingsversion = 7

    if not config.has_option('bitmessagesettings', 'sockslisten'):
        logger.debug("DEBUG: Adding missing sockslisten option")
        config.set('bitmessagesettings', 'sockslisten', 'false')

    if not config.has_option('bitmessagesettings', 'userlocale'):
        logger.debug("DEBUG: Adding missing userlocale option")
        config.set('bitmessagesettings', 'userlocale', 'system')

    if not config.has_option('bitmessagesettings', 'sendoutgoingconnections'):
        logger.debug("DEBUG: Adding missing sendoutgoingconnections option")
        config.set('bitmessagesettings', 'sendoutgoingconnections', 'True')

    if not config.has_option('bitmessagesettings', 'useidenticons'):
        logger.debug("DEBUG: Adding missing useidenticons option")
        config.set('bitmessagesettings', 'useidenticons', 'True')
        
    if not config.has_option('bitmessagesettings', 'identiconsuffix'):
        logger.debug("DEBUG: Adding missing identiconsuffix option")
        config.set(
            'bitmessagesettings', 'identiconsuffix', ''.join(
                helper_random.randomchoice(
                    "123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
                    "abcdefghijkmnopqrstuvwxyz") for x in range(12))
        )

    if settingsversion == 7:
        logger.debug("DEBUG: Upgrading from version 7 to 8")
        config.set('bitmessagesettings', 'stopresendingafterxdays', '')
        config.set('bitmessagesettings', 'stopresendingafterxmonths', '')
        settingsversion = 8

    if settingsversion == 8:
        logger.debug("DEBUG: Upgrading from version 8 to 9")
        config.set(
            'bitmessagesettings', 'defaultnoncetrialsperbyte',
            str(defaults.networkDefaultProofOfWorkNonceTrialsPerByte))
        config.set(
            'bitmessagesettings', 'defaultpayloadlengthextrabytes',
            str(defaults.networkDefaultPayloadLengthExtraBytes))
        previousTotalDifficulty = int(
            config.getint(
                'bitmessagesettings', 'maxacceptablenoncetrialsperbyte')
        ) / 320
        previousSmallMessageDifficulty = int(
            config.getint(
                'bitmessagesettings', 'maxacceptablepayloadlengthextrabytes')
        ) / 14000
        config.set(
            'bitmessagesettings', 'maxacceptablenoncetrialsperbyte',
            str(previousTotalDifficulty * 1000))
        config.set(
            'bitmessagesettings', 'maxacceptablepayloadlengthextrabytes',
            str(previousSmallMessageDifficulty * 1000))
        settingsversion = 9

    if settingsversion == 9:
        logger.debug("DEBUG: Upgrading from version 9 to 10")
        for addressInKeysFile in config.addresses():
            try:
                previousTotalDifficulty = float(
                    config.getint(
                        addressInKeysFile, 'noncetrialsperbyte')) / 320
                previousSmallMessageDifficulty = float(
                    config.getint(
                        addressInKeysFile, 'payloadlengthextrabytes')) / 14000
                if previousTotalDifficulty <= 2:
                    previousTotalDifficulty = 1
                if previousSmallMessageDifficulty < 1:
                    previousSmallMessageDifficulty = 1
                config.set(
                    addressInKeysFile, 'noncetrialsperbyte',
                    str(int(previousTotalDifficulty * 1000)))
                config.set(
                    addressInKeysFile, 'payloadlengthextrabytes',
                    str(int(previousSmallMessageDifficulty * 1000)))
            except (ValueError, TypeError, configparser.NoSectionError,
                    configparser.NoOptionError):
                logger.debug("DEBUG: Error processing address %s", addressInKeysFile)
                continue
        config.set('bitmessagesettings', 'maxdownloadrate', '0')
        config.set('bitmessagesettings', 'maxuploadrate', '0')
        settingsversion = 10

    if config.safeGetInt(
            'bitmessagesettings', 'maxacceptablenoncetrialsperbyte') == 0:
        logger.debug("DEBUG: Setting default maxacceptablenoncetrialsperbyte")
        config.set(
            'bitmessagesettings', 'maxacceptablenoncetrialsperbyte',
            str(defaults.ridiculousDifficulty
                * defaults.networkDefaultProofOfWorkNonceTrialsPerByte)
        )
        
    if config.safeGetInt(
            'bitmessagesettings', 'maxacceptablepayloadlengthextrabytes') == 0:
        logger.debug("DEBUG: Setting default maxacceptablepayloadlengthextrabytes")
        config.set(
            'bitmessagesettings', 'maxacceptablepayloadlengthextrabytes',
            str(defaults.ridiculousDifficulty
                * defaults.networkDefaultPayloadLengthExtraBytes)
        )

    if not config.has_option('bitmessagesettings', 'onionport'):
        logger.debug("DEBUG: Adding missing onionport option")
        config.set('bitmessagesettings', 'onionport', '8444')
        
    if not config.has_option('bitmessagesettings', 'onionbindip'):
        logger.debug("DEBUG: Adding missing onionbindip option")
        config.set('bitmessagesettings', 'onionbindip', '127.0.0.1')
        
    if not config.has_option('bitmessagesettings', 'smtpdeliver'):
        logger.debug("DEBUG: Adding missing smtpdeliver option")
        config.set('bitmessagesettings', 'smtpdeliver', '')
        
    if not config.has_option(
            'bitmessagesettings', 'hidetrayconnectionnotifications'):
        logger.debug("DEBUG: Adding missing hidetrayconnectionnotifications option")
        config.set(
            'bitmessagesettings', 'hidetrayconnectionnotifications', 'false')
            
    if config.safeGetInt('bitmessagesettings', 'maxoutboundconnections') < 1:
        logger.debug("DEBUG: Fixing invalid maxoutboundconnections value")
        config.set('bitmessagesettings', 'maxoutboundconnections', '8')
        logger.warning('Your maximum outbound connections must be a number.')

    if not config.has_option('bitmessagesettings', 'ttl'):
        logger.debug("DEBUG: Adding missing ttl option")
        config.set('bitmessagesettings', 'ttl', '367200')

    config.set('bitmessagesettings', 'settingsversion', str(settingsversion))
    config.save()
    logger.debug("DEBUG: Config updated and saved. Exiting updateConfig()")


def adjustHalfOpenConnectionsLimit():
    """Check and satisfy half-open connections limit (mainly XP and Vista)"""
    logger.debug("DEBUG: Entering adjustHalfOpenConnectionsLimit()")
    
    if config.safeGet(
            'bitmessagesettings', 'socksproxytype', 'none') != 'none':
        logger.debug("DEBUG: SOCKS proxy detected, limiting connections to 4")
        state.maximumNumberOfHalfOpenConnections = 4
        return

    is_limited = False
    try:
        if sys.platform[0:3] == "win":
            logger.debug("DEBUG: Windows platform detected")
            VER_THIS = StrictVersion(platform.version())
            is_limited = (
                StrictVersion("5.1.2600") <= VER_THIS
                and StrictVersion("6.0.6000") >= VER_THIS
            )
            logger.debug("DEBUG: Windows version limited status: %s", is_limited)
    except ValueError:
        logger.debug("DEBUG: Error checking Windows version", exc_info=True)
        pass

    state.maximumNumberOfHalfOpenConnections = 9 if is_limited else 64
    logger.debug("DEBUG: Set maximumNumberOfHalfOpenConnections to %d", 
                state.maximumNumberOfHalfOpenConnections)
    logger.debug("DEBUG: Exiting adjustHalfOpenConnectionsLimit()")


def fixSocket():
    """Add missing socket options and methods mainly on Windows"""
    logger.debug("DEBUG: Entering fixSocket()")
    
    if sys.platform.startswith('linux'):
        logger.debug("DEBUG: Linux platform detected, adding SO_BINDTODEVICE")
        socket.SO_BINDTODEVICE = 25

    if not sys.platform.startswith('win'):
        logger.debug("DEBUG: Non-Windows platform, exiting fixSocket()")
        return

    if not hasattr(socket, 'inet_ntop'):
        logger.debug("DEBUG: Adding missing inet_ntop function")
        addressToString = ctypes.windll.ws2_32.WSAAddressToStringA

        def inet_ntop(family, host):
            """Converting an IP address in packed
            binary format to string format"""
            logger.debug("DEBUG: inet_ntop called with family: %d", family)
            if family == socket.AF_INET:
                if len(host) != 4:
                    raise ValueError("invalid IPv4 host")
                host = pack("hH4s8s", socket.AF_INET, 0, host, "\0" * 8)
            elif family == socket.AF_INET6:
                if len(host) != 16:
                    raise ValueError("invalid IPv6 host")
                host = pack("hHL16sL", socket.AF_INET6, 0, 0, host, 0)
            else:
                raise ValueError("invalid address family")
            buf = "\0" * 64
            lengthBuf = pack("I", len(buf))
            addressToString(host, len(host), None, buf, lengthBuf)
            result = buf[0:buf.index("\0")]
            logger.debug("DEBUG: inet_ntop returning: %s", result)
            return result
        socket.inet_ntop = inet_ntop

    if not hasattr(socket, 'inet_pton'):
        logger.debug("DEBUG: Adding missing inet_pton function")
        stringToAddress = ctypes.windll.ws2_32.WSAStringToAddressA

        def inet_pton(family, host):
            """Converting an IP address in string format
            to a packed binary format"""
            logger.debug("DEBUG: inet_pton called with family: %d, host: %s", 
                        family, host)
            buf = "\0" * 28
            lengthBuf = pack("I", len(buf))
            if stringToAddress(str(host),
                               int(family),
                               None,
                               buf,
                               lengthBuf) != 0:
                raise socket.error("illegal IP address passed to inet_pton")
            if family == socket.AF_INET:
                result = buf[4:8]
            elif family == socket.AF_INET6:
                result = buf[8:24]
            else:
                raise ValueError("invalid address family")
            logger.debug("DEBUG: inet_pton returning: %s", result)
            return result
        socket.inet_pton = inet_pton

    if not hasattr(socket, 'IPPROTO_IPV6'):
        logger.debug("DEBUG: Adding missing IPPROTO_IPV6 constant")
        socket.IPPROTO_IPV6 = 41
        
    if not hasattr(socket, 'IPV6_V6ONLY'):
        logger.debug("DEBUG: Adding missing IPV6_V6ONLY constant")
        socket.IPV6_V6ONLY = 27
        
    logger.debug("DEBUG: Exiting fixSocket()")


def start_proxyconfig():
    """Check socksproxytype and start any proxy configuration plugin"""
    logger.debug("DEBUG: Entering start_proxyconfig()")
    
    if not get_plugin:
        logger.debug("DEBUG: No plugin system available, exiting")
        return
        
    config_ready.wait()
    proxy_type = config.safeGet('bitmessagesettings', 'socksproxytype')
    logger.debug("DEBUG: Proxy type: %s", proxy_type)
    
    if proxy_type and proxy_type not in ('none', 'SOCKS4a', 'SOCKS5'):
        try:
            proxyconfig_start = time.time()
            logger.debug("DEBUG: Attempting to start proxy config plugin: %s", 
                        proxy_type)
            if not get_plugin('proxyconfig', name=proxy_type)(config):
                raise TypeError()
        except TypeError:
            logger.error(
                'Failed to run proxy config plugin %s',
                proxy_type, exc_info=True)
            config.setTemp('bitmessagesettings', 'dontconnect', 'true')
        else:
            logger.info(
                'Started proxy config plugin %s in %s sec',
                proxy_type, time.time() - proxyconfig_start)
            logger.debug("DEBUG: Proxy config plugin started successfully")
            
    logger.debug("DEBUG: Exiting start_proxyconfig()")
