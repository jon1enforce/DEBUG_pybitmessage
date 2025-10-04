"""
Namecoin queries
"""
# pylint: disable=too-many-branches

import base64
from six.moves import http_client as httplib
import json
import os
import socket
import sys

import defaults
from addresses import decodeAddress
from bmconfigparser import config
from debug import logger
from tr import _translate


configSection = "bitmessagesettings"
logger.debug("DEBUG: Namecoin module initialized with config section: %s", configSection)


class RPCError(Exception):
    """Error thrown when the RPC call returns an error."""
    error = None

    def __init__(self, data):
        logger.debug("DEBUG: RPCError created with data: %s", data)
        super(RPCError, self).__init__()
        self.error = data

    def __str__(self):
        return '{0}: {1}'.format(type(self).__name__, self.error)


class namecoinConnection(object):
    """This class handles the Namecoin identity integration."""

    user = None
    password = None
    host = None
    port = None
    nmctype = None
    bufsize = 4096
    queryid = 1
    con = None

    def __init__(self, options=None):
        """
        Initialise. If options are given, take the connection settings from
        them instead of loading from the configs.
        """
        logger.debug("DEBUG: namecoinConnection.__init__ called with options: %s", options)
        
        if options is None:
            logger.debug("DEBUG: Loading settings from config")
            self.nmctype = config.get(configSection, "namecoinrpctype")
            self.host = config.get(configSection, "namecoinrpchost")
            self.port = int(config.get(configSection, "namecoinrpcport"))
            self.user = config.get(configSection, "namecoinrpcuser")
            self.password = config.get(configSection, "namecoinrpcpassword")
        else:
            logger.debug("DEBUG: Using provided options")
            self.nmctype = options["type"]
            self.host = options["host"]
            self.port = int(options["port"])
            self.user = options["user"]
            self.password = options["password"]

        logger.debug("DEBUG: Connection type: %s, host: %s, port: %d", 
                    self.nmctype, self.host, self.port)
        
        assert self.nmctype in ("namecoind", "nmcontrol")
        if self.nmctype == "namecoind":
            logger.debug("DEBUG: Creating HTTP connection for namecoind")
            self.con = httplib.HTTPConnection(self.host, self.port, timeout=3)

    def query(self, identity):
        """
        Query for the bitmessage address corresponding to the given identity
        string.
        """
        logger.debug("DEBUG: query called with identity: %s", identity)
        
        slashPos = identity.find("/")
        if slashPos < 0:
            display_name = identity
            identity = "id/" + identity
            logger.debug("DEBUG: Added 'id/' prefix to identity: %s", identity)
        else:
            display_name = identity.split("/")[1]
            logger.debug("DEBUG: Extracted display name: %s", display_name)

        try:
            if self.nmctype == "namecoind":
                logger.debug("DEBUG: Querying namecoind for identity: %s", identity)
                res = self.callRPC("name_show", [identity])
                res = res["value"]
            elif self.nmctype == "nmcontrol":
                logger.debug("DEBUG: Querying nmcontrol for identity: %s", identity)
                res = self.callRPC("data", ["getValue", identity])
                res = res["reply"]
                if not res:
                    msg = _translate("MainWindow", "The name {0} was not found.").format(
                        identity.decode("utf-8", "ignore"))
                    logger.debug("DEBUG: Name not found: %s", identity)
                    return (msg, None)
            else:
                assert False
        except RPCError as exc:
            logger.exception("DEBUG: Namecoin query RPC exception")
            if isinstance(exc.error, dict):
                errmsg = exc.error["message"]
            else:
                errmsg = exc.error
            msg = _translate("MainWindow", "The namecoin query failed ({0})").format(
                errmsg.decode("utf-8", "ignore"))
            logger.debug("DEBUG: RPC error: %s", msg)
            return (msg, None)
        except AssertionError:
            msg = _translate("MainWindow", "Unknown namecoin interface type: {0}").format(
                self.nmctype.decode("utf-8", "ignore"))
            logger.debug("DEBUG: Assertion error: %s", msg)
            return (msg, None)
        except Exception:
            logger.exception("DEBUG: Namecoin query exception")
            msg = _translate("MainWindow", "The namecoin query failed.")
            logger.debug("DEBUG: General query error: %s", msg)
            return (msg, None)

        try:
            logger.debug("DEBUG: Trying to parse JSON response: %s", res)
            res = json.loads(res)
        except ValueError:
            logger.debug("DEBUG: Response is not JSON, using raw value")
            pass
        else:
            try:
                display_name = res["name"]
                logger.debug("DEBUG: Found display name in JSON: %s", display_name)
            except KeyError:
                pass
            res = res.get("bitmessage")

        logger.debug("DEBUG: Validating Bitmessage address: %s", res)
        valid = decodeAddress(res)[0] == "success"
        if valid:
            result = "%s <%s>" % (display_name, res)
            logger.debug("DEBUG: Valid address found: %s", result)
            return (None, result)
        else:
            msg = _translate("MainWindow", "The name {0} has no associated Bitmessage address.").format(
                identity.decode("utf-8", "ignore"))
            logger.debug("DEBUG: No valid address found: %s", msg)
            return (msg, None)

    def test(self):
        """Test the connection settings."""
        logger.debug("DEBUG: test connection called")
        try:
            if self.nmctype == "namecoind":
                logger.debug("DEBUG: Testing namecoind connection")
                try:
                    vers = self.callRPC("getinfo", [])["version"]
                except RPCError:
                    vers = self.callRPC("getnetworkinfo", [])["version"]

                v3 = vers % 100
                vers = vers / 100
                v2 = vers % 100
                vers = vers / 100
                v1 = vers
                if v3 == 0:
                    versStr = "0.%d.%d" % (v1, v2)
                else:
                    versStr = "0.%d.%d.%d" % (v1, v2, v3)
                
                msg = _translate("MainWindow", "Success!  Namecoind version {0} running.").format(
                    versStr.decode("utf-8", "ignore"))
                logger.debug("DEBUG: namecoind test success: %s", msg)
                return ('success', msg)

            elif self.nmctype == "nmcontrol":
                logger.debug("DEBUG: Testing nmcontrol connection")
                res = self.callRPC("data", ["status"])
                prefix = "Plugin data running"
                if ("reply" in res) and res["reply"][:len(prefix)] == prefix:
                    msg = _translate("MainWindow", "Success! NMControll is up and running.")
                    logger.debug("DEBUG: nmcontrol test success: %s", msg)
                    return ('success', msg)

                logger.error("DEBUG: Unexpected nmcontrol reply: %s", res)
                msg = _translate("MainWindow", "Couldn\'t understand NMControl.")
                logger.debug("DEBUG: nmcontrol test failed: %s", msg)
                return ('failed', msg)

            else:
                sys.exit("Unsupported Namecoin type")

        except Exception:
            logger.exception("DEBUG: Namecoin connection test failure")
            msg = _translate("MainWindow", "The connection to namecoin failed.")
            logger.debug("DEBUG: Test failed with error: %s", msg)
            return ('failed', msg)

    def callRPC(self, method, params):
        """Perform an JSON RPC call."""
        logger.debug("DEBUG: callRPC called with method: %s, params: %s", method, params)
        
        data = {"method": method, "params": params, "id": self.queryid}
        logger.debug("DEBUG: RPC request data: %s", data)
        
        if self.nmctype == "namecoind":
            logger.debug("DEBUG: Using HTTP transport")
            resp = self.queryHTTP(json.dumps(data))
        elif self.nmctype == "nmcontrol":
            logger.debug("DEBUG: Using socket transport")
            resp = self.queryServer(json.dumps(data))
        else:
            assert False
            
        logger.debug("DEBUG: RPC raw response: %s", resp)
        val = json.loads(resp)

        if val["id"] != self.queryid:
            logger.error("DEBUG: ID mismatch in RPC response: expected %d, got %d", 
                       self.queryid, val["id"])
            raise Exception("ID mismatch in JSON RPC answer.")

        if self.nmctype == "namecoind":
            self.queryid = self.queryid + 1
            logger.debug("DEBUG: Incremented query ID to %d", self.queryid)

        error = val["error"]
        if error is None:
            logger.debug("DEBUG: RPC call successful, result: %s", val["result"])
            return val["result"]

        if isinstance(error, bool):
            logger.error("DEBUG: RPC error (boolean): %s", val["result"])
            raise RPCError(val["result"])
        
        logger.error("DEBUG: RPC error: %s", error)
        raise RPCError(error)

    def queryHTTP(self, data):
        """Query the server via HTTP."""
        logger.debug("DEBUG: queryHTTP called with data length: %d", len(data))
        result = None

        try:
            logger.debug("DEBUG: Preparing HTTP request")
            self.con.putrequest("POST", "/")
            self.con.putheader("Connection", "Keep-Alive")
            self.con.putheader("User-Agent", "bitmessage")
            self.con.putheader("Host", self.host)
            self.con.putheader("Content-Type", "application/json")
            self.con.putheader("Content-Length", str(len(data)))
            self.con.putheader("Accept", "application/json")
            authstr = "%s:%s" % (self.user, self.password)
            self.con.putheader("Authorization", "Basic %s" % base64.b64encode(authstr))
            self.con.endheaders()
            self.con.send(data)
            
            try:
                logger.debug("DEBUG: Getting HTTP response")
                resp = self.con.getresponse()
                result = resp.read()
                if resp.status != 200:
                    msg = "Namecoin returned status %i: %s" % (resp.status, resp.reason)
                    logger.error("DEBUG: HTTP error: %s", msg)
                    raise Exception(msg)
            except Exception as e:
                logger.error("DEBUG: HTTP receive error: %s", str(e))
        except Exception as e:
            logger.error("DEBUG: HTTP connection error: %s", str(e))

        logger.debug("DEBUG: HTTP query result length: %d", len(result) if result else 0)
        return result

    def queryServer(self, data):
        """Send data to the RPC server and return the result."""
        logger.debug("DEBUG: queryServer called with data length: %d", len(data))
        
        try:
            logger.debug("DEBUG: Creating socket connection")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(3)
            s.connect((self.host, self.port))
            s.sendall(data)
            result = ""

            while True:
                tmp = s.recv(self.bufsize)
                if not tmp:
                    break
                result += tmp

            s.close()
            logger.debug("DEBUG: Socket query result length: %d", len(result))
            return result

        except socket.error as exc:
            logger.error("DEBUG: Socket error in RPC connection: %s", str(exc))
            raise Exception("Socket error in RPC connection: %s" % exc)


def lookupNamecoinFolder():
    """Look up the namecoin data folder."""
    logger.debug("DEBUG: lookupNamecoinFolder called")
    
    app = "namecoin"
    logger.debug("DEBUG: Platform: %s", sys.platform)

    if sys.platform == "darwin":
        try:
            dataFolder = os.path.join(os.getenv("HOME"), "Library/Application Support/", app)
            logger.debug("DEBUG: MacOS data folder: %s", dataFolder)
        except TypeError:
            msg = "Could not find home folder"
            logger.error("DEBUG: %s", msg)
            sys.exit(msg + ", please report this message and your OS X version to the BitMessage Github.")

    dataFolder = (
        os.path.join(os.getenv("APPDATA"), app)
        if sys.platform.startswith('win') else
        os.path.join(os.getenv("HOME"), ".%s" % app)
    )
    logger.debug("DEBUG: Determined data folder: %s", dataFolder)

    return dataFolder + os.path.sep


def ensureNamecoinOptions():
    """Ensure all namecoin options are set with default values if missing."""
    logger.debug("DEBUG: ensureNamecoinOptions called")

    if not config.has_option(configSection, "namecoinrpctype"):
        logger.debug("DEBUG: Setting default namecoinrpctype")
        config.set(configSection, "namecoinrpctype", "namecoind")
    if not config.has_option(configSection, "namecoinrpchost"):
        logger.debug("DEBUG: Setting default namecoinrpchost")
        config.set(configSection, "namecoinrpchost", "localhost")

    hasUser = config.has_option(configSection, "namecoinrpcuser")
    hasPass = config.has_option(configSection, "namecoinrpcpassword")
    hasPort = config.has_option(configSection, "namecoinrpcport")

    logger.debug("DEBUG: Checking namecoin config: user=%s, pass=%s, port=%s", 
                hasUser, hasPass, hasPort)

    # Try to read user/password from .namecoin configuration file
    defaultUser = ""
    defaultPass = ""
    nmcFolder = lookupNamecoinFolder()
    nmcConfig = nmcFolder + "namecoin.conf"
    logger.debug("DEBUG: Looking for namecoin config at: %s", nmcConfig)

    try:
        with safe_open(nmcConfig, "r") as nmc:
            logger.debug("DEBUG: Reading namecoin config file")
            while True:
                line = nmc.readline()
                if line == "":
                    break
                parts = line.split("=")
                if len(parts) == 2:
                    key = parts[0]
                    val = parts[1].rstrip()

                    if key == "rpcuser" and not hasUser:
                        defaultUser = val
                        logger.debug("DEBUG: Found rpcuser in config")
                    if key == "rpcpassword" and not hasPass:
                        defaultPass = val
                        logger.debug("DEBUG: Found rpcpassword in config")
                    if key == "rpcport":
                        defaults.namecoinDefaultRpcPort = val
                        logger.debug("DEBUG: Found rpcport in config: %s", val)

    except IOError:
        logger.warning("DEBUG: %s unreadable or missing, Namecoin support deactivated", nmcConfig)
    except Exception:
        logger.warning("DEBUG: Error processing namecoin.conf", exc_info=True)

    # Set defaults if not found
    if not hasUser:
        logger.debug("DEBUG: Setting default rpcuser")
        config.set(configSection, "namecoinrpcuser", defaultUser)
    if not hasPass:
        logger.debug("DEBUG: Setting default rpcpassword")
        config.set(configSection, "namecoinrpcpassword", defaultPass)
    if not hasPort:
        logger.debug("DEBUG: Setting default rpcport: %s", defaults.namecoinDefaultRpcPort)
        config.set(configSection, "namecoinrpcport", defaults.namecoinDefaultRpcPort)
