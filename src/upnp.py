# pylint: disable=too-many-statements,too-many-branches,protected-access,no-self-use
"""
Complete UPnP port forwarding implementation in separate thread.
Reference: http://mattscodecave.com/posts/using-python-and-upnp-to-forward-a-port
"""

import sys
import six
from six.moves import http_client as httplib
import re
import socket
import time
from six.moves.urllib.request import urlopen
from random import randint
from six.moves.urllib.parse import urlparse
from xml.dom.minidom import Document  # nosec B408
from defusedxml.minidom import parseString
import traceback

import queues
import state
import tr
from bmconfigparser import config
from debug import logger
from network import connectionpool, knownnodes, StoppableThread
from network.node import Peer

def createRequestXML(service, action, arguments=None):
    """Router UPnP requests are XML formatted"""
    print("DEBUG: createRequestXML() called with service=%s, action=%s" % (service, action))
    
    doc = Document()
    envelope = doc.createElementNS('', 's:Envelope')
    envelope.setAttribute('xmlns:s', 'http://schemas.xmlsoap.org/soap/envelope/')
    envelope.setAttribute('s:encodingStyle', 'http://schemas.xmlsoap.org/soap/encoding/')

    body = doc.createElementNS('', 's:Body')
    fn = doc.createElementNS('', 'u:%s' % action)
    fn.setAttribute('xmlns:u', 'urn:schemas-upnp-org:service:%s' % service)

    argument_list = []
    if arguments is not None:
        print("DEBUG: Processing %d arguments for UPnP request" % len(arguments))
        for k, v in arguments:
            tmp_node = doc.createElement(k)
            tmp_text_node = doc.createTextNode(v)
            tmp_node.appendChild(tmp_text_node)
            argument_list.append(tmp_node)
            print("DEBUG: Added argument %s=%s" % (k, v))

    for arg in argument_list:
        fn.appendChild(arg)

    body.appendChild(fn)
    envelope.appendChild(body)
    doc.appendChild(envelope)

    xml_str = doc.toxml()
    print("DEBUG: Generated UPnP request XML:\n%s" % xml_str)
    return xml_str

class UPnPError(Exception):
    """Handle a UPnP error"""
    def __init__(self, message):
        super(UPnPError, self).__init__()
        print("DEBUG: UPnPError occurred: %s" % message)
        print("DEBUG: Stack trace:\n%s" % traceback.format_exc())

class Router:
    """Encapulate routing"""
    def __init__(self, ssdpResponse, address):
        print("DEBUG: Initializing Router with address: %s" % address)
        self.name = ""
        self.path = ""
        self.address = address
        self.routerPath = None
        self.extPort = None
        self.upnp_schema = ""

        row = ssdpResponse.split(b'\r\n')
        header = {}
        for i in range(1, len(row)):
            part = row[i].split(b': ')
            if len(part) == 2:
                header[part[0].decode("utf-8", "replace").lower()] = part[1].decode("utf-8", "replace")
        
        print("DEBUG: SSDP response headers: %s" % header)

        try:
            self.routerPath = urlparse(header['location'])
            if not self.routerPath or not hasattr(self.routerPath, "hostname"):
                print("DEBUG: No valid hostname in router path")
            else:
                print("DEBUG: Router path parsed successfully: %s" % self.routerPath)
        except KeyError:
            print("DEBUG: Missing location header in SSDP response")

        try:
            print("DEBUG: Fetching router description from %s" % header['location'])
            directory = urlopen(header['location']).read()
            print("DEBUG: Received router description (%d bytes)" % len(directory))

            dom = parseString(directory)
            self.name = dom.getElementsByTagName('friendlyName')[0].childNodes[0].data
            print("DEBUG: Router friendly name: %s" % self.name)

            service_types = dom.getElementsByTagName('serviceType')
            print("DEBUG: Found %d service types" % len(service_types))

            for service in service_types:
                service_data = service.childNodes[0].data
                if service_data.find('WANIPConnection') > 0 or service_data.find('WANPPPConnection') > 0:
                    self.path = service.parentNode.getElementsByTagName('controlURL')[0].childNodes[0].data
                    self.upnp_schema = re.sub(r'[^A-Za-z0-9:-]', '', service_data.split(':')[-2])
                    print("DEBUG: Found WAN service - schema: %s, path: %s" % (self.upnp_schema, self.path))
                    break
        except Exception as e:
            print("DEBUG: Router initialization failed: %s" % str(e))
            raise UPnPError("Router init failed: %s" % str(e))

    def AddPortMapping(self, externalPort, internalPort, internalClient, protocol, description, leaseDuration=0, enabled=1):
        """Add UPnP port mapping"""
        print("DEBUG: AddPortMapping() called - ext:%s int:%s client:%s proto:%s desc:%s" % 
              (externalPort, internalPort, internalClient, protocol, description))
        
        try:
            resp = self.soapRequest(self.upnp_schema + ':1', 'AddPortMapping', [
                ('NewRemoteHost', ''),
                ('NewExternalPort', str(externalPort)),
                ('NewProtocol', protocol),
                ('NewInternalPort', str(internalPort)),
                ('NewInternalClient', internalClient),
                ('NewEnabled', str(enabled)),
                ('NewPortMappingDescription', str(description)),
                ('NewLeaseDuration', str(leaseDuration))
            ])
            self.extPort = externalPort
            print("DEBUG: Successfully created port mapping on external port %s" % externalPort)
            return resp
        except Exception as e:
            print("DEBUG: Failed to add port mapping: %s" % str(e))
            raise

    def DeletePortMapping(self, externalPort, protocol):
        """Delete UPnP port mapping"""
        print("DEBUG: DeletePortMapping() called - port:%s proto:%s" % (externalPort, protocol))
        
        try:
            resp = self.soapRequest(self.upnp_schema + ':1', 'DeletePortMapping', [
                ('NewRemoteHost', ''),
                ('NewExternalPort', str(externalPort)),
                ('NewProtocol', protocol),
            ])
            print("DEBUG: Successfully deleted port mapping on port %s" % externalPort)
            return resp
        except Exception as e:
            print("DEBUG: Failed to delete port mapping: %s" % str(e))
            raise

    def GetExternalIPAddress(self):
        """Get the external address"""
        print("DEBUG: GetExternalIPAddress() called")
        
        try:
            resp = self.soapRequest(self.upnp_schema + ':1', 'GetExternalIPAddress')
            dom = parseString(resp.read())
            ip = dom.getElementsByTagName('NewExternalIPAddress')[0].childNodes[0].data
            print("DEBUG: Got external IP: %s" % ip)
            return ip
        except Exception as e:
            print("DEBUG: Failed to get external IP: %s" % str(e))
            raise

    def soapRequest(self, service, action, arguments=None):
        """Make a request to a router"""
        print("DEBUG: soapRequest() called - service:%s action:%s" % (service, action))
        
        try:
            conn = httplib.HTTPConnection(self.routerPath.hostname, self.routerPath.port)
            print("DEBUG: Connecting to %s:%s" % (self.routerPath.hostname, self.routerPath.port))
            
            xml = createRequestXML(service, action, arguments)
            headers = {
                'SOAPAction': '"urn:schemas-upnp-org:service:%s#%s"' % (service, action),
                'Content-Type': 'text/xml'
            }
            
            print("DEBUG: Sending POST to path: %s" % self.path)
            conn.request('POST', self.path, xml, headers)
            
            resp = conn.getresponse()
            print("DEBUG: Received response - status:%s reason:%s" % (resp.status, resp.reason))
            
            if resp.status == 500:
                respData = resp.read()
                print("DEBUG: SOAP error response: %s" % respData)
                try:
                    dom = parseString(respData)
                    errinfo = dom.getElementsByTagName('errorDescription')
                    if errinfo:
                        raise UPnPError(errinfo[0].childNodes[0].data)
                except:
                    raise UPnPError("Unable to parse SOAP error: %s" % (respData))
            
            conn.close()
            return resp
        except Exception as e:
            print("DEBUG: soapRequest failed: %s" % str(e))
            raise

class uPnPThread(StoppableThread):
    """Start a thread to handle UPnP activity"""
    SSDP_ADDR = "239.255.255.250"
    GOOGLE_DNS = "8.8.8.8"
    SSDP_PORT = 1900
    SSDP_MX = 2
    SSDP_ST = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"

    def __init__(self):
        print("DEBUG: Initializing uPnPThread")
        super(uPnPThread, self).__init__(name="uPnPThread")
        self.extPort = config.safeGetInt('bitmessagesettings', 'extport', default=None)
        print("DEBUG: Configured external port: %s" % self.extPort)
        
        self.localIP = self.getLocalIP()
        print("DEBUG: Detected local IP: %s" % self.localIP)
        
        self.routers = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.localIP, 0))
        
        # OpenBSD-spezifischer Workaround für IP_MULTICAST_TTL
        if sys.platform.startswith('openbsd'):
            print("DEBUG: OpenBSD detected - using alternative socket configuration")
            try:
                # Versuche IP_MULTICAST_TTL mit IPv6
                self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 2)
                print("DEBUG: Successfully set IPV6_MULTICAST_HOPS on OpenBSD")
            except (AttributeError, OSError) as e:
                print("DEBUG: OpenBSD workaround failed (IPV6_MULTICAST_HOPS not available): %s" % str(e))
                # Falls IPv6 nicht verfügbar, einfach ohne TTL fortfahren
        else:
            try:
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                print("DEBUG: Successfully set IP_MULTICAST_TTL")
            except OSError as e:
                print("DEBUG: Could not set IP_MULTICAST_TTL (non-critical): %s" % str(e))
        
        self.sock.settimeout(5)
        self.sendSleep = 60
        print("DEBUG: Socket initialized - bind:%s timeout:%s" % (self.localIP, self.sock.gettimeout()))

    def run(self):
        """Start the thread to manage UPnP activity"""
        print("DEBUG: uPnPThread.run() started")
        lastSent = 0

        # wait until asyncore binds so that we know the listening port
        bound = False
        while state.shutdown == 0 and not self._stopped and not bound:
            for s in connectionpool.pool.listeningSockets.values():
                if s.is_bound():
                    bound = True
            if not bound:
                time.sleep(1)

        self.localPort = config.getint('bitmessagesettings', 'port')
        print("DEBUG: Local port configured: %s" % self.localPort)

        while state.shutdown == 0 and config.safeGetBoolean('bitmessagesettings', 'upnp'):
            if time.time() - lastSent > self.sendSleep and not self.routers:
                print("DEBUG: Sending router search (last sent: %s)" % lastSent)
                try:
                    self.sendSearchRouter()
                except Exception as e:
                    print("DEBUG: Router search failed: %s" % str(e))
                lastSent = time.time()

            try:
                print("DEBUG: Waiting for router response...")
                resp, (ip, _) = self.sock.recvfrom(1000)
                if resp is None:
                    print("DEBUG: Empty response received")
                    continue
                
                print("DEBUG: Received response from %s" % ip)
                newRouter = Router(resp, ip)
                
                for router in self.routers:
                    if router.routerPath == newRouter.routerPath:
                        print("DEBUG: Router already known, skipping")
                        break
                else:
                    print("DEBUG: New router found at %s" % ip)
                    self.routers.append(newRouter)
                    self.createPortMapping(newRouter)
                    
                    try:
                        external_ip = newRouter.GetExternalIPAddress()
                        self_peer = Peer(external_ip, self.extPort)
                        print("DEBUG: Created peer with external IP: %s" % external_ip)
                        
                        with knownnodes.knownNodesLock:
                            knownnodes.addKnownNode(1, self_peer, is_self=True)
                            print("DEBUG: Added self to known nodes")
                            
                        queues.UISignalQueue.put((
                            'updateStatusBar', tr._translate(
                                "MainWindow",
                                "UPnP port mapping established on port {0}"
                            ).format(self.extPort)
                        ))
                    except Exception as e:
                        print("DEBUG: Failed to get external IP or create peer: %s" % str(e))

            except socket.timeout:
                print("DEBUG: Socket timeout while waiting for router response")
            except Exception as e:
                print("DEBUG: Error in router search: %s" % str(e))

        print("DEBUG: Shutting down UPnP thread")
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
            print("DEBUG: Socket closed")
        except Exception as e:
            print("DEBUG: Error closing socket: %s" % str(e))

        deleted = False
        for router in self.routers:
            if router.extPort is not None:
                deleted = True
                self.deletePortMapping(router)
                print("DEBUG: Deleted port mapping for router %s" % router.name)

        if deleted:
            queues.UISignalQueue.put(('updateStatusBar', tr._translate("MainWindow", 'UPnP port mapping removed')))
            print("DEBUG: Notified UI about port mapping removal")

        print("DEBUG: uPnPThread.run() completed")

    def getLocalIP(self):
        """Get the local IP of the node"""
        print("DEBUG: getLocalIP() called")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.connect((uPnPThread.GOOGLE_DNS, 1))
            ip = s.getsockname()[0]
            print("DEBUG: Detected local IP: %s" % ip)
            return ip
        except Exception as e:
            print("DEBUG: Failed to detect local IP: %s" % str(e))
            raise

    def sendSearchRouter(self):
        """Querying for UPnP services"""
        print("DEBUG: sendSearchRouter() called")
        ssdpRequest = "M-SEARCH * HTTP/1.1\r\n" + \
            "HOST: %s:%d\r\n" % (uPnPThread.SSDP_ADDR, uPnPThread.SSDP_PORT) + \
            "MAN: \"ssdp:discover\"\r\n" + \
            "MX: %d\r\n" % (uPnPThread.SSDP_MX, ) + \
            "ST: %s\r\n" % (uPnPThread.SSDP_ST, ) + "\r\n"

        try:
            print("DEBUG: Sending SSDP request to %s:%d" % (uPnPThread.SSDP_ADDR, uPnPThread.SSDP_PORT))
            self.sock.sendto(ssdpRequest.encode("utf8", "replace"), (uPnPThread.SSDP_ADDR, uPnPThread.SSDP_PORT))
            print("DEBUG: SSDP request sent successfully")
        except Exception as e:
            print("DEBUG: Failed to send SSDP request: %s" % str(e))
            raise

    def createPortMapping(self, router):
        """Add a port mapping"""
        print("DEBUG: createPortMapping() called for router %s" % router.name)
        
        for i in range(50):
            try:
                if i == 0:
                    extPort = self.localPort
                    print("DEBUG: Attempt %d - trying configured port %d" % (i+1, extPort))
                elif i == 1 and self.extPort:
                    extPort = self.extPort
                    print("DEBUG: Attempt %d - trying previous external port %d" % (i+1, extPort))
                else:
                    extPort = randint(32767, 65535)
                    print("DEBUG: Attempt %d - trying random port %d" % (i+1, extPort))
                
                print("DEBUG: Requesting mapping for %s:%d on external port %d" % 
                      (self.localIP, self.localPort, extPort))
                
                router.AddPortMapping(extPort, self.localPort, self.localIP, 'TCP', 'BitMessage')
                self.extPort = extPort
                config.set('bitmessagesettings', 'extport', str(extPort))
                config.save()
                print("DEBUG: Port mapping successful, saved config")
                break
            except UPnPError as e:
                print("DEBUG: Port mapping attempt %d failed: %s" % (i+1, str(e)))
            except Exception as e:
                print("DEBUG: Unexpected error in port mapping attempt %d: %s" % (i+1, str(e)))

    def deletePortMapping(self, router):
        """Delete a port mapping"""
        print("DEBUG: deletePortMapping() called for router %s, port %s" % (router.name, router.extPort))
        try:
            router.DeletePortMapping(router.extPort, 'TCP')
            print("DEBUG: Port mapping deleted successfully")
        except Exception as e:
            print("DEBUG: Failed to delete port mapping: %s" % str(e))
