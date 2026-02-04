"""
A thread to handle network concerns
"""
import network.asyncore_pollchoose as asyncore
from network import connectionpool
from queues import excQueue
from .threads import StoppableThread


class BMNetworkThread(StoppableThread):
    """Main network thread"""
    name = "Asyncore"

    def run(self):
        try:
            while not self._stopped:
                connectionpool.pool.loop()
        except Exception as e:
            excQueue.put((self.name, e))
            raise

    def stopThread(self):
        super(BMNetworkThread, self).stopThread()
        
        # Kopien der Dictionaries erstellen, um Concurrent Modification zu vermeiden
        listening_sockets = list(connectionpool.pool.listeningSockets.values())
        outbound_connections = list(connectionpool.pool.outboundConnections.values())
        inbound_connections = list(connectionpool.pool.inboundConnections.values())
        
        # Alle Sockets schließen
        for sock in listening_sockets:
            try:
                sock.close()
            except:  # nosec B110 # pylint:disable=bare-except
                pass
        
        # Outbound Connections schließen
        for conn in outbound_connections:
            try:
                conn.close()
            except:  # nosec B110 # pylint:disable=bare-except
                pass
        
        # Inbound Connections schließen
        for conn in inbound_connections:
            try:
                conn.close()
            except:  # nosec B110 # pylint:disable=bare-except
                pass

        # just in case
        asyncore.close_all()
