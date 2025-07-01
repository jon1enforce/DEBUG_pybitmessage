"""
    UI Singnaler for kivy interface
"""

import logging
from threading import Thread
from kivy.app import App
from pybitmessage import queues
from pybitmessage import state
from pybitmessage.bitmessagekivy.baseclass.common import kivy_state_variables

logger = logging.getLogger('default')


class UIkivySignaler(Thread):
    """Kivy ui signaler"""

    def __init__(self, *args, **kwargs):
        logger.debug("DEBUG: Initializing UIkivySignaler thread")
        super(UIkivySignaler, self).__init__(*args, **kwargs)
        self.kivy_state = kivy_state_variables()
        logger.debug("DEBUG: UIkivySignaler initialized with kivy_state: %s", self.kivy_state)

    def run(self):
        logger.debug("DEBUG: UIkivySignaler thread started")
        self.kivy_state.kivyui_ready.wait()
        logger.debug("DEBUG: Kivy UI is ready, starting main loop")

        while state.shutdown == 0:
            try:
                logger.debug("DEBUG: Waiting for next UI signal from queue...")
                command, data = queues.UISignalQueue.get()
                logger.debug("DEBUG: Received UI signal - command: %s, data: %s", command, data)

                if command == 'writeNewAddressToTable':
                    logger.debug("DEBUG: Processing 'writeNewAddressToTable' command")
                    address = data[1]
                    logger.debug("DEBUG: Adding new address to identity_list: %s", address)
                    App.get_running_app().identity_list.append(address)
                    logger.debug("DEBUG: Address added successfully")

                elif command == 'updateSentItemStatusByAckdata':
                    logger.debug("DEBUG: Processing 'updateSentItemStatusByAckdata' command")
                    logger.debug("DEBUG: Dispatching status update with data: %s", data)
                    App.get_running_app().status_dispatching(data)
                    logger.debug("DEBUG: Status update dispatched")

                elif command == 'writeNewpaymentAddressToTable':
                    logger.debug("DEBUG: Processing 'writeNewpaymentAddressToTable' command (no action implemented)")

                else:
                    logger.debug("DEBUG: Received unknown command: %s", command)

                # Log queue size for monitoring
                logger.debug("DEBUG: UISignalQueue remaining items: %d", queues.UISignalQueue.qsize())

            except Exception as e:
                logger.error("DEBUG: Exception in UIkivySignaler main loop: %s", str(e), exc_info=True)

        logger.debug("DEBUG: Shutdown detected, exiting UIkivySignaler thread")
