"""BMStatusBar class definition"""

from time import time
import logging

from qtpy import QtWidgets

# Debugging setup
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class BMStatusBar(QtWidgets.QStatusBar):
    """
    Status bar with message queue and priorities.
    
    Attributes:
        duration (int): Message display duration in milliseconds
        deleteAfter (int): Time in seconds after which messages are purged from queue
        important (list): Queue of important messages with timestamps
        timer (int): Timer ID
        iterator (int): Current position in message queue
    """
    duration = 10000  # 10 seconds
    deleteAfter = 60  # 1 minute

    def __init__(self, parent=None):
        """
        Initialize the status bar.
        
        Args:
            parent (QWidget): Parent widget
        """
        logger.debug("DEBUG: Initializing BMStatusBar")
        super(BMStatusBar, self).__init__(parent)
        self.important = []
        self.timer = self.startTimer(BMStatusBar.duration)
        self.iterator = 0
        logger.debug("DEBUG: BMStatusBar initialized with timer ID: %s", self.timer)

    def timerEvent(self, event):  # pylint: disable=unused-argument
        """
        Timer event handler for managing message queue display and cleanup.
        
        Args:
            event (QTimerEvent): Timer event
        """
        logger.debug("DEBUG: timerEvent triggered, processing message queue")
        
        while len(self.important) > 0:
            self.iterator += 1
            logger.debug(f"DEBUG: Current iterator position: {self.iterator}")
            
            try:
                message_time = self.important[self.iterator][1]
                if message_time + BMStatusBar.deleteAfter < time():
                    logger.debug(f"DEBUG: Purging expired message at index {self.iterator}")
                    del self.important[self.iterator]
                    self.iterator -= 1
                    continue
            except IndexError:
                logger.debug("DEBUG: Iterator out of bounds, resetting to start")
                self.iterator = -1
                continue
                
            current_message = self.important[self.iterator][0]
            logger.debug(f"DEBUG: Displaying message: {current_message}")
            self.showMessage(current_message, 0)
            break
            
        logger.debug("DEBUG: Finished processing message queue")

    def addImportant(self, message):
        """
        Add an important message to the queue and trigger display.
        
        Args:
            message (str): The message to add
        """
        logger.debug(f"DEBUG: Adding important message: {message}")
        timestamp = time()
        self.important.append([message, timestamp])
        self.iterator = len(self.important) - 2
        logger.debug(f"DEBUG: Queue size: {len(self.important)}, iterator set to: {self.iterator}")
        self.timerEvent(None)
