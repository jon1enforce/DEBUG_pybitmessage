"""
Storing inventory items
"""

from abc import abstractmethod
from collections import namedtuple
from six.moves.collections_abc import MutableMapping  # pylint: disable=deprecated-class
import logging

logger = logging.getLogger('default')

InventoryItem = namedtuple('InventoryItem', 'type stream payload expires tag')


class InventoryStorage(MutableMapping):
    """
    Base class for storing inventory
    (extendable for other items to store)
    """

    def __init__(self):
        logger.debug("DEBUG: Initializing InventoryStorage base class")
        self.numberOfInventoryLookupsPerformed = 0
        logger.debug("DEBUG: InventoryStorage initialized with lookup counter set to 0")

    @abstractmethod
    def __contains__(self, item):
        logger.debug("DEBUG: Checking if item exists in inventory")
        pass

    @abstractmethod
    def __getitem__(self, key):
        logger.debug("DEBUG: Getting inventory item by key")
        pass

    @abstractmethod
    def __setitem__(self, key, value):
        logger.debug("DEBUG: Setting inventory item")
        pass

    @abstractmethod
    def __delitem__(self, key):
        logger.debug("DEBUG: Deleting inventory item")
        pass

    @abstractmethod
    def __iter__(self):
        logger.debug("DEBUG: Creating inventory iterator")
        pass

    @abstractmethod
    def __len__(self):
        logger.debug("DEBUG: Getting inventory length")
        pass

    @abstractmethod
    def by_type_and_tag(self, objectType, tag):
        """Return objects filtered by object type and tag"""
        logger.debug(f"DEBUG: Filtering inventory by type {objectType} and tag {tag}")
        pass

    @abstractmethod
    def unexpired_hashes_by_stream(self, stream):
        """Return unexpired inventory vectors filtered by stream"""
        logger.debug(f"DEBUG: Getting unexpired hashes for stream {stream}")
        pass

    @abstractmethod
    def flush(self):
        """Flush cache"""
        logger.debug("DEBUG: Flushing inventory cache")
        pass

    @abstractmethod
    def clean(self):
        """Free memory / perform garbage collection"""
        logger.debug("DEBUG: Cleaning inventory storage")
        pass
