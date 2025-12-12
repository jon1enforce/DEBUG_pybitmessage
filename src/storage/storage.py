"""
Storing inventory items
"""

from abc import abstractmethod
from collections import namedtuple
from six.moves.collections_abc import MutableMapping  # pylint: disable=deprecated-class
import logging

logger = logging.getLogger('default')

# Flexiblere Version von InventoryItem, die mit unterschiedlicher Anzahl an Parametern umgehen kann
class InventoryItem(namedtuple('InventoryItemBase', 'type stream payload expires tag')):
    """
    Inventory item that can handle different numbers of arguments
    Falls nur wenige Parameter übergeben werden, werden Default-Werte verwendet
    """
    
    __slots__ = ()  # Namedtuples haben keine __dict__, also __slots__ leer lassen
    
    def __new__(cls, *args, **kwargs):
        # Standardwerte
        type_val = 0
        stream_val = 0
        payload_val = b''
        expires_val = 0
        tag_val = b''
        
        # Wenn Positional Arguments übergeben wurden
        if args:
            # Falls ein einziges Tuple/List übergeben wurde
            if len(args) == 1 and isinstance(args[0], (tuple, list)):
                args = args[0]
            
            # Je nach Anzahl der Argumente zuweisen
            if len(args) >= 1:
                type_val = args[0]
            if len(args) >= 2:
                stream_val = args[1]
            if len(args) >= 3:
                payload_val = args[2]
            if len(args) >= 4:
                expires_val = args[3]
            if len(args) >= 5:
                tag_val = args[4]
        
        # Keyword Arguments überschreiben die Positional Arguments
        if 'type' in kwargs:
            type_val = kwargs['type']
        if 'stream' in kwargs:
            stream_val = kwargs['stream']
        if 'payload' in kwargs:
            payload_val = kwargs['payload']
        if 'expires' in kwargs:
            expires_val = kwargs['expires']
        if 'tag' in kwargs:
            tag_val = kwargs['tag']
        
        # Namedtuple mit allen 5 Parametern erstellen
        return super(InventoryItem, cls).__new__(
            cls, type_val, stream_val, payload_val, expires_val, tag_val
        )
    
    @classmethod
    def from_fields(cls, type_val=0, stream_val=0, payload_val=b'', expires_val=0, tag_val=b''):
        """Alternative Factory-Methode für klare Benennung"""
        return cls(type=type_val, stream=stream_val, payload=payload_val, 
                  expires=expires_val, tag=tag_val)


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
