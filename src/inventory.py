"""The Inventory"""

import logging
# TODO make this dynamic, and watch out for frozen, like with messagetypes
import storage.filesystem
import storage.sqlite
from bmconfigparser import config

logger = logging.getLogger('default')

def create_inventory_instance(backend="sqlite"):
    """
    Create an instance of the inventory class
    defined in `storage.<backend>`.
    """
    logger.debug("DEBUG: create_inventory_instance called with backend: %s", backend)
    
    try:
        storage_module = getattr(storage, backend)
        logger.debug("DEBUG: Successfully imported storage module: %s", storage_module)
        
        class_name = "{}Inventory".format(backend.title())
        logger.debug("DEBUG: Looking for inventory class: %s", class_name)
        
        inventory_class = getattr(storage_module, class_name)
        logger.debug("DEBUG: Found inventory class: %s", inventory_class)
        
        instance = inventory_class()
        logger.debug("DEBUG: Successfully created inventory instance")
        
        return instance
    except AttributeError as e:
        logger.error("DEBUG: Failed to create inventory instance: %s", str(e))
        raise
    except Exception as e:
        logger.error("DEBUG: Unexpected error creating inventory instance: %s", str(e))
        raise


class Inventory:
    """
    Inventory class which uses storage backends
    to manage the inventory.
    """
    def __init__(self):
        logger.debug("DEBUG: Inventory.__init__ called")
        
        self._moduleName = config.safeGet("inventory", "storage")
        logger.debug("DEBUG: Using storage backend: %s", self._moduleName)
        
        self._realInventory = create_inventory_instance(self._moduleName)
        logger.debug("DEBUG: Created real inventory instance: %s", self._realInventory)
        
        self.numberOfInventoryLookupsPerformed = 0
        logger.debug("DEBUG: Initialized inventory lookup counter")

    # cheap inheritance copied from asyncore
    def __getattr__(self, attr):
        logger.debug("DEBUG: __getattr__ called with attribute: %s", attr)
        
        try:
            realRet = getattr(self._realInventory, attr)
            logger.debug("DEBUG: Successfully retrieved attribute from real inventory")
            return realRet
        except AttributeError as e:
            logger.error("DEBUG: Attribute not found in real inventory: %s", str(e))
            raise AttributeError(
                "%s instance has no attribute '%s'" %
                (self.__class__.__name__, attr)
            )

    def __contains__(self, key):
        logger.debug("DEBUG: __contains__ called with key: %s", key)
        
        self.numberOfInventoryLookupsPerformed += 1
        logger.debug("DEBUG: Incremented lookup counter to: %d", 
                    self.numberOfInventoryLookupsPerformed)
        
        result = key in self._realInventory
        logger.debug("DEBUG: Key %s %s in inventory", key, "is" if result else "is not")
        return result

    # hint for pylint: this is dictionary like object
    def __getitem__(self, key):
        logger.debug("DEBUG: __getitem__ called with key: %s", key)
        
        try:
            value = self._realInventory[key]
            logger.debug("DEBUG: Successfully retrieved item from inventory")
            return value
        except KeyError as e:
            logger.error("DEBUG: Key not found in inventory: %s", str(e))
            raise
        except Exception as e:
            logger.error("DEBUG: Error retrieving item from inventory: %s", str(e))
            raise

    def __setitem__(self, key, value):
        logger.debug("DEBUG: __setitem__ called with key: %s, value: %s", key, value)
        
        try:
            self._realInventory[key] = value
            logger.debug("DEBUG: Successfully set item in inventory")
        except Exception as e:
            logger.error("DEBUG: Error setting item in inventory: %s", str(e))
            raise
