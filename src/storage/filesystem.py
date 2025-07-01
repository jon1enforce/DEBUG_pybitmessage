"""
Module for using filesystem (directory with files) for inventory storage
"""
import logging
import os
import time
from binascii import hexlify, unhexlify
from threading import RLock

from paths import lookupAppdataFolder
from .storage import InventoryItem, InventoryStorage

logger = logging.getLogger('default')


class FilesystemInventory(InventoryStorage):
    """Filesystem for inventory storage"""
    topDir = "inventory"
    objectDir = "objects"
    metadataFilename = "metadata"
    dataFilename = "data"

    def __init__(self):
        logger.debug("DEBUG: Initializing FilesystemInventory")
        super(FilesystemInventory, self).__init__()
        self.baseDir = os.path.join(
            lookupAppdataFolder(), FilesystemInventory.topDir)
        logger.debug(f"DEBUG: Base directory set to: {self.baseDir}")

        for createDir in [self.baseDir, os.path.join(self.baseDir, "objects")]:
            if os.path.exists(createDir):
                if not os.path.isdir(createDir):
                    error_msg = f"{createDir} exists but it's not a directory"
                    logger.error(f"DEBUG: {error_msg}")
                    raise IOError(error_msg)
                logger.debug(f"DEBUG: Directory exists: {createDir}")
            else:
                logger.debug(f"DEBUG: Creating directory: {createDir}")
                os.makedirs(createDir)

        self.lock = RLock()
        self._inventory = {}
        logger.debug("DEBUG: Loading existing inventory from filesystem")
        self._load()
        logger.debug("DEBUG: FilesystemInventory initialization complete")

    def __contains__(self, hashval):
        logger.debug(f"DEBUG: Checking if hash exists: {hexlify(hashval)}")
        for stream, streamDict in self._inventory.items():
            if hashval in streamDict:
                logger.debug(f"DEBUG: Hash found in stream {stream}")
                return True
        logger.debug("DEBUG: Hash not found in inventory")
        return False

    def __delitem__(self, hash_):
        logger.debug(f"DEBUG: Delete attempted (not implemented) for hash: {hexlify(hash_)}")
        raise NotImplementedError

    def __getitem__(self, hashval):
        logger.debug(f"DEBUG: Retrieving item: {hexlify(hashval)}")
        for stream, streamDict in self._inventory.items():
            try:
                retval = streamDict[hashval]
                logger.debug(f"DEBUG: Found in stream {stream} - type: {retval.type}")
                
                if retval.payload is None:
                    logger.debug("DEBUG: Loading payload from filesystem")
                    retval = InventoryItem(
                        retval.type,
                        retval.stream,
                        self.getData(hashval),
                        retval.expires,
                        retval.tag)
                return retval
            except KeyError:
                continue
                
        logger.debug("DEBUG: Item not found in any stream")
        raise KeyError(hashval)

    def __setitem__(self, hashval, value):
        with self.lock:
            logger.debug(f"DEBUG: Setting item: {hexlify(hashval)}")
            value = InventoryItem(*value)
            object_dir = os.path.join(
                self.baseDir,
                FilesystemInventory.objectDir,
                hexlify(hashval).decode())
            
            try:
                logger.debug(f"DEBUG: Creating object directory: {object_dir}")
                os.makedirs(object_dir)
            except OSError:
                logger.debug("DEBUG: Object directory already exists")

            try:
                metadata_path = os.path.join(object_dir, FilesystemInventory.metadataFilename)
                data_path = os.path.join(object_dir, FilesystemInventory.dataFilename)
                
                logger.debug(f"DEBUG: Writing metadata to {metadata_path}")
                with open(metadata_path, "w") as f:
                    metadata = f"{value.type},{value.stream},{value.expires},{hexlify(value.tag).decode()},"
                    f.write(metadata)
                
                logger.debug(f"DEBUG: Writing payload ({len(value.payload)} bytes) to {data_path}")
                with open(data_path, "wb") as f:
                    f.write(value.payload)
                
                try:
                    self._inventory[value.stream][hashval] = value
                    logger.debug(f"DEBUG: Added to stream {value.stream} in memory cache")
                except KeyError:
                    self._inventory[value.stream] = {hashval: value}
                    logger.debug(f"DEBUG: Created new stream {value.stream} in memory cache")
                    
            except IOError as e:
                logger.error(f"DEBUG: Failed to write item: {str(e)}")
                raise KeyError

    def delHashId(self, hashval):
        """Remove object from inventory"""
        logger.debug(f"DEBUG: Deleting hash: {hexlify(hashval)}")
        hex_hash = hexlify(hashval).decode()
        base_path = os.path.join(self.baseDir, FilesystemInventory.objectDir, hex_hash)
        
        # Remove from memory cache
        for stream in self._inventory:
            try:
                del self._inventory[stream][hashval]
                logger.debug(f"DEBUG: Removed from stream {stream} in memory cache")
            except KeyError:
                pass

        with self.lock:
            # Remove metadata file
            try:
                os.remove(os.path.join(base_path, FilesystemInventory.metadataFilename))
                logger.debug("DEBUG: Removed metadata file")
            except IOError:
                logger.debug("DEBUG: Metadata file not found or already removed")

            # Remove data file
            try:
                os.remove(os.path.join(base_path, FilesystemInventory.dataFilename))
                logger.debug("DEBUG: Removed data file")
            except IOError:
                logger.debug("DEBUG: Data file not found or already removed")

            # Remove directory
            try:
                os.rmdir(base_path)
                logger.debug("DEBUG: Removed object directory")
            except IOError:
                logger.debug("DEBUG: Object directory not found or already removed")

    def __iter__(self):
        elems = []
        for stream, streamDict in self._inventory.items():
            elems.extend(streamDict.keys())
        logger.debug(f"DEBUG: Creating iterator with {len(elems)} items across {len(self._inventory)} streams")
        return elems.__iter__()

    def __len__(self):
        retval = 0
        for stream, streamDict in self._inventory.items():
            retval += len(streamDict)
        logger.debug(f"DEBUG: Inventory contains {retval} items across {len(self._inventory)} streams")
        return retval

    def _load(self):
        logger.debug("DEBUG: Loading inventory from filesystem")
        newInventory = {}
        loaded_count = 0
        error_count = 0
        
        for hashId in self.object_list():
            try:
                objectType, streamNumber, expiresTime, tag = self.getMetadata(hashId)
                try:
                    newInventory[streamNumber][hashId] = InventoryItem(
                        objectType, streamNumber, None, expiresTime, tag)
                except KeyError:
                    newInventory[streamNumber] = {
                        hashId: InventoryItem(objectType, streamNumber, None, expiresTime, tag)
                    }
                loaded_count += 1
            except KeyError as e:
                error_count += 1
                logger.debug(f'DEBUG: Error loading {hexlify(hashId)}: {str(e)}', exc_info=True)
        
        self._inventory = newInventory
        logger.debug(f"DEBUG: Loaded {loaded_count} items, {error_count} errors")

    def stream_list(self):
        """Return list of streams"""
        streams = list(self._inventory.keys())
        logger.debug(f"DEBUG: Returning {len(streams)} streams")
        return streams

    def object_list(self):
        """Return inventory vectors (hashes) from a directory"""
        dir_path = os.path.join(self.baseDir, FilesystemInventory.objectDir)
        try:
            items = os.listdir(dir_path)
            logger.debug(f"DEBUG: Found {len(items)} objects in {dir_path}")
            return [unhexlify(x) for x in items]
        except OSError as e:
            logger.error(f"DEBUG: Error listing objects: {str(e)}")
            return []

    def getData(self, hashId):
        """Get object data"""
        hex_hash = hexlify(hashId).decode()
        data_path = os.path.join(
            self.baseDir,
            FilesystemInventory.objectDir,
            hex_hash,
            FilesystemInventory.dataFilename)
        
        logger.debug(f"DEBUG: Reading data from {data_path}")
        try:
            with open(data_path, "rb") as f:
                data = f.read()
                logger.debug(f"DEBUG: Read {len(data)} bytes")
                return data
        except IOError as e:
            logger.error(f"DEBUG: Error reading data: {str(e)}")
            raise AttributeError

    def getMetadata(self, hashId):
        """Get object metadata"""
        hex_hash = hexlify(hashId).decode()
        metadata_path = os.path.join(
            self.baseDir,
            FilesystemInventory.objectDir,
            hex_hash,
            FilesystemInventory.metadataFilename)
        
        logger.debug(f"DEBUG: Reading metadata from {metadata_path}")
        try:
            with open(metadata_path, "r") as f:
                content = f.read()
                parts = content.split(",", 4)
                objectType, streamNumber, expiresTime, tag = parts[:4]
                
                logger.debug(f"DEBUG: Metadata - type: {objectType}, stream: {streamNumber}, expires: {expiresTime}")
                return [
                    int(objectType),
                    int(streamNumber),
                    int(expiresTime),
                    unhexlify(tag)]
        except IOError as e:
            logger.error(f"DEBUG: Error reading metadata: {str(e)}")
            raise KeyError

    def by_type_and_tag(self, objectType, tag):
        """Get a list of objects filtered by object type and tag"""
        logger.debug(f"DEBUG: Filtering by type {objectType} and tag {hexlify(tag)}")
        retval = []
        
        for stream, streamDict in self._inventory.items():
            for hashId, item in streamDict.items():
                if item.type == objectType and item.tag == tag:
                    try:
                        if item.payload is None:
                            logger.debug(f"DEBUG: Loading payload for {hexlify(hashId)}")
                            item.payload = self.getData(hashId)
                        retval.append(InventoryItem(
                            item.type,
                            item.stream,
                            item.payload,
                            item.expires,
                            item.tag))
                    except IOError as e:
                        logger.debug(f"DEBUG: Error loading payload: {str(e)}")
                        continue
        
        logger.debug(f"DEBUG: Found {len(retval)} matching items")
        return retval

    def hashes_by_stream(self, stream):
        """Return inventory vectors (hashes) for a stream"""
        logger.debug(f"DEBUG: Getting hashes for stream {stream}")
        try:
            hashes = list(self._inventory[stream].keys())
            logger.debug(f"DEBUG: Found {len(hashes)} hashes")
            return hashes
        except KeyError:
            logger.debug("DEBUG: Stream not found")
            return []

    def unexpired_hashes_by_stream(self, stream):
        """Return unexpired hashes in the inventory for a particular stream"""
        current_time = int(time.time())
        logger.debug(f"DEBUG: Checking unexpired hashes for stream {stream} at {current_time}")
        
        try:
            result = [
                x for x, value in self._inventory[stream].items()
                if value.expires > current_time]
            logger.debug(f"DEBUG: Found {len(result)} unexpired hashes")
            return result
        except KeyError:
            logger.debug("DEBUG: Stream not found")
            return []

    def flush(self):
        """Flush the inventory and create a new, empty one"""
        logger.debug("DEBUG: Flushing inventory (reloading from filesystem)")
        self._load()

    def clean(self):
        """Clean out old items from the inventory"""
        minTime = int(time.time()) - 60 * 60 * 30
        logger.debug(f"DEBUG: Cleaning inventory (removing items before {minTime})")
        deletes = []
        
        for stream, streamDict in self._inventory.items():
            for hashId, item in streamDict.items():
                if item.expires < minTime:
                    deletes.append(hashId)
        
        logger.debug(f"DEBUG: Found {len(deletes)} items to clean")
        for hashId in deletes:
            self.delHashId(hashId)
        logger.debug("DEBUG: Cleanup complete")
