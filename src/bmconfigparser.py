"""
BMConfigParser class definition and default configuration settings
"""

import os
import shutil
import logging
from threading import Event
from datetime import datetime

from six import string_types
from six.moves import configparser
from unqstr import ustr

try:
    import state
except ImportError:
    from pybitmessage import state

try:
    SafeConfigParser = configparser.SafeConfigParser
except AttributeError:
    # alpine linux, python3.12
    SafeConfigParser = configparser.ConfigParser
config_ready = Event()

logger = logging.getLogger('bmconfigparser')

class BMConfigParser(SafeConfigParser):
    """
    Singleton class inherited from :class:`configparser.SafeConfigParser`
    with additional methods specific to bitmessage config.
    """
    # pylint: disable=too-many-ancestors
    _temp = {}

    def set(self, section, option, value=None):
        logger.debug("Setting config value: [%s] %s = %s", section, option, value)
        if self._optcre is self.OPTCRE or value:
            if not isinstance(value, string_types):
                logger.error("Config value must be string, got %s for [%s] %s", 
                           type(value), section, option)
                raise TypeError("option values must be strings")
        if not self.validate(section, option, value):
            logger.error("Invalid config value: [%s] %s = %s", section, option, value)
            raise ValueError("Invalid value %s" % value)
        return SafeConfigParser.set(self, section, option, value)

    def get(self, section, option, **kwargs):
        """Try returning temporary value before using parent get()"""
        try:
            val = self._temp[section][option]
            logger.debug("Getting temp config value: [%s] %s = %s", section, option, val)
            return val
        except KeyError:
            pass
        val = SafeConfigParser.get(self, section, option, **kwargs)
        logger.debug("Getting config value: [%s] %s = %s", section, option, val)
        return val

    def setTemp(self, section, option, value=None):
        """Temporary set option to value, not saving."""
        logger.debug("Setting temp config value: [%s] %s = %s", section, option, value)
        try:
            self._temp[section][option] = value
        except KeyError:
            self._temp[section] = {option: value}

    def safeGetBoolean(self, section, option):
        """Return value as boolean, False on exceptions"""
        try:
            val = self.getboolean(section, option)
            logger.debug("Getting boolean config: [%s] %s = %s", section, option, val)
            return val
        except (configparser.NoSectionError, configparser.NoOptionError,
                ValueError, AttributeError) as e:
            logger.debug("Failed to get boolean for [%s] %s: %s", section, option, str(e))
            return False

    def safeGetInt(self, section, option, default=0):
        """Return value as integer, default on exceptions,
        0 if default missing"""
        try:
            val = int(self.get(section, option))
            logger.debug("Getting int config: [%s] %s = %d", section, option, val)
            return val
        except (configparser.NoSectionError, configparser.NoOptionError,
                ValueError, AttributeError) as e:
            logger.debug("Failed to get int for [%s] %s: %s (using default %d)", 
                       section, option, str(e), default)
            return default

    def safeGetFloat(self, section, option, default=0.0):
        """Return value as float, default on exceptions,
        0.0 if default missing"""
        try:
            val = self.getfloat(section, option)
            logger.debug("Getting float config: [%s] %s = %f", section, option, val)
            return val
        except (configparser.NoSectionError, configparser.NoOptionError,
                ValueError, AttributeError) as e:
            logger.debug("Failed to get float for [%s] %s: %s (using default %f)", 
                       section, option, str(e), default)
            return default

    def safeGet(self, section, option, default=None):
        """
        Return value as is, default on exceptions, None if default missing
        """
        try:
            val = self.get(section, option)
            logger.debug("Getting config: [%s] %s = %s", section, option, val)
            return val
        except (configparser.NoSectionError, configparser.NoOptionError,
                ValueError, AttributeError) as e:
            logger.debug("Failed to get value for [%s] %s: %s (using default %s)", 
                       section, option, str(e), default)
            return default

    def items(self, section, raw=False, variables=None):
        """Return section variables as parent,
        but override the "raw" argument to always True"""
        logger.debug("Getting all items from section: %s", section)
        return SafeConfigParser.items(self, section, True, variables)

    def _reset(self):
        """
        Reset current config.
        There doesn't appear to be a built in method for this.
        """
        logger.debug("Resetting config parser")
        self._temp = {}
        sections = self.sections()
        for x in sections:
            self.remove_section(x)

    def read(self, filenames=None):
        """Read configuration from files"""
        logger.debug("Reading config files: %s", filenames)
        self._reset()
        default_path = os.path.join(os.path.dirname(__file__), 'default.ini')
        logger.debug("Loading default config from: %s", default_path)
        SafeConfigParser.read(self, default_path)
        if filenames:
            SafeConfigParser.read(self, filenames)

    def addresses(self, sort=False):
        """Return a list of local bitmessage addresses (from section labels)"""
        logger.debug("Getting list of addresses (sort=%s)", sort)
        sections = [x for x in self.sections() if x.startswith('BM-')]
        if sort:
            sections.sort(key=lambda item: ustr(self.get(item, 'label')).lower())
        logger.debug("Found %d addresses", len(sections))
        return sections

    def save(self):
        """Save the runtime config onto the filesystem"""
        fileName = os.path.join(state.appdata, 'keys.dat')
        fileNameBak = '.'.join([
            fileName, datetime.now().strftime("%Y%j%H%M%S%f"), 'bak'])
        
        logger.debug("Saving config to: %s", fileName)
        logger.debug("Creating backup at: %s", fileNameBak)
        
        # create a backup copy to prevent the accidental loss due to
        # the disk write failure
        try:
            shutil.copyfile(fileName, fileNameBak)
            # The backup succeeded.
            fileNameExisted = True
            logger.debug("Backup created successfully")
        except(IOError, Exception) as e:
            # The backup failed. This can happen if the file
            # didn't exist before.
            fileNameExisted = False
            logger.debug("Backup failed (file may not exist): %s", str(e))

        try:
            with open(fileName, 'w') as configfile:
                self.write(configfile)
            logger.debug("Config saved successfully")
        except Exception as e:
            logger.error("Failed to save config: %s", str(e))
            raise

        # delete the backup
        if fileNameExisted:
            try:
                os.remove(fileNameBak)
                logger.debug("Backup file removed")
            except Exception as e:
                logger.warning("Failed to remove backup file: %s", str(e))

    def validate(self, section, option, value):
        """Input validator interface (using factory pattern)"""
        logger.debug("Validating [%s] %s = %s", section, option, value)
        try:
            validator = getattr(self, 'validate_%s_%s' % (section, option))
            result = validator(value)
            logger.debug("Validation result: %s", result)
            return result
        except AttributeError:
            logger.debug("No custom validator for [%s] %s", section, option)
            return True

    @staticmethod
    def validate_bitmessagesettings_maxoutboundconnections(value):
        """Reject maxoutboundconnections that are too high or too low"""
        logger.debug("Validating maxoutboundconnections: %s", value)
        try:
            value = int(value)
        except ValueError:
            logger.debug("Invalid maxoutboundconnections (not an integer)")
            return False
        if value < 0 or value > 8:
            logger.debug("Invalid maxoutboundconnections (out of range 0-8)")
            return False
        return True

    def search_addresses(self, address, searched_text):
        """Return the searched label of MyAddress"""
        logger.debug("Searching address %s for: %s", address, searched_text)
        results = [x for x in [self.get(address, 'label').lower(),
                address.lower()] if searched_text in x]
        logger.debug("Search results: %s", results)
        return results

    def disable_address(self, address):
        """"Disabling the specific Address"""
        logger.debug("Disabling address: %s", address)
        self.set(str(address), 'enabled', 'false')
        self.save()

    def enable_address(self, address):
        """"Enabling the specific Address"""
        logger.debug("Enabling address: %s", address)
        self.set(address, 'enabled', 'true')
        self.save()


if not getattr(BMConfigParser, 'read_file', False):
    BMConfigParser.read_file = BMConfigParser.readfp
    logger.debug("Added read_file alias for readfp")

config = BMConfigParser()  # TODO: remove this crutch
logger.debug("Global config instance created")
