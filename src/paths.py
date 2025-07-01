"""
Path related functions
"""
import logging
import os
import re
import sys
from datetime import datetime
from shutil import move

logger = logging.getLogger('default')

# When using py2exe or py2app, the variable frozen is added to the sys
# namespace.  This can be used to setup a different code path for
# binary distributions vs source distributions.
frozen = getattr(sys, 'frozen', None)
logger.debug("DEBUG: frozen attribute: %s", frozen)


def lookupExeFolder():
    """Returns executable folder path"""
    logger.debug("DEBUG: lookupExeFolder called")
    if frozen:
        logger.debug("DEBUG: lookupExeFolder - frozen environment detected")
        if frozen == "macosx_app":
            logger.debug("DEBUG: lookupExeFolder - MacOS app bundle detected")
            exeFolder = os.path.dirname(sys.executable).split(os.path.sep)[0]
        else:
            logger.debug("DEBUG: lookupExeFolder - other frozen environment")
            exeFolder = os.path.dirname(sys.executable)
    elif os.getenv('APPIMAGE'):
        logger.debug("DEBUG: lookupExeFolder - APPIMAGE environment detected")
        exeFolder = os.path.dirname(os.getenv('APPIMAGE'))
    elif __file__:
        logger.debug("DEBUG: lookupExeFolder - using __file__ path")
        exeFolder = os.path.dirname(__file__)
    else:
        logger.debug("DEBUG: lookupExeFolder - no path found, returning empty string")
        return ''
    
    result = exeFolder + os.path.sep
    logger.debug("DEBUG: lookupExeFolder returning: %s", result)
    return result


def lookupAppdataFolder():
    """Returns path of the folder where application data is stored"""
    logger.debug("DEBUG: lookupAppdataFolder called")
    APPNAME = "PyBitmessage"
    dataFolder = os.environ.get('BITMESSAGE_HOME')
    
    if dataFolder:
        logger.debug("DEBUG: lookupAppdataFolder - BITMESSAGE_HOME found: %s", dataFolder)
        if dataFolder[-1] not in (os.path.sep, os.path.altsep):
            dataFolder += os.path.sep
    elif sys.platform == 'darwin':
        logger.debug("DEBUG: lookupAppdataFolder - Darwin platform detected")
        try:
            dataFolder = os.path.join(
                os.environ['HOME'],
                'Library/Application Support/', APPNAME
            ) + '/'
            logger.debug("DEBUG: lookupAppdataFolder - MacOS data folder: %s", dataFolder)
        except KeyError:
            logger.error("DEBUG: lookupAppdataFolder - Could not find home folder")
            sys.exit(
                'Could not find home folder, please report this message'
                ' and your OS X version to the BitMessage Github.')
    elif sys.platform.startswith('win'):
        logger.debug("DEBUG: lookupAppdataFolder - Windows platform detected")
        dataFolder = os.path.join(os.environ['APPDATA'], APPNAME) + os.path.sep
        logger.debug("DEBUG: lookupAppdataFolder - Windows data folder: %s", dataFolder)
    else:
        logger.debug("DEBUG: lookupAppdataFolder - assuming Unix-like platform")
        try:
            dataFolder = os.path.join(os.environ['XDG_CONFIG_HOME'], APPNAME)
            logger.debug("DEBUG: lookupAppdataFolder - XDG_CONFIG_HOME found: %s", dataFolder)
        except KeyError:
            dataFolder = os.path.join(os.environ['HOME'], '.config', APPNAME)
            logger.debug("DEBUG: lookupAppdataFolder - using default config location: %s", dataFolder)

        # Migrate existing data to the proper location
        # if this is an existing install
        old_path = os.path.join(os.environ['HOME'], '.%s' % APPNAME)
        logger.debug("DEBUG: lookupAppdataFolder - checking old data path: %s", old_path)
        try:
            move(old_path, dataFolder)
            logger.info('Moving data folder to %s', dataFolder)
        except IOError:
            logger.debug("DEBUG: lookupAppdataFolder - old directory does not exist or move failed")
            pass
        dataFolder = dataFolder + os.path.sep
    
    logger.debug("DEBUG: lookupAppdataFolder returning: %s", dataFolder)
    return dataFolder


def codePath():
    """Returns path to the program sources"""
    logger.debug("DEBUG: codePath called")
    if not frozen:
        logger.debug("DEBUG: codePath - not frozen, using __file__")
        result = os.path.dirname(__file__)
    else:
        if frozen == "macosx_app":
            logger.debug("DEBUG: codePath - MacOS app bundle detected")
            result = os.environ.get('RESOURCEPATH')
        else:
            logger.debug("DEBUG: codePath - other frozen environment, using MEIPASS")
            # pylint: disable=protected-access
            result = sys._MEIPASS
    
    logger.debug("DEBUG: codePath returning: %s", result)
    return result


def tail(f, lines=20):
    """Returns last lines in the f file object"""
    logger.debug("DEBUG: tail called with lines=%d", lines)
    total_lines_wanted = lines

    BLOCK_SIZE = 1024
    f.seek(0, 2)
    block_end_byte = f.tell()
    lines_to_go = total_lines_wanted
    block_number = -1
    # blocks of size BLOCK_SIZE, in reverse order starting
    # from the end of the file
    blocks = []
    while lines_to_go > 0 and block_end_byte > 0:
        if block_end_byte - BLOCK_SIZE > 0:
            # read the last block we haven't yet read
            f.seek(block_number * BLOCK_SIZE, 2)
            blocks.append(f.read(BLOCK_SIZE))
        else:
            # file too small, start from begining
            f.seek(0, 0)
            # only read what was not read
            blocks.append(f.read(block_end_byte))
        lines_found = blocks[-1].count('\n')
        lines_to_go -= lines_found
        block_end_byte -= BLOCK_SIZE
        block_number -= 1
        logger.debug("DEBUG: tail - lines_to_go=%d, block_end_byte=%d", lines_to_go, block_end_byte)
    
    all_read_text = ''.join(reversed(blocks))
    result = '\n'.join(all_read_text.splitlines()[-total_lines_wanted:])
    logger.debug("DEBUG: tail returning %d lines", len(result.splitlines()))
    return result


def lastCommit():
    """
    Returns last commit information as dict with 'commit' and 'time' keys
    """
    logger.debug("DEBUG: lastCommit called")
    githeadfile = os.path.join(codePath(), '..', '.git', 'logs', 'HEAD')
    result = {}
    
    if os.path.isfile(githeadfile):
        logger.debug("DEBUG: lastCommit - git head file found: %s", githeadfile)
        try:
            with open(githeadfile, 'rt') as githead:
                line = tail(githead, 1)
                logger.debug("DEBUG: lastCommit - last line: %s", line)
            
            result['commit'] = line.split()[1]
            logger.debug("DEBUG: lastCommit - commit hash: %s", result['commit'])
            
            timestamp_match = re.search(r'>\s*(.*?)\s', line)
            if timestamp_match:
                timestamp = float(timestamp_match.group(1))
                result['time'] = datetime.fromtimestamp(timestamp)
                logger.debug("DEBUG: lastCommit - commit time: %s", result['time'])
        except (IOError, AttributeError, TypeError) as e:
            logger.debug("DEBUG: lastCommit - error processing git file: %s", str(e))
            pass
    else:
        logger.debug("DEBUG: lastCommit - git head file not found")
    
    logger.debug("DEBUG: lastCommit returning: %s", result)
    return result
