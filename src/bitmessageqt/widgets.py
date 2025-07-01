from qtpy import uic
import os.path
import paths
import logging

# Debugging setup
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def resource_path(resFile):
    """
    Find the full path to a resource file by searching in standard directories.
    
    Args:
        resFile (str): The resource filename to locate
        
    Returns:
        str: Full path to the resource file or None if not found
    """
    logger.debug(f"DEBUG: resource_path() called with resFile='{resFile}'")
    
    baseDir = paths.codePath()
    logger.debug(f"DEBUG: Base directory resolved to: '{baseDir}'")
    
    search_dirs = ("ui", "bitmessageqt")
    logger.debug(f"DEBUG: Will search in subdirectories: {search_dirs}")
    
    for subDir in search_dirs:
        path = os.path.join(baseDir, subDir, resFile)
        logger.debug(f"DEBUG: Checking path: '{path}'")
        
        if os.path.isfile(path):
            logger.debug(f"DEBUG: Found resource at: '{path}'")
            return path
            
    logger.warning(f"DEBUG: Resource file '{resFile}' not found in any searched directory")
    return None

def load(resFile, widget):
    """
    Load a UI file and apply it to the given widget.
    
    Args:
        resFile (str): The UI file to load
        widget (QWidget): The widget to apply the UI to
    """
    logger.debug(f"DEBUG: load() called with resFile='{resFile}', widget={widget}")
    
    ui_path = resource_path(resFile)
    if ui_path is None:
        logger.error(f"DEBUG: Failed to load UI file '{resFile}' - resource not found")
        return
        
    logger.debug(f"DEBUG: Loading UI from path: '{ui_path}'")
    try:
        uic.loadUi(ui_path, widget)
        logger.debug(f"DEBUG: Successfully loaded UI file '{resFile}' into widget")
    except Exception as e:
        logger.error(f"DEBUG: Failed to load UI file '{resFile}': {str(e)}")
        raise
