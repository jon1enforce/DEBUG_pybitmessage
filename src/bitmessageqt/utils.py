import hashlib
import os
import logging

from qtpy import QtGui

import state
from addresses import addBMIfNotPresent
from bmconfigparser import config

# Debugging setup
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

str_broadcast_subscribers = '[Broadcast subscribers]'
str_chan = '[chan]'

def identiconize(address):
    """
    Generate an identicon for the given address using the configured library.
    
    Args:
        address (str): The address to generate identicon for
        
    Returns:
        QtGui.QIcon: Generated identicon or empty icon if disabled in config
    """
    logger.debug(f"DEBUG: identiconize() called with address='{address}'")
    size = 48

    if not config.getboolean('bitmessagesettings', 'useidenticons'):
        logger.debug("DEBUG: Identicons disabled in config, returning empty icon")
        return QtGui.QIcon()

    identicon_lib = config.safeGet(
        'bitmessagesettings', 'identiconlib', 'qidenticon_two_x')
    logger.debug(f"DEBUG: Using identicon library: '{identicon_lib}'")

    data = addBMIfNotPresent(address) + config.get(
        'bitmessagesettings', 'identiconsuffix')
    data = data.encode("utf-8", "replace")
    logger.debug(f"DEBUG: Identicon generation data: '{data}'")

    if identicon_lib[:len('qidenticon')] == 'qidenticon':
        logger.debug("DEBUG: Using qidenticon library")
        import qidenticon
        icon_hash = hashlib.md5(data).hexdigest()
        logger.debug(f"DEBUG: Generated MD5 hash: {icon_hash}")
        
        use_two_colors = (identicon_lib[:len('qidenticon_two')] == 'qidenticon_two')
        opacity = int(
            identicon_lib not in (
                'qidenticon_x', 'qidenticon_two_x',
                'qidenticon_b', 'qidenticon_two_b'
            )) * 255
        penwidth = 0
        
        logger.debug(f"DEBUG: qidenticon params - two_colors: {use_two_colors}, opacity: {opacity}, penwidth: {penwidth}")
        
        try:
            image = qidenticon.render_identicon(
                int(icon_hash, 16), size, use_two_colors, opacity, penwidth)
            idcon = QtGui.QIcon()
            idcon.addPixmap(image, QtGui.QIcon.Normal, QtGui.QIcon.Off)
            logger.debug("DEBUG: Successfully generated qidenticon")
            return idcon
        except Exception as e:
            logger.error(f"DEBUG: Error generating qidenticon: {str(e)}")
            return QtGui.QIcon()
            
    elif identicon_lib == 'pydenticon':
        logger.debug("DEBUG: Using pydenticon library")
        try:
            from pydenticon import Pydenticon
            idcon_render = Pydenticon(data, size * 3)
            rendering = idcon_render._render()
            data = rendering.convert("RGBA").tostring("raw", "RGBA")
            qim = QtGui.QImage(data, size, size, QtGui.QImage.Format_ARGB32)
            pix = QtGui.QPixmap.fromImage(qim)
            idcon = QtGui.QIcon()
            idcon.addPixmap(pix, QtGui.QIcon.Normal, QtGui.QIcon.Off)
            logger.debug("DEBUG: Successfully generated pydenticon")
            return idcon
        except ImportError:
            logger.error("DEBUG: pydenticon library not available")
        except Exception as e:
            logger.error(f"DEBUG: Error generating pydenticon: {str(e)}")
    
    logger.warning("DEBUG: No valid identicon library found, returning empty icon")
    return QtGui.QIcon()

def avatarize(address):
    """
    Loads a supported image for the given address' hash from 'avatars' folder.
    Falls back to default avatar if 'default.*' file exists.
    Falls back to identiconize(address) if no avatar found.
    
    Args:
        address (str): The address to find/generate avatar for
        
    Returns:
        QtGui.QIcon: Found or generated avatar icon
    """
    logger.debug(f"DEBUG: avatarize() called with address='{address}'")
    
    idcon = QtGui.QIcon()
    
    if address == str_broadcast_subscribers:
        logger.debug("DEBUG: Handling broadcast subscribers special case")
        icon_hash = address
    else:
        icon_hash = hashlib.md5(addBMIfNotPresent(address).encode("utf-8", "replace")).hexdigest()
    
    logger.debug(f"DEBUG: Avatar hash: '{icon_hash}'")
    
    extensions = [
        'PNG', 'GIF', 'JPG', 'JPEG', 'SVG', 'BMP', 'MNG', 'PBM', 'PGM', 'PPM',
        'TIFF', 'XBM', 'XPM', 'TGA']
    
    # Try to find specific avatar
    for ext in extensions:
        lower_hash = state.appdata + 'avatars/' + icon_hash + '.' + ext.lower()
        upper_hash = state.appdata + 'avatars/' + icon_hash + '.' + ext.upper()
        
        if os.path.isfile(lower_hash):
            logger.debug(f"DEBUG: Found avatar at: '{lower_hash}'")
            idcon.addFile(lower_hash)
            return idcon
        elif os.path.isfile(upper_hash):
            logger.debug(f"DEBUG: Found avatar at: '{upper_hash}'")
            idcon.addFile(upper_hash)
            return idcon
    
    logger.debug("DEBUG: No specific avatar found, checking for default avatar")
    
    # Try to find default avatar
    for ext in extensions:
        lower_default = state.appdata + 'avatars/' + 'default.' + ext.lower()
        upper_default = state.appdata + 'avatars/' + 'default.' + ext.upper()
        
        if os.path.isfile(lower_default):
            logger.debug(f"DEBUG: Found default avatar at: '{lower_default}'")
            idcon.addFile(lower_default)
            return idcon
        elif os.path.isfile(upper_default):
            logger.debug(f"DEBUG: Found default avatar at: '{upper_default}'")
            idcon.addFile(upper_default)
            return idcon
    
    logger.debug("DEBUG: No avatar found, falling back to identicon")
    return identiconize(address)
