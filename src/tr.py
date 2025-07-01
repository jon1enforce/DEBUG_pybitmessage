"""
Slim layer providing environment agnostic _translate()
"""

import sys
import logging
from unqstr import ustr

# Debug-Setup
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)
logger.info("Initializing translation module")

try:
    import state
    logger.debug("Successfully imported state module directly")
except ImportError:
    from . import state
    logger.debug("Imported state module relatively")

logger.debug(f"GUI enabled: {state.enableGUI}, curses mode: {state.curses}")

def _tr_dummy(context, text, disambiguation=None, n=None):
    # pylint: disable=unused-argument
    logger.debug(f"Dummy translation called - context: {context}, text: {text}, "
                 f"disambiguation: {disambiguation}, n: {n}")
    return text

if state.enableGUI and not state.curses:
    logger.debug("GUI is enabled and not in curses mode, attempting Qt import")
    try:
        from qtpy import QtWidgets, QtCore
        logger.debug("Successfully imported QtWidgets and QtCore from qtpy")
        _translate = QtWidgets.QApplication.translate
        logger.debug("Using Qt's translation function")
    except ImportError as e:
        logger.error(f"Failed to import Qt modules: {str(e)}")
        _translate = _tr_dummy
        logger.warning("Falling back to dummy translation")
else:
    logger.debug("GUI disabled or in curses mode, using dummy translation")
    _translate = _tr_dummy

logger.info("Translation module initialized")
