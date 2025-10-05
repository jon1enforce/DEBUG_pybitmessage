import logging
import os
from importlib import import_module

logger = logging.getLogger('default')

# Whitelist der erlaubten Message-Types - NUR diese können instanziiert werden
ALLOWED_MESSAGE_TYPES = {
    'getpubkey': 'Getpubkey',
    'pubkey': 'Pubkey', 
    'msg': 'Msg',
    'broadcast': 'Broadcast'
}

def constructObject(data):
    """Constructing an object safely with whitelist validation"""
    # Prüfe ob der Message-Type in der Whitelist ist
    message_type = data.get("", "").lower()
    
    if message_type not in ALLOWED_MESSAGE_TYPES:
        logger.error("Blocked unauthorized message type: \"%s\"", message_type)
        return None
    
    try:
        # Verwende die vordefinierte Klasse aus der Whitelist
        class_name = ALLOWED_MESSAGE_TYPES[message_type]
        classBase = getattr(import_module(f".{message_type}", __name__), class_name)
        
    except (AttributeError, ImportError) as e:
        logger.error(
            "Error importing message type '%s': %s", 
            message_type, e, exc_info=True
        )
        return None
    except Exception as e:
        logger.error(
            "Unexpected error handling message type '%s': %s", 
            message_type, e, exc_info=True
        )
        return None

    try:
        # Instanziere das Objekt und dekodiere die Daten
        returnObj = classBase()
        returnObj.decode(data)
        
    except KeyError as e:
        logger.error("Missing mandatory key %s in message type '%s'", e, message_type)
        return None
    except Exception as e:
        logger.error(
            "Error decoding message type '%s': %s", 
            message_type, e, exc_info=True
        )
        return None
    else:
        logger.debug("Successfully processed message type: %s", message_type)
        return returnObj


# Dynamischer Import-Teil bleibt gleich, aber mit besserer Fehlerbehandlung
try:
    from pybitmessage import paths
except ImportError:
    paths = None

if paths and paths.frozen is not None:
    # In frozen/compiled Umgebungen: explizite Imports
    from . import getpubkey, pubkey, msg, broadcast  # noqa: F401
else:
    # In Entwicklungs-Umgebungen: dynamische Imports, aber nur für Whitelist-Types
    import os
    current_dir = os.path.dirname(__file__)
    
    for mod in os.listdir(current_dir):
        if mod == "__init__.py":
            continue
            
        splitted = os.path.splitext(mod)
        if splitted[1] != ".py" or splitted[0] not in ALLOWED_MESSAGE_TYPES:
            continue
            
        try:
            import_module(f".{splitted[0]}", __name__)
            logger.debug("Successfully imported message type module: %s", splitted[0])
        except ImportError as e:
            logger.error("Error importing message type module %s: %s", mod, e)
        except Exception as e:
            logger.error("Unexpected error importing %s: %s", mod, e)
