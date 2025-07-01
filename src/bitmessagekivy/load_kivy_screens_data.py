"""
    Load kivy screens data from json
"""
import os
import json
import importlib
import logging

logger = logging.getLogger('default')

data_screen_dict = {}


def load_screen_json(data_file="screens_data.json"):
    """Load screens data from json"""
    logger.debug("DEBUG: Starting to load screen data from JSON")
    
    try:
        json_path = os.path.join(os.path.dirname(__file__), data_file)
        logger.debug("DEBUG: JSON file path: %s", json_path)
        
        with open(json_path) as read_file:
            logger.debug("DEBUG: Successfully opened JSON file")
            all_data = json.load(read_file)
            data_screens = list(all_data.keys())
            logger.debug("DEBUG: Loaded %d screen configurations", len(data_screens))
            logger.debug("DEBUG: Screen names: %s", data_screens)
        
        for key in all_data:
            if all_data[key]['Import']:
                import_data = all_data.get(key)['Import']
                logger.debug("DEBUG: Processing import for screen '%s': %s", key, import_data)
                
                import_to = import_data.split("import")[1].strip()
                import_from = import_data.split("import")[0].split('from')[1].strip()
                logger.debug("DEBUG: Import details - from: '%s', to: '%s'", import_from, import_to)
                
                try:
                    data_screen_dict[import_to] = importlib.import_module(import_from, import_to)
                    logger.debug("DEBUG: Successfully imported module '%s' as '%s'", import_from, import_to)
                except ImportError as e:
                    logger.error("DEBUG: Failed to import module '%s': %s", import_from, str(e))
                    raise
                except Exception as e:
                    logger.error("DEBUG: Unexpected error importing module '%s': %s", import_from, str(e))
                    raise
        
        logger.debug("DEBUG: Completed loading screen data. Total screens: %d", len(data_screens))
        logger.debug("DEBUG: Data screen dictionary contains %d entries", len(data_screen_dict))
        return data_screens, all_data, data_screen_dict, 'success'
    
    except FileNotFoundError:
        logger.error("DEBUG: JSON file not found at path: %s", json_path)
        raise
    except json.JSONDecodeError as e:
        logger.error("DEBUG: Invalid JSON format in file: %s. Error: %s", data_file, str(e))
        raise
    except Exception as e:
        logger.error("DEBUG: Unexpected error loading screen data: %s", str(e))
        raise
