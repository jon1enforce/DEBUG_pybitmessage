# pylint: disable=too-many-instance-attributes, too-few-public-methods

"""
Kivy State variables are assigned here, they are separated from state.py
=================================
"""

import os
import threading
import logging

logger = logging.getLogger('default')

class KivyStateVariables(object):
    """This Class hold all the kivy state variables"""

    def __init__(self):
        logger.debug("DEBUG: Initializing KivyStateVariables")
        
        # Initialize all state variables with debug logging
        self.selected_address = ''
        logger.debug("DEBUG: selected_address initialized to empty string")
        
        self.navinstance = None
        logger.debug("DEBUG: navinstance initialized to None")
        
        self.mail_id = 0
        logger.debug("DEBUG: mail_id initialized to 0")
        
        self.my_address_obj = None
        logger.debug("DEBUG: my_address_obj initialized to None")
        
        self.detail_page_type = None
        logger.debug("DEBUG: detail_page_type initialized to None")
        
        self.ackdata = None
        logger.debug("DEBUG: ackdata initialized to None")
        
        self.status = None
        logger.debug("DEBUG: status initialized to None")
        
        self.screen_density = None
        logger.debug("DEBUG: screen_density initialized to None")
        
        self.msg_counter_objs = None
        logger.debug("DEBUG: msg_counter_objs initialized to None")
        
        self.check_sent_acc = None
        logger.debug("DEBUG: check_sent_acc initialized to None")
        
        self.sent_count = 0
        logger.debug("DEBUG: sent_count initialized to 0")
        
        self.inbox_count = 0
        logger.debug("DEBUG: inbox_count initialized to 0")
        
        self.trash_count = 0
        logger.debug("DEBUG: trash_count initialized to 0")
        
        self.draft_count = 0
        logger.debug("DEBUG: draft_count initialized to 0")
        
        self.all_count = 0
        logger.debug("DEBUG: all_count initialized to 0")
        
        self.searching_text = ''
        logger.debug("DEBUG: searching_text initialized to empty string")
        
        self.search_screen = ''
        logger.debug("DEBUG: search_screen initialized to empty string")
        
        self.send_draft_mail = None
        logger.debug("DEBUG: send_draft_mail initialized to None")
        
        self.is_allmail = False
        logger.debug("DEBUG: is_allmail initialized to False")
        
        self.in_composer = False
        logger.debug("DEBUG: in_composer initialized to False")
        
        self.available_credit = 0
        logger.debug("DEBUG: available_credit initialized to 0")
        
        self.in_sent_method = False
        logger.debug("DEBUG: in_sent_method initialized to False")
        
        self.in_search_mode = False
        logger.debug("DEBUG: in_search_mode initialized to False")
        
        self.image_dir = os.path.abspath(os.path.join('images', 'kivy'))
        logger.debug("DEBUG: image_dir set to: %s", self.image_dir)
        
        self.kivyui_ready = threading.Event()
        logger.debug("DEBUG: kivyui_ready Event initialized")
        
        self.file_manager = None
        logger.debug("DEBUG: file_manager initialized to None")
        
        self.manager_open = False
        logger.debug("DEBUG: manager_open initialized to False")
        
        logger.debug("DEBUG: KivyStateVariables initialization complete")

    def __setattr__(self, name, value):
        """Override __setattr__ to log state changes"""
        if hasattr(self, name):
            logger.debug("DEBUG: Changing state variable %s from %s to %s", 
                       name, getattr(self, name), value)
        else:
            logger.debug("DEBUG: Setting new state variable %s to %s", name, value)
        super(KivyStateVariables, self).__setattr__(name, value)

    def __str__(self):
        """Return string representation of state for debugging"""
        state_vars = "\n".join(f"{k}: {v}" for k, v in self.__dict__.items())
        return f"KivyStateVariables:\n{state_vars}"
