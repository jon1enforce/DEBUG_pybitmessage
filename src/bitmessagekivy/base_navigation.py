# pylint: disable=unused-argument, no-name-in-module, too-few-public-methods
"""
    Base class for Navigation Drawer
"""

import logging
from kivy.lang import Observable
from kivy.properties import (
    BooleanProperty,
    NumericProperty,
    StringProperty
)
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.spinner import Spinner
from kivy.clock import Clock
from kivy.core.window import Window
from kivymd.uix.list import (
    OneLineAvatarIconListItem,
    OneLineListItem
)
from pybitmessage.bmconfigparser import config

logger = logging.getLogger('default')

class BaseLanguage(Observable):
    """UI Language"""
    observers = []
    lang = None

    def __init__(self, defaultlang):
        logger.debug("DEBUG: Initializing BaseLanguage with default: %s", defaultlang)
        super(BaseLanguage, self).__init__()
        self.ugettext = None
        self.lang = defaultlang
        logger.debug("DEBUG: BaseLanguage initialized")

    @staticmethod
    def _(text):
        logger.debug("DEBUG: BaseLanguage translation lookup for: %s", text)
        return text


class BaseNavigationItem(OneLineAvatarIconListItem):
    """NavigationItem class for kivy Ui"""
    badge_text = StringProperty()
    icon = StringProperty()
    active = BooleanProperty(False)

    def currentlyActive(self):
        """Currenly active"""
        logger.debug("DEBUG: Setting navigation item as active: %s", self.text)
        for nav_obj in self.parent.children:
            nav_obj.active = False
            logger.debug("DEBUG: Deactivated item: %s", nav_obj.text)
        self.active = True
        logger.debug("DEBUG: Activated item: %s", self.text)


class BaseNavigationDrawerDivider(OneLineListItem):
    """
    A small full-width divider that can be placed
    in the :class:`MDNavigationDrawer`
    """

    disabled = True
    divider = None
    _txt_top_pad = NumericProperty(dp(8))
    _txt_bot_pad = NumericProperty(dp(8))

    def __init__(self, **kwargs):
        logger.debug("DEBUG: Initializing NavigationDrawerDivider")
        super(BaseNavigationDrawerDivider, self).__init__(**kwargs)
        self.height = dp(16)
        logger.debug("DEBUG: NavigationDrawerDivider initialized with height: %s", self.height)


class BaseNavigationDrawerSubheader(OneLineListItem):
    """
    A subheader for separating content in :class:`MDNavigationDrawer`

    Works well alongside :class:`NavigationDrawerDivider`
    """

    disabled = True
    divider = None
    theme_text_color = 'Secondary'

    def __init__(self, **kwargs):
        logger.debug("DEBUG: Initializing NavigationDrawerSubheader")
        super(BaseNavigationDrawerSubheader, self).__init__(**kwargs)
        logger.debug("DEBUG: NavigationDrawerSubheader initialized")


class BaseContentNavigationDrawer(BoxLayout):
    """ContentNavigationDrawer class for kivy Uir"""

    def __init__(self, *args, **kwargs):
        """Method used for contentNavigationDrawer"""
        logger.debug("DEBUG: Initializing ContentNavigationDrawer")
        super(BaseContentNavigationDrawer, self).__init__(*args, **kwargs)
        Clock.schedule_once(self.init_ui, 0)
        logger.debug("DEBUG: Scheduled init_ui for ContentNavigationDrawer")

    def init_ui(self, dt=0):
        """Clock Schdule for class contentNavigationDrawer"""
        logger.debug("DEBUG: Initializing UI for ContentNavigationDrawer")
        self.ids.scroll_y.bind(scroll_y=self.check_scroll_y)
        logger.debug("DEBUG: Bound scroll_y event handler")

    def check_scroll_y(self, instance, somethingelse):
        """show data on scroll down"""
        if self.ids.identity_dropdown.is_open:
            logger.debug("DEBUG: Closing identity dropdown due to scrolling")
            self.ids.identity_dropdown.is_open = False


class BaseIdentitySpinner(Spinner):
    """Base Class for Identity Spinner(Dropdown)"""

    def __init__(self, *args, **kwargs):
        """Method used for setting size of spinner"""
        logger.debug("DEBUG: Initializing IdentitySpinner")
        super(BaseIdentitySpinner, self).__init__(*args, **kwargs)
        self.dropdown_cls.max_height = Window.size[1] / 3
        logger.debug("DEBUG: Set dropdown max height to: %s", self.dropdown_cls.max_height)
        
        self.values = list(addr for addr in config.addresses()
                         if config.getboolean(str(addr), 'enabled'))
        logger.debug("DEBUG: Loaded %d enabled identities into spinner", len(self.values))
        logger.debug("DEBUG: IdentitySpinner initialized")
