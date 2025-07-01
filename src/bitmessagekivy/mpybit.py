# pylint: disable=too-many-public-methods, unused-variable, too-many-ancestors
# pylint: disable=no-name-in-module, too-few-public-methods, unused-argument
# pylint: disable=attribute-defined-outside-init, too-many-instance-attributes

"""
Bitmessage android(mobile) interface
"""

import os
import logging
import sys
from functools import partial
from PIL import Image as PilImage

from kivy.clock import Clock
from kivy.lang import Builder
from kivy.core.window import Window
from kivy.uix.boxlayout import BoxLayout

from kivymd.app import MDApp
from kivymd.uix.label import MDLabel
from kivymd.uix.dialog import MDDialog
from kivymd.uix.list import (
    IRightBodyTouch
)
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.bottomsheet import MDCustomBottomSheet
from kivymd.uix.filemanager import MDFileManager

from pybitmessage.bitmessagekivy.kivy_state import KivyStateVariables
from pybitmessage.bitmessagekivy.base_navigation import (
    BaseLanguage, BaseNavigationItem, BaseNavigationDrawerDivider,
    BaseNavigationDrawerSubheader, BaseContentNavigationDrawer,
    BaseIdentitySpinner
)
from pybitmessage.bmconfigparser import config  # noqa: F401
from pybitmessage.bitmessagekivy import identiconGeneration
from pybitmessage.bitmessagekivy.get_platform import platform
from pybitmessage.bitmessagekivy.baseclass.common import toast, load_image_path, get_identity_list
from pybitmessage.bitmessagekivy.load_kivy_screens_data import load_screen_json

from pybitmessage.bitmessagekivy.baseclass.popup import (
    AddAddressPopup, AppClosingPopup, AddressChangingLoader
)
from pybitmessage.bitmessagekivy.baseclass.login import *  # noqa: F401, F403
from pybitmessage.bitmessagekivy.uikivysignaler import UIkivySignaler

from pybitmessage.mockbm.helper_startup import loadConfig, total_encrypted_messages_per_month

logger = logging.getLogger('default')


class Lang(BaseLanguage):
    """UI Language"""


class NavigationItem(BaseNavigationItem):
    """NavigationItem class for kivy Ui"""


class NavigationDrawerDivider(BaseNavigationDrawerDivider):
    """
    A small full-width divider that can be placed
    in the :class:`MDNavigationDrawer`
    """


class NavigationDrawerSubheader(BaseNavigationDrawerSubheader):
    """
    A subheader for separating content in :class:`MDNavigationDrawer`

    Works well alongside :class:`NavigationDrawerDivider`
    """


class ContentNavigationDrawer(BaseContentNavigationDrawer):
    """ContentNavigationDrawer class for kivy Uir"""


class BadgeText(IRightBodyTouch, MDLabel):
    """BadgeText class for kivy Ui"""


class IdentitySpinner(BaseIdentitySpinner):
    """Identity Dropdown in Side Navigation bar"""


class NavigateApp(MDApp):
    """Navigation Layout of class"""

    kivy_state = KivyStateVariables()
    title = "PyBitmessage"
    identity_list = get_identity_list()
    image_path = load_image_path()
    app_platform = platform
    encrypted_messages_per_month = total_encrypted_messages_per_month()
    tr = Lang("en")  # for changing in franch replace en with fr

    def __init__(self):
        logger.debug("DEBUG: Initializing NavigateApp")
        super(NavigateApp, self).__init__()
        # workaround for relative imports
        sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
        logger.debug("DEBUG: Added to sys.path: %s", os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
        
        self.data_screens, self.all_data, self.data_screen_dict, response = load_screen_json()
        logger.debug("DEBUG: Loaded screen data - screens: %d, all_data: %d, response: %s", 
                   len(self.data_screens), len(self.all_data), response)
        
        self.kivy_state_obj = KivyStateVariables()
        self.image_dir = load_image_path()
        self.kivy_state_obj.screen_density = Window.size
        self.window_size = self.kivy_state_obj.screen_density
        logger.debug("DEBUG: Window size initialized: %s", self.window_size)

    def build(self):
        """Method builds the widget"""
        logger.debug("DEBUG: Starting build process")
        for kv in self.data_screens:
            kv_path = os.path.join(
                os.path.dirname(__file__),
                'kv',
                '{0}.kv'.format(self.all_data[kv]["kv_string"]),
            )
            logger.debug("DEBUG: Loading KV file: %s", kv_path)
            Builder.load_file(kv_path)
        
        Window.bind(on_request_close=self.on_request_close)
        main_kv_path = os.path.join(os.path.dirname(__file__), 'main.kv')
        logger.debug("DEBUG: Loading main KV file: %s", main_kv_path)
        return Builder.load_file(main_kv_path)

    def set_screen(self, screen_name):
        """Set the screen name when navigate to other screens"""
        logger.debug("DEBUG: Setting screen to: %s", screen_name)
        self.root.ids.scr_mngr.current = screen_name

    def run(self):
        """Running the widgets"""
        logger.debug("DEBUG: Starting application run")
        loadConfig()
        
        kivysignalthread = UIkivySignaler()
        kivysignalthread.daemon = True
        kivysignalthread.start()
        logger.debug("DEBUG: Started UIkivySignaler thread")
        
        self.kivy_state_obj.kivyui_ready.set()
        logger.debug("DEBUG: Kivy UI ready flag set")
        
        super(NavigateApp, self).run()

    def addingtoaddressbook(self):
        """Dialog for saving address"""
        logger.debug("DEBUG: Opening 'Add contact' dialog")
        width = .85 if platform == 'android' else .8
        self.add_popup = MDDialog(
            title='Add contact',
            type="custom",
            size_hint=(width, .23),
            content_cls=AddAddressPopup(),
            buttons=[
                MDRaisedButton(
                    text="Save",
                    on_release=self.savecontact,
                ),
                MDRaisedButton(
                    text="Cancel",
                    on_release=self.close_pop,
                ),
                MDRaisedButton(
                    text="Scan QR code",
                    on_release=self.scan_qr_code,
                ),
            ],
        )
        self.add_popup.auto_dismiss = False
        self.add_popup.open()
        logger.debug("DEBUG: 'Add contact' dialog opened")

    def scan_qr_code(self, instance):
        """this method is used for showing QR code scanner"""
        logger.debug("DEBUG: Attempting to scan QR code")
        if self.is_camara_attached():
            logger.debug("DEBUG: Camera is available, showing scanner")
            self.add_popup.dismiss()
            self.root.ids.id_scanscreen.get_screen(self.root.ids.scr_mngr.current, self.add_popup)
            self.root.ids.scr_mngr.current = 'scanscreen'
        else:
            alert_text = (
                'Currently this feature is not avaialbe!' if platform == 'android' else 'Camera is not available!')
            logger.debug("DEBUG: Camera not available, showing alert: %s", alert_text)
            self.add_popup.dismiss()
            toast(alert_text)

    def is_camara_attached(self):
        """This method is for checking the camera is available or not"""
        logger.debug("DEBUG: Checking camera availability")
        self.root.ids.id_scanscreen.check_camera()
        is_available = self.root.ids.id_scanscreen.camera_available
        logger.debug("DEBUG: Camera available: %s", is_available)
        return is_available

    def savecontact(self, instance):
        """Method is used for saving contacts"""
        logger.debug("DEBUG: Saving contact")
        popup_obj = self.add_popup.content_cls
        label = popup_obj.ids.label.text.strip()
        address = popup_obj.ids.address.text.strip()
        logger.debug("DEBUG: Contact details - label: %s, address: %s", label, address)
        
        popup_obj.ids.label.focus = not label
        # default focus on address field
        popup_obj.ids.address.focus = label or not address

    def close_pop(self, instance):
        """Close the popup"""
        logger.debug("DEBUG: Closing popup")
        self.add_popup.dismiss()
        toast('Canceled')

    def loadMyAddressScreen(self, action):
        """loadMyAddressScreen method spin the loader"""
        logger.debug("DEBUG: Loading MyAddress screen with action: %s", action)
        if len(self.root.ids.id_myaddress.children) <= 2:
            self.root.ids.id_myaddress.children[0].active = action
        else:
            self.root.ids.id_myaddress.children[1].active = action

    def load_screen(self, instance):
        """This method is used for loading screen on every click"""
        logger.debug("DEBUG: Loading screen for: %s", instance.text)
        if instance.text == 'Inbox':
            self.root.ids.scr_mngr.current = 'inbox'
            self.root.ids.id_inbox.children[1].active = True
        elif instance.text == 'Trash':
            self.root.ids.scr_mngr.current = 'trash'
            try:
                self.root.ids.id_trash.children[1].active = True
            except Exception as e:
                logger.debug("DEBUG: Exception in trash screen loading: %s", str(e))
                self.root.ids.id_trash.children[0].children[1].active = True
        Clock.schedule_once(partial(self.load_screen_callback, instance), 1)

    def load_screen_callback(self, instance, dt=0):
        """This method is rotating loader for few seconds"""
        logger.debug("DEBUG: Executing screen callback for: %s", instance.text)
        if instance.text == 'Inbox':
            self.root.ids.id_inbox.ids.ml.clear_widgets()
            self.root.ids.id_inbox.loadMessagelist(self.kivy_state_obj.selected_address)
            self.root.ids.id_inbox.children[1].active = False
        elif instance.text == 'Trash':
            self.root.ids.id_trash.clear_widgets()
            self.root.ids.id_trash.add_widget(self.data_screen_dict['Trash'].Trash())
            try:
                self.root.ids.id_trash.children[1].active = False
            except Exception as e:
                logger.debug("DEBUG: Exception in trash screen callback: %s", str(e))
                self.root.ids.id_trash.children[0].children[1].active = False

    @staticmethod
    def get_enabled_addresses():
        """Getting list of all the enabled addresses"""
        addresses = [addr for addr in config.addresses()
                     if config.getboolean(str(addr), 'enabled')]
        logger.debug("DEBUG: Found %d enabled addresses", len(addresses))
        return addresses

    @staticmethod
    def format_address(address):
        """Formatting address"""
        formatted = " ({0})".format(address)
        logger.debug("DEBUG: Formatted address: %s", formatted)
        return formatted

    @staticmethod
    def format_label(label):
        """Formatting label"""
        if label:
            f_name = label.split()
            truncate_string = '...'
            f_name_max_length = 15
            formatted_label = f_name[0][:14].capitalize() + truncate_string if len(
                f_name[0]) > f_name_max_length else f_name[0].capitalize()
            logger.debug("DEBUG: Formatted label: %s", formatted_label)
            return formatted_label
        logger.debug("DEBUG: Empty label received")
        return ''

    @staticmethod
    def format_address_and_label(address=None):
        """Getting formatted address information"""
        if not address:
            try:
                address = NavigateApp.get_enabled_addresses()[0]
                logger.debug("DEBUG: Using first enabled address: %s", address)
            except IndexError:
                logger.debug("DEBUG: No enabled addresses found")
                return ''
        
        formatted = "{0}{1}".format(
            NavigateApp.format_label(config.get(address, "label")),
            NavigateApp.format_address(address)
        )
        logger.debug("DEBUG: Combined formatted address and label: %s", formatted)
        return formatted

    def getDefaultAccData(self, instance):
        """Getting Default Account Data"""
        logger.debug("DEBUG: Getting default account data")
        if self.identity_list:
            self.kivy_state_obj.selected_address = first_addr = self.identity_list[0]
            logger.debug("DEBUG: Using first identity: %s", first_addr)
            return first_addr
        logger.debug("DEBUG: No identities available")
        return 'Select Address'

    def getCurrentAccountData(self, text):
        """Get Current Address Account Data"""
        logger.debug("DEBUG: Getting current account data for: %s", text)
        if text != '':
            if os.path.exists(os.path.join(
                    self.image_dir, 'default_identicon', '{}.png'.format(text))
            ):
                logger.debug("DEBUG: Loading existing identicon for address")
                self.load_selected_Image(text)
            else:
                logger.debug("DEBUG: Generating new identicon for address")
                self.set_identicon(text)
                self.root.ids.content_drawer.ids.reset_image.opacity = 0
                self.root.ids.content_drawer.ids.reset_image.disabled = True
            
            address_label = self.format_address_and_label(text)
            self.root_window.children[1].ids.toolbar.title = address_label
            self.kivy_state_obj.selected_address = text
            logger.debug("DEBUG: Set selected address to: %s", text)
            
            AddressChangingLoader().open()
            for nav_obj in self.root.ids.content_drawer.children[
                    0].children[0].children[0].children:
                nav_obj.active = True if nav_obj.text == 'Inbox' else False
            
            self.fileManagerSetting()
            Clock.schedule_once(self.setCurrentAccountData, 0.5)

    def setCurrentAccountData(self, dt=0):
        """This method set the current accout data on all the screens"""
        logger.debug("DEBUG: Setting current account data on all screens")
        self.root.ids.id_inbox.ids.ml.clear_widgets()
        self.root.ids.id_inbox.loadMessagelist(self.kivy_state_obj.selected_address)

        self.root.ids.id_sent.ids.ml.clear_widgets()
        self.root.ids.id_sent.children[2].children[2].ids.search_field.text = ''
        self.root.ids.id_sent.loadSent(self.kivy_state_obj.selected_address)

    def fileManagerSetting(self):
        """This method is for file manager setting"""
        logger.debug("DEBUG: Setting up file manager")
        if not self.root.ids.content_drawer.ids.file_manager.opacity and \
                self.root.ids.content_drawer.ids.file_manager.disabled:
            self.root.ids.content_drawer.ids.file_manager.opacity = 1
            self.root.ids.content_drawer.ids.file_manager.disabled = False
            logger.debug("DEBUG: File manager enabled")

    def on_request_close(self, *args):  # pylint: disable=no-self-use
        """This method is for app closing request"""
        logger.debug("DEBUG: App close request received")
        AppClosingPopup().open()
        return True

    def clear_composer(self):
        """If slow down, the new composer edit screen"""
        logger.debug("DEBUG: Clearing composer")
        self.set_navbar_for_composer()
        composer_obj = self.root.ids.id_create.children[1].ids
        composer_obj.ti.text = ''
        composer_obj.composer_dropdown.text = 'Select'
        composer_obj.txt_input.text = ''
        composer_obj.subject.text = ''
        composer_obj.body.text = ''
        self.kivy_state_obj.in_composer = True
        self.kivy_state_obj = False

    def set_navbar_for_composer(self):
        """Clearing toolbar data when composer open"""
        logger.debug("DEBUG: Setting navbar for composer")
        self.root.ids.toolbar.left_action_items = [
            ['arrow-left', lambda x: self.back_press()]]
        self.root.ids.toolbar.right_action_items = [
            ['refresh',
             lambda x: self.root.ids.id_create.children[1].reset_composer()],
            ['send',
             lambda x: self.root.ids.id_create.children[1].send(self)]]

    def set_identicon(self, text):
        """Show identicon in address spinner"""
        logger.debug("DEBUG: Generating identicon for: %s", text)
        img = identiconGeneration.generate(text)
        self.root.ids.content_drawer.ids.top_box.children[0].texture = (img.texture)

    # pylint: disable=import-outside-toplevel
    def file_manager_open(self):
        """This method open the file manager of local system"""
        logger.debug("DEBUG: Opening file manager")
        if not self.kivy_state_obj.file_manager:
            self.file_manager = MDFileManager(
                exit_manager=self.exit_manager,
                select_path=self.select_path,
                ext=['.png', '.jpg']
            )
        self.file_manager.previous = False
        self.file_manager.current_path = '/'
        if platform == 'android':
            # pylint: disable=import-error
            from android.permissions import request_permissions, Permission, check_permission
            if check_permission(Permission.WRITE_EXTERNAL_STORAGE) and \
                    check_permission(Permission.READ_EXTERNAL_STORAGE):
                logger.debug("DEBUG: Android permissions granted, showing file manager")
                self.file_manager.show(os.getenv('EXTERNAL_STORAGE'))
                self.kivy_state_obj.manager_open = True
            else:
                logger.debug("DEBUG: Requesting Android permissions")
                request_permissions([Permission.WRITE_EXTERNAL_STORAGE, Permission.READ_EXTERNAL_STORAGE])
        else:
            logger.debug("DEBUG: Showing file manager for non-Android platform")
            self.file_manager.show(os.environ["HOME"])
            self.kivy_state_obj.manager_open = True

    def select_path(self, path):
        """This method is used to set the select image"""
        logger.debug("DEBUG: Selected image path: %s", path)
        try:
            newImg = PilImage.open(path).resize((300, 300))
            if platform == 'android':
                android_path = os.path.join(
                    os.path.join(os.environ['ANDROID_PRIVATE'], 'app', 'images', 'kivy')
                )
                if not os.path.exists(os.path.join(android_path, 'default_identicon')):
                    os.makedirs(os.path.join(android_path, 'default_identicon'))
                save_path = os.path.join(android_path, 'default_identicon', '{}.png'.format(
                    self.kivy_state_obj.selected_address))
                newImg.save(save_path)
                logger.debug("DEBUG: Saved image to Android path: %s", save_path)
            else:
                if not os.path.exists(os.path.join(self.image_dir, 'default_identicon')):
                    os.makedirs(os.path.join(self.image_dir, 'default_identicon'))
                save_path = os.path.join(self.image_dir, 'default_identicon', '{0}.png'.format(
                    self.kivy_state_obj.selected_address))
                newImg.save(save_path)
                logger.debug("DEBUG: Saved image to local path: %s", save_path)
            
            self.load_selected_Image(self.kivy_state_obj.selected_address)
            toast('Image changed')
        except Exception as e:
            logger.error("DEBUG: Error processing selected image: %s", str(e))
            toast('Exit')
        self.exit_manager()

    def exit_manager(self, *args):
        """Called when the user reaches the root of the directory tree."""
        logger.debug("DEBUG: Closing file manager")
        self.kivy_state_obj.manager_open = False
        self.file_manager.close()

    def load_selected_Image(self, curerentAddr):
        """This method load the selected image on screen"""
        logger.debug("DEBUG: Loading selected image for address: %s", curerentAddr)
        top_box_obj = self.root.ids.content_drawer.ids.top_box.children[0]
        image_path = os.path.join(self.image_dir, 'default_identicon', '{0}.png'.format(curerentAddr))
        top_box_obj.source = image_path
        self.root.ids.content_drawer.ids.reset_image.opacity = 1
        self.root.ids.content_drawer.ids.reset_image.disabled = False
        top_box_obj.reload()
        logger.debug("DEBUG: Image loaded from: %s", image_path)

    def rest_default_avatar_img(self):
        """set default avatar generated image"""
        logger.debug("DEBUG: Resetting avatar to default")
        self.set_identicon(self.kivy_state_obj.selected_address)
        img_path = os.path.join(
            self.image_dir, 'default_identicon', '{}.png'.format(self.kivy_state_obj.selected_address)
        )
        if os.path.exists(img_path):
            os.remove(img_path)
            logger.debug("DEBUG: Removed custom avatar image: %s", img_path)
        self.root.ids.content_drawer.ids.reset_image.opacity = 0
        self.root.ids.content_drawer.ids.reset_image.disabled = True
        toast('Avatar reset')

    def get_default_logo(self, instance):
        """Getting default logo image"""
        logger.debug("DEBUG: Getting default logo")
        if self.identity_list:
            first_addr = self.identity_list[0]
            if config.getboolean(str(first_addr), 'enabled'):
                image_path = os.path.join(
                    self.image_dir, 'default_identicon', '{}.png'.format(first_addr)
                )
                if os.path.exists(image_path):
                    logger.debug("DEBUG: Using existing identicon: %s", image_path)
                    return image_path
                else:
                    logger.debug("DEBUG: Generating new identicon for first address")
                    img = identiconGeneration.generate(first_addr)
                    instance.texture = img.texture
                    return
        default_logo = os.path.join(self.image_dir, 'drawer_logo1.png')
        logger.debug("DEBUG: Using fallback logo: %s", default_logo)
        return default_logo

    @staticmethod
    def have_any_address():
        """Checking existance of any address"""
        has_address = bool(config.addresses())
        logger.debug("DEBUG: Checking address existence: %s", has_address)
        return has_address

    def reset_login_screen(self):
        """This method is used for clearing the widgets of random screen"""
        logger.debug("DEBUG: Resetting login screen widgets")
        if self.root.ids.id_newidentity.ids.add_random_bx.children:
            self.root.ids.id_newidentity.ids.add_random_bx.clear_widgets()

    def reset(self, *args):
        """Set transition direction"""
        logger.debug("DEBUG: Resetting transition direction")
        self.root.ids.scr_mngr.transition.direction = 'left'
        self.root.ids.scr_mngr.transition.unbind(on_complete=self.reset)

    def back_press(self):
        """Method for, reverting composer to previous page"""
        logger.debug("DEBUG: Handling back press")
        if self.root.ids.scr_mngr.current == 'showqrcode':
            logger.debug("DEBUG: Returning from QR code screen")
            self.set_common_header()
            self.root.ids.scr_mngr.current = 'myaddress'
        self.root.ids.scr_mngr.transition.bind(on_complete=self.reset)
        self.kivy_state.in_composer = False

    def set_toolbar_for_QrCode(self):
        """This method is use for setting Qr code toolbar."""
        logger.debug("DEBUG: Setting toolbar for QR code")
        self.root.ids.toolbar.left_action_items = [
            ['arrow-left', lambda x: self.back_press()]]
        self.root.ids.toolbar.right_action_items = []

    def set_common_header(self):
        """Common header for all the Screens"""
        logger.debug("DEBUG: Setting common header")
        self.root.ids.toolbar.right_action_items = [
            ['account-plus', lambda x: self.addingtoaddressbook()]]
        self.root.ids.toolbar.left_action_items = [
            ['menu', lambda x: self.root.ids.nav_drawer.set_state("toggle")]]
        return

    def open_payment_layout(self, sku):
        """It basically open up a payment layout for kivy UI"""
        logger.debug("DEBUG: Opening payment layout for SKU: %s", sku)
        pml = PaymentMethodLayout()
        self.product_id = sku
        self.custom_sheet = MDCustomBottomSheet(screen=pml)
        self.custom_sheet.open()

    def initiate_purchase(self, method_name):
        """initiate_purchase module"""
        logger.debug("DEBUG: Purchasing %s through %s", self.product_id, method_name)


class PaymentMethodLayout(BoxLayout):
    """PaymentMethodLayout class for kivy Ui"""


if __name__ == '__main__':
    logger.debug("DEBUG: Starting application")
    NavigateApp().run()
