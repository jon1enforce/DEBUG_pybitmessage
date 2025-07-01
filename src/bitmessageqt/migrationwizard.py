"""
Migration Wizard implementation for PyBitMessage configuration migration
"""

from qtpy import QtCore, QtWidgets

class MigrationWizardIntroPage(QtWidgets.QWizardPage):
    def __init__(self):
        print("DEBUG: [MigrationWizardIntroPage.__init__] Initializing intro page")
        super(QtWidgets.QWizardPage, self).__init__()
        
        try:
            self.setTitle("Migrating configuration")
            print("DEBUG: [MigrationWizardIntroPage.__init__] Set page title")

            label = QtWidgets.QLabel("This wizard will help you to migrate your configuration. "
                "You can still keep using PyBitMessage once you migrate, the changes are backwards compatible.")
            label.setWordWrap(True)
            print("DEBUG: [MigrationWizardIntroPage.__init__] Created intro label")

            layout = QtWidgets.QVBoxLayout()
            layout.addWidget(label)
            self.setLayout(layout)
            print("DEBUG: [MigrationWizardIntroPage.__init__] Layout configured")
            
        except Exception as e:
            print(f"DEBUG: [MigrationWizardIntroPage.__init__] Error initializing page: {e}")
            raise
        
    def nextId(self):
        next_id = 1
        print(f"DEBUG: [MigrationWizardIntroPage.nextId] Returning next page ID: {next_id}")
        return next_id
    

class MigrationWizardAddressesPage(QtWidgets.QWizardPage):
    def __init__(self, addresses):
        print("DEBUG: [MigrationWizardAddressesPage.__init__] Initializing addresses page")
        super(QtWidgets.QWizardPage, self).__init__()
        
        try:
            self.addresses = addresses
            self.setTitle("Addresses")
            print("DEBUG: [MigrationWizardAddressesPage.__init__] Set page title")
            print(f"DEBUG: [MigrationWizardAddressesPage.__init__] Received {len(addresses)} addresses")

            label = QtWidgets.QLabel("Please select addresses that you are already using with mailchuck. ")
            label.setWordWrap(True)
            print("DEBUG: [MigrationWizardAddressesPage.__init__] Created addresses label")

            # Create checkboxes for each address
            self.checkboxes = []
            scroll = QtWidgets.QScrollArea()
            scroll.setWidgetResizable(True)
            container = QtWidgets.QWidget()
            scroll_layout = QtWidgets.QVBoxLayout(container)
            
            for addr in addresses:
                cb = QtWidgets.QCheckBox(addr)
                self.checkboxes.append(cb)
                scroll_layout.addWidget(cb)
                print(f"DEBUG: [MigrationWizardAddressesPage.__init__] Added checkbox for address: {addr}")
            
            scroll.setWidget(container)
            
            layout = QtWidgets.QVBoxLayout()
            layout.addWidget(label)
            layout.addWidget(scroll)
            self.setLayout(layout)
            print("DEBUG: [MigrationWizardAddressesPage.__init__] Layout configured with scroll area")
            
        except Exception as e:
            print(f"DEBUG: [MigrationWizardAddressesPage.__init__] Error initializing page: {e}")
            raise
        
    def nextId(self):
        next_id = 10
        print(f"DEBUG: [MigrationWizardAddressesPage.nextId] Returning next page ID: {next_id}")
        return next_id
    

class MigrationWizardGPUPage(QtWidgets.QWizardPage):
    def __init__(self):
        print("DEBUG: [MigrationWizardGPUPage.__init__] Initializing GPU page")
        super(QtWidgets.QWizardPage, self).__init__()
        
        try:
            self.setTitle("GPU")
            print("DEBUG: [MigrationWizardGPUPage.__init__] Set page title")

            label = QtWidgets.QLabel("Are you using a GPU? ")
            label.setWordWrap(True)
            print("DEBUG: [MigrationWizardGPUPage.__init__] Created GPU label")

            # Add radio buttons for GPU selection
            self.gpu_yes = QtWidgets.QRadioButton("Yes")
            self.gpu_no = QtWidgets.QRadioButton("No")
            self.gpu_no.setChecked(True)
            
            button_group = QtWidgets.QButtonGroup(self)
            button_group.addButton(self.gpu_yes)
            button_group.addButton(self.gpu_no)
            
            layout = QtWidgets.QVBoxLayout()
            layout.addWidget(label)
            layout.addWidget(self.gpu_yes)
            layout.addWidget(self.gpu_no)
            self.setLayout(layout)
            print("DEBUG: [MigrationWizardGPUPage.__init__] Layout configured with radio buttons")
            
        except Exception as e:
            print(f"DEBUG: [MigrationWizardGPUPage.__init__] Error initializing page: {e}")
            raise
        
    def nextId(self):
        next_id = 10
        print(f"DEBUG: [MigrationWizardGPUPage.nextId] Returning next page ID: {next_id}")
        return next_id
    

class MigrationWizardConclusionPage(QtWidgets.QWizardPage):
    def __init__(self):
        print("DEBUG: [MigrationWizardConclusionPage.__init__] Initializing conclusion page")
        super(QtWidgets.QWizardPage, self).__init__()
        
        try:
            self.setTitle("All done!")
            print("DEBUG: [MigrationWizardConclusionPage.__init__] Set page title")

            label = QtWidgets.QLabel("You successfully migrated.")
            label.setWordWrap(True)
            print("DEBUG: [MigrationWizardConclusionPage.__init__] Created conclusion label")

            layout = QtWidgets.QVBoxLayout()
            layout.addWidget(label)
            self.setLayout(layout)
            print("DEBUG: [MigrationWizardConclusionPage.__init__] Layout configured")
            
        except Exception as e:
            print(f"DEBUG: [MigrationWizardConclusionPage.__init__] Error initializing page: {e}")
            raise


class Ui_MigrationWizard(QtWidgets.QWizard):
    def __init__(self, addresses):
        print("DEBUG: [Ui_MigrationWizard.__init__] Initializing migration wizard")
        super(QtWidgets.QWizard, self).__init__()
        
        try:
            self.pages = {}
            print(f"DEBUG: [Ui_MigrationWizard.__init__] Received {len(addresses)} addresses")
            
            # Create and register pages
            print("DEBUG: [Ui_MigrationWizard.__init__] Creating intro page")
            page = MigrationWizardIntroPage()
            self.setPage(0, page)
            self.setStartId(0)
            
            print("DEBUG: [Ui_MigrationWizard.__init__] Creating addresses page")
            page = MigrationWizardAddressesPage(addresses)
            self.setPage(1, page)
            
            print("DEBUG: [Ui_MigrationWizard.__init__] Creating GPU page")
            page = MigrationWizardGPUPage()
            self.setPage(2, page)
            
            print("DEBUG: [Ui_MigrationWizard.__init__] Creating conclusion page")
            page = MigrationWizardConclusionPage()
            self.setPage(10, page)

            self.setWindowTitle("Migration from PyBitMessage wizard")
            self.adjustSize()
            print("DEBUG: [Ui_MigrationWizard.__init__] Wizard initialized successfully")
            
            # Connect signals
            self.currentIdChanged.connect(self._on_page_changed)
            print("DEBUG: [Ui_MigrationWizard.__init__] Connected page change signal")
            
            self.show()
            print("DEBUG: [Ui_MigrationWizard.__init__] Wizard displayed")
            
        except Exception as e:
            print(f"DEBUG: [Ui_MigrationWizard.__init__] Error initializing wizard: {e}")
            raise
    
    def _on_page_changed(self, page_id):
        print(f"DEBUG: [Ui_MigrationWizard._on_page_changed] Page changed to ID: {page_id}")
        if page_id == 10:  # Conclusion page
            selected_addresses = []
            addresses_page = self.page(1)
            for cb in addresses_page.checkboxes:
                if cb.isChecked():
                    selected_addresses.append(cb.text())
            print(f"DEBUG: [Ui_MigrationWizard._on_page_changed] Selected addresses: {selected_addresses}")
            
            gpu_page = self.page(2)
            using_gpu = gpu_page.gpu_yes.isChecked()
            print(f"DEBUG: [Ui_MigrationWizard._on_page_changed] Using GPU: {using_gpu}")
            
            # Here you would typically process the migration with these settings
            print("DEBUG: [Ui_MigrationWizard._on_page_changed] Ready to process migration")
