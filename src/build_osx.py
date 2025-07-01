"""Building osx."""
import os
import sys
from glob import glob
from PyQt4 import QtCore
from setuptools import setup

print("DEBUG: Starting OSX build process")

name = "Bitmessage"
version = os.getenv("PYBITMESSAGEVERSION", "custom")
print(f"DEBUG: Building {name} version {version}")

mainscript = ["bitmessagemain.py"]
print(f"DEBUG: Main script: {mainscript[0]}")

# Log environment variables for debugging
print("DEBUG: Environment variables:")
for key, value in os.environ.items():
    if key.startswith("PYBIT") or key.startswith("QT"):
        print(f"DEBUG:   {key}={value}")

print("DEBUG: Gathering data files...")
DATA_FILES = [
    ('', ['sslkeys', 'images', 'default.ini']),
    ('sql', glob('sql/*.sql')),
    ('bitmsghash', ['bitmsghash/bitmsghash.cl', 'bitmsghash/bitmsghash.so']),
    ('translations', glob('translations/*.qm')),
    ('ui', glob('bitmessageqt/*.ui')),
]

# Add Qt translations if available
try:
    qt_translations_path = str(QtCore.QLibraryInfo.location(
        QtCore.QLibraryInfo.TranslationsPath))
    print(f"DEBUG: Qt translations path: {qt_translations_path}")
    
    qt_translations = glob(os.path.join(qt_translations_path, 'qt_??.qm'))
    print(f"DEBUG: Found {len(qt_translations)} Qt language files")
    DATA_FILES.append(('translations', qt_translations))
    
    qt_country_translations = glob(os.path.join(
        qt_translations_path, 'qt_??_??.qm'))
    print(f"DEBUG: Found {len(qt_country_translations)} Qt country-specific language files")
    DATA_FILES.append(('translations', qt_country_translations))
except Exception as e:
    print(f"DEBUG: Error while gathering Qt translations: {str(e)}")

# Debug output for collected files
print("DEBUG: Data files to include:")
for dest, files in DATA_FILES:
    print(f"DEBUG:   {dest}:")
    for f in files:
        print(f"DEBUG:     - {f}")

print("DEBUG: Configuring py2app options...")
py2app_options = dict(
    includes=['sip', 'PyQt4._qt'],
    iconfile="images/bitmessage.icns"
)

print("DEBUG: py2app options:")
for key, value in py2app_options.items():
    print(f"DEBUG:   {key}: {value}")

print("DEBUG: Starting setup...")
setup(
    name=name,
    version=version,
    app=mainscript,
    data_files=DATA_FILES,
    setup_requires=["py2app"],
    options=dict(
        py2app=py2app_options
    )
)
print("DEBUG: Setup completed successfully")
