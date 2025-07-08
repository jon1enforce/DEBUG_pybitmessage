#!/usr/bin/env python3

import os
import platform
import shutil
import sys
import six
import logging
from importlib import import_module
from setuptools import setup, Extension
from setuptools.command.install import install

# Setup extensive logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Try to import version with debug info
try:
    logger.debug("Attempting to import softwareVersion from src.version")
    from src.version import softwareVersion
    logger.debug(f"Imported softwareVersion: {softwareVersion}, type: {type(softwareVersion)}")
except ImportError as e:
    logger.error(f"Failed to import softwareVersion: {e}")
    softwareVersion = "0.6.3.2"  # Fallback version
    logger.warning(f"Using fallback version: {softwareVersion}")
except Exception as e:
    logger.error(f"Unexpected error importing version: {e}")
    raise

# Debug version info
logger.debug(f"Final version to be used: {softwareVersion}, type: {type(softwareVersion)}")

EXTRAS_REQUIRE = {
    'docs': ['sphinx'],
    'gir': ['pygobject'],
    'json': ['jsonrpclib'],
    'notify2': ['notify2'],
    'opencl': ['pyopencl', 'numpy'],
    'prctl': ['python_prctl'],  # Named threads
    'qrcode': ['qrcode'],
    'sound;platform_system=="Windows"': ['winsound'],
    'tor': ['stem'],
    'xdg': ['pyxdg'],
    'xml': ['defusedxml']
}

class InstallCmd(install):
    """Custom setuptools install command preparing icons"""
    
    def run(self):
        logger.debug("Running custom install command")
        # prepare icons directories
        try:
            os.makedirs('desktop/icons/scalable')
            logger.debug("Created scalable icons directory")
        except os.error as e:
            logger.debug(f"Directory exists or couldn't be created: {e}")

        try:
            shutil.copyfile(
                'desktop/can-icon.svg', 'desktop/icons/scalable/pybitmessage.svg')
            logger.debug("Copied scalable icon")
        except Exception as e:
            logger.error(f"Failed to copy scalable icon: {e}")

        try:
            os.makedirs('desktop/icons/24x24')
            logger.debug("Created 24x24 icons directory")
        except os.error as e:
            logger.debug(f"Directory exists or couldn't be created: {e}")

        try:
            shutil.copyfile(
                'desktop/icon24.png', 'desktop/icons/24x24/pybitmessage.png')
            logger.debug("Copied 24x24 icon")
        except Exception as e:
            logger.error(f"Failed to copy 24x24 icon: {e}")

        logger.debug("Proceeding with standard install")
        return install.run(self)

if __name__ == "__main__":
    logger.debug("Starting setup.py execution")
    
    try:
        here = os.path.abspath(os.path.dirname(__file__))
        logger.debug(f"Base directory: {here}")

        # Read README
        try:
            with open(os.path.join(here, 'README.md')) as f:
                README = f.read()
            logger.debug("Successfully read README.md")
        except Exception as e:
            logger.error(f"Failed to read README.md: {e}")
            README = ""

        # Read requirements
        try:
            with open(os.path.join(here, 'requirements.txt'), 'r') as f:
                requirements = list(f.readlines())
            logger.debug("Successfully read requirements.txt")
        except Exception as e:
            logger.error(f"Failed to read requirements.txt: {e}")
            requirements = []

        # Extension setup
        bitmsghash = Extension(
            'pybitmessage.bitmsghash.bitmsghash',
            sources=['src/bitmsghash/bitmsghash.cpp'],
            libraries=['pthread', 'crypto'],
        )
        logger.debug("Configured bitmsghash extension")

        installRequires = ['six']
        packages = [
            'pybitmessage',
            'pybitmessage.bitmessageqt',
            'pybitmessage.bitmessagecurses',
            'pybitmessage.fallback',
            'pybitmessage.messagetypes',
            'pybitmessage.network',
            'pybitmessage.plugins',
            'pybitmessage.pyelliptic',
            'pybitmessage.storage'
        ]
        logger.debug(f"Base packages: {packages}")

        package_data = {'': [
            'bitmessageqt/*.ui', 'bitmsghash/*.cl', 'sslkeys/*.pem',
            'translations/*.ts', 'translations/*.qm', 'default.ini', 'sql/*.sql',
            'images/*.png', 'images/*.ico', 'images/*.icns',
            'bitmessagekivy/main.kv', 'bitmessagekivy/screens_data.json',
            'bitmessagekivy/kv/*.kv', 'images/kivy/payment/*.png', 'images/kivy/*.gif',
            'images/kivy/text_images*.png'
        ]}
        logger.debug("Configured package_data")

        if six.PY3:
            packages.extend([
                'pybitmessage.bitmessagekivy',
                'pybitmessage.bitmessagekivy.baseclass'
            ])
            logger.debug(f"Added PY3 specific packages: {packages[-2:]}")

        if os.environ.get('INSTALL_TESTS', False):
            packages.extend(['pybitmessage.mockbm', 'pybitmessage.backend', 'pybitmessage.bitmessagekivy.tests'])
            package_data[''].extend(['bitmessagekivy/tests/sampleData/*.dat'])
            logger.debug("Added test packages and data")

        # Handle msgpack dependencies
        try:
            import msgpack
            installRequires.append(
                "msgpack-python" if msgpack.version[:2] < (0, 6) else "msgpack")
            logger.debug(f"Added msgpack dependency: {installRequires[-1]}")
        except ImportError:
            try:
                import_module('umsgpack')
                installRequires.append("umsgpack")
                logger.debug("Added umsgpack dependency")
            except ImportError:
                packages += ['pybitmessage.fallback.umsgpack']
                logger.debug("Added fallback umsgpack package")

        data_files = [
            ('share/applications/',
                ['desktop/pybitmessage.desktop']),
            ('share/icons/hicolor/scalable/apps/',
                ['desktop/icons/scalable/pybitmessage.svg']),
            ('share/icons/hicolor/24x24/apps/',
                ['desktop/icons/24x24/pybitmessage.png'])
        ]
        logger.debug("Configured data_files")

        try:
            if hasattr(platform, 'dist'):
                dist_info = platform.dist()
                if dist_info[0] in ('Debian', 'Ubuntu'):
                    data_files += [
                        ("etc/apparmor.d/",
                            ['packages/apparmor/pybitmessage'])
                    ]
                    logger.debug("Added Debian/Ubuntu specific data_files")
        except Exception as e:
            logger.debug(f"Couldn't check platform dist: {e}")

        logger.debug("Starting setup() configuration")
        dist = setup(
            name='pybitmessage',
            version=softwareVersion,
            description="Reference client for Bitmessage: "
            "a P2P communications protocol",
            long_description=README,
            license='MIT',
            url='https://bitmessage.org',
            install_requires=installRequires,
            tests_require=requirements,
            test_suite='tests.unittest_discover',
            extras_require=EXTRAS_REQUIRE,
            classifiers=[
                "License :: OSI Approved :: MIT License",
                "Operating System :: OS Independent",
                "Programming Language :: Python :: 3",
                "Topic :: Internet",
                "Topic :: Security :: Cryptography",
                "Topic :: Software Development :: Libraries :: Python Modules",
            ],
            package_dir={'pybitmessage': 'src'},
            packages=packages,
            package_data=package_data,
            data_files=data_files,
            ext_modules=[bitmsghash],
            zip_safe=False,
            entry_points={
                'bitmessage.gui.menu': [
                    'address.qrcode = pybitmessage.plugins.menu_qrcode [qrcode]'
                ],
                'bitmessage.notification.message': [
                    'notify2 = pybitmessage.plugins.notification_notify2'
                    '[gir, notify2]'
                ],
                'bitmessage.notification.sound': [
                    'theme.canberra = pybitmessage.plugins.sound_canberra',
                    'file.gstreamer = pypybitmessage.plugins.sound_gstreamer'
                    '[gir]',
                    'file.fallback = pybitmessage.plugins.sound_playfile'
                    '[sound]'
                ],
                'bitmessage.indicator': [
                    'libmessaging ='
                    'pybitmessage.plugins.indicator_libmessaging [gir]'
                ],
                'bitmessage.desktop': [
                    'freedesktop = pybitmessage.plugins.desktop_xdg [xdg]'
                ],
                'bitmessage.proxyconfig': [
                    'stem = pybitmessage.plugins.proxyconfig_stem [tor]'
                ],
                'console_scripts': [
                    'pybitmessage = pybitmessage.bitmessagemain:main'
                ] if sys.platform[:3] == 'win' else []
            },
            scripts=['src/pybitmessage'],
            cmdclass={'install': InstallCmd},
            command_options={
                'build_sphinx': {
                    'source_dir': ('setup.py', 'docs')}
            }
        )
        logger.debug("Setup completed successfully")

    except Exception as e:
        logger.error(f"Fatal error in setup: {e}", exc_info=True)
        raise
