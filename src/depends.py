"""
Utility functions to check the availability of dependencies
and suggest how it may be installed
"""

import os
import re
import sys
import six

# Debug setup
DEBUG = True

def debug_print(message):
    if DEBUG:
        print(f"DEBUG: {message}")

debug_print("Starting dependency checks...")

# Only really old versions of Python don't have sys.hexversion. We don't
# support them. The logging module was introduced in Python 2.3
if not hasattr(sys, 'hexversion') or sys.hexversion < 0x20300F0:
    debug_print(f"Unsupported Python version detected: {sys.version}")
    sys.exit(
        'Python version: %s\n'
        'PyBitmessage requires Python 2.7.4 or greater (but not Python 3)'
        % sys.version
    )

import logging  # noqa:E402
from distutils import version
import subprocess  # nosec B404

from importlib import import_module
from helper_sql import safe_decode

debug_print("Basic imports completed successfully")

# We can now use logging so set up a simple configuration
formatter = logging.Formatter('%(levelname)s: %(message)s')
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(formatter)
logger = logging.getLogger('both')
logger.addHandler(handler)
logger.setLevel(logging.ERROR)

debug_print("Logger configuration completed")

OS_RELEASE = {
    "Debian GNU/Linux".lower(): "Debian",
    "fedora": "Fedora",
    "opensuse": "openSUSE",
    "ubuntu": "Ubuntu",
    "gentoo": "Gentoo",
    "calculate": "Gentoo"
}

PACKAGE_MANAGER = {
    "OpenBSD": "pkg_add",
    "FreeBSD": "pkg install",
    "Debian": "apt-get install",
    "Ubuntu": "apt-get install",
    "Ubuntu 12": "apt-get install",
    "Ubuntu 20": "apt-get install",
    "openSUSE": "zypper install",
    "Fedora": "dnf install",
    "Guix": "guix package -i",
    "Gentoo": "emerge"
}

PACKAGES = {
    "qtpy": {
        "OpenBSD": "py-qtpy",
        "FreeBSD": "py27-QtPy",
        "Debian": "python-qtpy",
        "Ubuntu": "python-qtpy",
        "Ubuntu 12": "python-qtpy",
        "Ubuntu 20": "python-qtpy",
        "openSUSE": "python-QtPy",
        "Fedora": "python2-QtPy",
        "Guix": "",
        "Gentoo": "dev-python/QtPy",
        "optional": True,
        "description":
        "You only need qtpy if you want to use the GUI."
        " When only running as a daemon, this can be skipped.\n"
        "Also maybe you need to install PyQt5 or PyQt4"
        " if your package manager not installs it as qtpy dependency"
    },
    "msgpack": {
        "OpenBSD": "py-msgpack",
        "FreeBSD": "py27-msgpack-python",
        "Debian": "python-msgpack",
        "Ubuntu": "python-msgpack",
        "Ubuntu 12": "msgpack-python",
        "Ubuntu 20": "",
        "openSUSE": "python-msgpack-python",
        "Fedora": "python2-msgpack",
        "Guix": "python2-msgpack",
        "Gentoo": "dev-python/msgpack",
        "optional": True,
        "description":
        "python-msgpack is recommended for improved performance of"
        " message encoding/decoding"
    },
    "pyopencl": {
        "FreeBSD": "py27-pyopencl",
        "Debian": "python-pyopencl",
        "Ubuntu": "python-pyopencl",
        "Ubuntu 12": "python-pyopencl",
        "Ubuntu 20": "",
        "Fedora": "python2-pyopencl",
        "openSUSE": "",
        "OpenBSD": "",
        "Guix": "",
        "Gentoo": "dev-python/pyopencl",
        "optional": True,
        "description":
        "If you install pyopencl, you will be able to use"
        " GPU acceleration for proof of work.\n"
        "You also need a compatible GPU and drivers."
    },
    "setuptools": {
        "OpenBSD": "py-setuptools",
        "FreeBSD": "py27-setuptools",
        "Debian": "python-setuptools",
        "Ubuntu": "python-setuptools",
        "Ubuntu 12": "python-setuptools",
        "Ubuntu 20": "python-setuptools",
        "Fedora": "python2-setuptools",
        "openSUSE": "python-setuptools",
        "Guix": "python2-setuptools",
        "Gentoo": "dev-python/setuptools",
        "optional": False,
    },
    "six": {
        "OpenBSD": "py-six",
        "FreeBSD": "py27-six",
        "Debian": "python-six",
        "Ubuntu": "python-six",
        "Ubuntu 12": "python-six",
        "Ubuntu 20": "python-six",
        "Fedora": "python-six",
        "openSUSE": "python-six",
        "Guix": "python-six",
        "Gentoo": "dev-python/six",
        "optional": False,
    }
}

debug_print("Configuration dictionaries initialized")

def detectOS():
    """Finding out what Operating System is running"""
    debug_print("Starting OS detection")
    if detectOS.result is not None:
        debug_print(f"Using cached OS detection result: {detectOS.result}")
        return detectOS.result
    if sys.platform.startswith('openbsd'):
        detectOS.result = "OpenBSD"
    elif sys.platform.startswith('freebsd'):
        detectOS.result = "FreeBSD"
    elif sys.platform.startswith('win'):
        detectOS.result = "Windows"
    elif os.path.isfile("/etc/os-release"):
        detectOSRelease()
    elif os.path.isfile("/etc/config.scm"):
        detectOS.result = "Guix"
    debug_print(f"OS detection complete: {detectOS.result}")
    return detectOS.result

detectOS.result = None

def detectOSRelease():
    """Detecting the release of OS"""
    debug_print("Starting OS release detection from /etc/os-release")
    with open("/etc/os-release", 'r') as osRelease:
        ver = None
        for line in osRelease:
            if line.startswith("NAME="):
                detectOS.result = OS_RELEASE.get(
                    line.replace('"', '').split("=")[-1].strip().lower())
                debug_print(f"Found OS name: {detectOS.result}")
            elif line.startswith("VERSION_ID="):
                try:
                    ver = float(line.split("=")[1].replace("\"", ""))
                    debug_print(f"Found OS version: {ver}")
                except ValueError:
                    debug_print("Could not parse VERSION_ID")
                    pass
        if detectOS.result == "Ubuntu" and ver is not None:
            if ver < 14:
                detectOS.result = "Ubuntu 12"
                debug_print("Ubuntu version < 14 detected, setting to Ubuntu 12")
            elif ver >= 20:
                detectOS.result = "Ubuntu 20"
                debug_print("Ubuntu version >= 20 detected, setting to Ubuntu 20")

def try_import(module, log_extra=False):
    """Try to import the non imported packages"""
    debug_print(f"Attempting to import module: {module}")
    try:
        imported = import_module(module)
        debug_print(f"Successfully imported module: {module}")
        return imported
    except ImportError:
        module = module.split('.')[0]
        debug_print(f"Failed to import module: {module}")
        logger.error('The %s module is not available.', module)
        if log_extra:
            logger.error(log_extra)
            dist = detectOS()
            logger.error(
                'On %s, try running "%s %s" as root.',
                dist, PACKAGE_MANAGER[dist], PACKAGES[module][dist])
        return False

def check_ripemd160():
    """Check availability of the RIPEMD160 hash function"""
    debug_print("Checking RIPEMD160 availability")
    try:
        from fallback import RIPEMD160Hash
        debug_print("RIPEMD160Hash imported successfully")
        return RIPEMD160Hash is not None
    except ImportError:
        debug_print("Failed to import RIPEMD160Hash")
        return False

def check_sqlite():
    """Do sqlite check.

    Simply check sqlite3 module if exist or not with hexversion
    support in python version for specifieed platform.
    """
    debug_print("Starting SQLite check")
    if sys.hexversion < 0x020500F0:
        debug_print("Python version too old for built-in sqlite3")
        logger.error(
            'The sqlite3 module is not included in this version of Python.')
        if sys.platform.startswith('freebsd'):
            logger.error(
                'On FreeBSD, try running "pkg install py27-sqlite3" as root.')
        return False

    sqlite3 = try_import('sqlite3')
    if not sqlite3:
        debug_print("SQLite import failed")
        return False

    debug_print("SQLite module imported successfully")
    logger.info('sqlite3 Module Version: %s', sqlite3.version)
    logger.info('SQLite Library Version: %s', sqlite3.sqlite_version)
    # sqlite_version_number formula: https://sqlite.org/c3ref/c_source_id.html
    sqlite_version_number = (
        sqlite3.sqlite_version_info[0] * 1000000
        + sqlite3.sqlite_version_info[1] * 1000
        + sqlite3.sqlite_version_info[2]
    )
    debug_print(f"SQLite version number calculated: {sqlite_version_number}")

    conn = None
    try:
        try:
            conn = sqlite3.connect(':memory:')
            debug_print("Connected to in-memory SQLite database")
            if sqlite_version_number >= 3006018:
                sqlite_source_id = conn.execute(
                    'SELECT sqlite_source_id();'
                ).fetchone()[0]
                logger.info('SQLite Library Source ID: %s', sqlite_source_id)
                debug_print(f"SQLite source ID: {sqlite_source_id}")
            if sqlite_version_number >= 3006023:
                compile_options = ', '.join(
                    [row[0] for row in conn.execute('PRAGMA compile_options;')])
                logger.info(
                    'SQLite Library Compile Options: %s', compile_options)
                debug_print(f"SQLite compile options: {compile_options}")
            # There is no specific version requirement as yet, so we just
            # use the first version that was included with Python.
            if sqlite_version_number < 3000008:
                logger.error(
                    'This version of SQLite is too old.'
                    ' PyBitmessage requires SQLite 3.0.8 or later')
                debug_print("SQLite version too old")
                return False
            return True
        except sqlite3.Error:
            logger.exception('An exception occured while checking sqlite.')
            debug_print("Exception occurred during SQLite check")
            return False
    finally:
        if conn:
            conn.close()
            debug_print("Closed SQLite connection")

def check_openssl():
    """Do openssl dependency check.

    Here we are checking for openssl with its all dependent libraries
    and version checking.
    """
    debug_print("Starting OpenSSL check")
    # pylint: disable=too-many-branches, too-many-return-statements
    # pylint: disable=protected-access, redefined-outer-name
    ctypes = try_import('ctypes')
    if not ctypes:
        logger.error('Unable to check OpenSSL.')
        debug_print("ctypes import failed, cannot check OpenSSL")
        return False

    # We need to emulate the way PyElliptic searches for OpenSSL.
    if sys.platform == 'win32':
        paths = ['libeay32.dll']
        if getattr(sys, 'frozen', False):
            paths.insert(0, os.path.join(sys._MEIPASS, 'libeay32.dll'))
    else:
        paths = ['libcrypto.so', 'libcrypto.so.1.0.0']
    if sys.platform == 'darwin':
        paths.extend([
            'libcrypto.dylib',
            '/usr/local/opt/openssl/lib/libcrypto.dylib',
            './../Frameworks/libcrypto.dylib'
        ])

    debug_print(f"OpenSSL search paths: {paths}")

    if re.match(r'linux|darwin|freebsd', sys.platform):
        try:
            import ctypes.util
            path = ctypes.util.find_library('ssl')
            if path not in paths:
                paths.append(path)
                debug_print(f"Added SSL library path: {path}")
        except:  # nosec B110 # pylint:disable=bare-except
            debug_print("Failed to find SSL library path")
            pass

    openssl_version = None
    openssl_hexversion = None
    openssl_cflags = None

    cflags_regex = re.compile(r'(?:OPENSSL_NO_)(AES|EC|ECDH|ECDSA)(?!\w)')

    import pyelliptic.openssl

    for path in paths:
        if not path:
            continue
        logger.info('Checking OpenSSL at %s', path)
        debug_print(f"Attempting to load OpenSSL from: {path}")
        try:
            library = ctypes.CDLL(path)
            debug_print(f"Successfully loaded OpenSSL from: {path}")
        except OSError as e:
            debug_print(f"Failed to load OpenSSL from {path}: {str(e)}")
            continue
        logger.info('OpenSSL Name: %s', library._name)
        try:
            openssl_version, openssl_hexversion, openssl_cflags = \
                pyelliptic.openssl.get_version(library)
            debug_print(f"Got OpenSSL version: {openssl_version}")
        except AttributeError:  # sphinx chokes
            debug_print("AttributeError in pyelliptic.openssl.get_version")
            return True
        if not openssl_version:
            logger.error('Cannot determine version of this OpenSSL library.')
            debug_print("Could not determine OpenSSL version")
            return False
        logger.info('OpenSSL Version: %s', openssl_version)
        logger.info('OpenSSL Compile Options: %s', openssl_cflags)
        debug_print(f"OpenSSL compile options: {openssl_cflags}")
        # PyElliptic uses EVP_CIPHER_CTX_new and EVP_CIPHER_CTX_free which were
        # introduced in 0.9.8b.
        if openssl_hexversion < 0x90802F:
            logger.error(
                'This OpenSSL library is too old. PyBitmessage requires'
                ' OpenSSL 0.9.8b or later with AES, Elliptic Curves (EC),'
                ' ECDH, and ECDSA enabled.')
            debug_print("OpenSSL version too old")
            return False
        matches = cflags_regex.findall(safe_decode(openssl_cflags, "utf-8", "ignore"))
        if matches:
            logger.error(
                'This OpenSSL library is missing the following required'
                ' features: %s. PyBitmessage requires OpenSSL 0.9.8b'
                ' or later with AES, Elliptic Curves (EC), ECDH,'
                ' and ECDSA enabled.', ', '.join(matches))
            debug_print(f"Missing OpenSSL features: {matches}")
            return False
        return True
    debug_print("No valid OpenSSL library found in any path")
    return False

def check_curses():
    """Do curses dependency check.

    Here we are checking for curses if available or not with check as interface
    requires the `pythondialog <https://pypi.org/project/pythondialog>`_ package
    and the dialog utility.
    """
    debug_print("Starting curses check")
    if sys.hexversion < 0x20600F0:
        logger.error(
            'The curses interface requires the pythondialog package and'
            ' the dialog utility.')
        debug_print("Python version too old for curses interface")
        return False
    curses = try_import('curses')
    if not curses:
        logger.error('The curses interface can not be used.')
        debug_print("curses module import failed")
        return False

    debug_print("curses module imported successfully")
    logger.info('curses Module Version: %s', curses.version)

    dialog = try_import('dialog')
    if not dialog:
        logger.error('The curses interface can not be used.')
        debug_print("dialog module import failed")
        return False

    try:
        subprocess.check_call(['which', 'dialog'])  # nosec B603, B607
        debug_print("dialog utility found in PATH")
    except subprocess.CalledProcessError:
        logger.error(
            'Curses requires the `dialog` command to be installed as well as'
            ' the python library.')
        debug_print("dialog utility not found in PATH")
        return False

    logger.info('pythondialog Package Version: %s', dialog.__version__)
    dialog_util_version = dialog.Dialog().cached_backend_version
    # The pythondialog author does not like Python2 str, so we have to use
    # unicode for just the version otherwise we get the repr form which
    # includes the module and class names along with the actual version.
    logger.info('dialog Utility Version %s', safe_decode(dialog_util_version, "utf-8"))
    debug_print(f"dialog utility version: {safe_decode(dialog_util_version, "utf-8")}")
    return True

def check_pyqt():
    """Do pyqt dependency check.

    Here we are checking for qtpy with its version, as for it require
    qtpy.
    """
    debug_print("Starting PyQt check")
    # pylint: disable=no-member
    try:
        import qtpy
        debug_print("qtpy imported successfully")
    except ImportError:
        logger.error(
            'PyBitmessage requires qtpy, and PyQt5 or PyQt4, '
            ' PyQt 4.8 or later and Qt 4.7 or later.')
        debug_print("qtpy import failed")
        return False

    sip_found = False
    try:
        import sip
        sip.setapi("QString", 2)
        sip.setapi("QVariant", 2)
        sip_found = True
        debug_print("sip imported and configured successfully")
    except ImportError:
        debug_print("sip import failed")
        pass

    QtCore = try_import(
        'qtpy.QtCore', 'PyBitmessage requires qtpy and Qt 4.7 or later.')

    if not QtCore:
        debug_print("qtpy.QtCore import failed")
        return False

    try:
        logger.info('PyQt Version: %s', QtCore.PYQT_VERSION_STR)
        debug_print(f"PyQt version: {QtCore.PYQT_VERSION_STR}")
    except AttributeError:
        logger.info('Can be PySide..')
        debug_print("PyQt version not available, might be PySide")
    try:
        logger.info('Qt Version: %s', QtCore.__version__)
        debug_print(f"Qt version: {QtCore.__version__}")
    except AttributeError:
        # Can be PySide..
        debug_print("Qt version not available, might be PySide")
        pass
    passed = True

    try:
        if version.LooseVersion(QtCore.PYQT_VERSION_STR) < '4.8':
            logger.error(
                'This version of PyQt is too old. PyBitmessage requries'
                ' PyQt 4.8 or later.')
            debug_print("PyQt version too old")
            passed = False
    except AttributeError:
        # Can be PySide..
        debug_print("Could not check PyQt version, might be PySide")
        pass
    try:
        if version.LooseVersion(QtCore.__version__) < '4.7':
            logger.error(
                'This version of Qt is too old. PyBitmessage requries'
                ' Qt 4.7 or later.')
            debug_print("Qt version too old")
            passed = False
    except AttributeError:
        # Can be PySide..
        debug_print("Could not check Qt version, might be PySide")
        pass

    if passed and not sip_found:
        logger.info("sip is not found although PyQt is found")
        debug_print("sip not found but PyQt is present")
        return False

    return passed

def check_msgpack():
    """Do msgpack module check.

    simply checking if msgpack package with all its dependency
    is available or not as recommended for messages coding.
    """
    debug_print("Starting msgpack check")
    result = try_import(
        'msgpack', 'It is highly recommended for messages coding.') is not False
    debug_print(f"msgpack check result: {result}")
    return result

def check_dependencies(verbose=False, optional=False):
    """Do dependency check.

    It identifies project dependencies and checks if there are
    any known, publicly disclosed, vulnerabilities.basically
    scan applications (and their dependent libraries) so that
    easily identify any known vulnerable components.
    """
    debug_print(f"Starting dependency check (verbose={verbose}, optional={optional})")
    if verbose:
        logger.setLevel(logging.INFO)
        debug_print("Verbose mode enabled")

    has_all_dependencies = True

    # Python 2.7.4 is the required minimum.
    # (https://bitmessage.org/forum/index.php?topic=4081.0)
    # Python 3+ is not supported, but it is still useful to provide
    # information about our other requirements.
    logger.info('Python version: %s', sys.version)
    debug_print(f"Python version: {sys.version}")
    if sys.hexversion < 0x20704F0:
        logger.error(
            'PyBitmessage requires Python 2.7.4 or greater.'
            ' Python 2.7.18 is recommended.')
        debug_print("Python version too old")
        has_all_dependencies = False

    # FIXME: This needs to be uncommented when more of the code is python3 compatible
    # if sys.hexversion >= 0x3000000 and sys.hexversion < 0x3060000:
    #     print("PyBitmessage requires python >= 3.6 if using python 3")

    check_functions = [check_ripemd160, check_sqlite, check_openssl]
    if optional:
        check_functions.extend([check_msgpack, check_pyqt, check_curses])
    
    debug_print(f"Check functions to run: {[f.__name__ for f in check_functions]}")

    # Unexpected exceptions are handled here
    for check in check_functions:
        try:
            debug_print(f"Running check: {check.__name__}")
            result = check()
            debug_print(f"Check {check.__name__} returned: {result}")
            has_all_dependencies &= result
        except:  # noqa:E722
            logger.exception('%s failed unexpectedly.', check.__name__)
            debug_print(f"Exception in check {check.__name__}", exc_info=True)
            has_all_dependencies = False

    if not has_all_dependencies:
        debug_print("Dependency check failed")
        sys.exit(
            'PyBitmessage cannot start. One or more dependencies are'
            ' unavailable.'
        )
    debug_print("All dependency checks passed")

logger.setLevel(0)
debug_print("Module initialization complete")
