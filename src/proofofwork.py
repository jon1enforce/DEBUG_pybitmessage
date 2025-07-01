# pylint: disable=too-many-branches,too-many-statements,protected-access
"""
Proof of work calculation
"""

import ctypes
import os
import subprocess  # nosec B404
import sys
import tempfile
import time
from struct import pack, unpack

import highlevelcrypto
import openclpow
import paths
import queues
import state
import tr
from bmconfigparser import config
from debug import logger

bitmsglib = 'bitmsghash.so'
bmpow = None


class LogOutput(object):  # pylint: disable=too-few-public-methods
    """
    A context manager that block stdout for its scope
    and appends it's content to log before exit. Usage::

    with LogOutput():
        os.system('ls -l')

    https://stackoverflow.com/questions/5081657
    """

    def __init__(self, prefix='PoW'):
        logger.debug("DEBUG: LogOutput.__init__ called with prefix: %s", prefix)
        self.prefix = prefix
        try:
            sys.stdout.flush()
            self._stdout = sys.stdout
            self._stdout_fno = os.dup(sys.stdout.fileno())
        except AttributeError:
            logger.debug("DEBUG: LogOutput - NullWriter instance has no attribute 'fileno'")
            self._stdout = None
        else:
            self._dst, self._filepath = tempfile.mkstemp()
            logger.debug("DEBUG: LogOutput created temp file: %s", self._filepath)

    def __enter__(self):
        logger.debug("DEBUG: LogOutput.__enter__ called")
        if not self._stdout:
            return
        stdout = os.dup(1)
        os.dup2(self._dst, 1)
        os.close(self._dst)
        sys.stdout = os.fdopen(stdout, 'w')

    def __exit__(self, exc_type, exc_val, exc_tb):
        logger.debug("DEBUG: LogOutput.__exit__ called with exc_type: %s", exc_type)
        if not self._stdout:
            return
        sys.stdout.close()
        sys.stdout = self._stdout
        sys.stdout.flush()
        os.dup2(self._stdout_fno, 1)

        with open(self._filepath) as out:
            for line in out:
                logger.info('%s: %s', self.prefix, line)
        os.remove(self._filepath)
        logger.debug("DEBUG: LogOutput removed temp file: %s", self._filepath)


def _set_idle():
    logger.debug("DEBUG: _set_idle called")
    if 'linux' in sys.platform:
        logger.debug("DEBUG: _set_idle - setting nice to 20 (Linux)")
        os.nice(20)
    else:
        try:
            logger.debug("DEBUG: _set_idle - trying to set Windows idle priority")
            # pylint: disable=no-member,import-error
            sys.getwindowsversion()
            import win32api
            import win32process
            import win32con
            pid = win32api.GetCurrentProcessId()
            handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, pid)
            win32process.SetPriorityClass(handle, win32process.IDLE_PRIORITY_CLASS)
            logger.debug("DEBUG: _set_idle - Windows idle priority set successfully")
        except:  # nosec B110 # noqa:E722 # pylint:disable=bare-except
            logger.debug("DEBUG: _set_idle - failed to set Windows idle priority", exc_info=True)
            pass


def trial_value(nonce, initialHash):
    """Calculate PoW trial value"""
    logger.debug("DEBUG: trial_value called with nonce: %d, initialHash: %s", 
                nonce, hexlify(initialHash) if initialHash else "None")
    trialValue, = unpack(
        '>Q', highlevelcrypto.double_sha512(
            pack('>Q', nonce) + initialHash)[0:8])
    logger.debug("DEBUG: trial_value result: %d", trialValue)
    return trialValue


def _pool_worker(nonce, initialHash, target, pool_size):
    logger.debug("DEBUG: _pool_worker started with nonce: %d, target: %d, pool_size: %d", 
                nonce, target, pool_size)
    _set_idle()
    trialValue = float('inf')
    while trialValue > target:
        nonce += pool_size
        trialValue = trial_value(nonce, initialHash)
    logger.debug("DEBUG: _pool_worker found solution: nonce: %d, trialValue: %d", 
                nonce, trialValue)
    return [trialValue, nonce]


def _doSafePoW(target, initialHash):
    logger.debug("DEBUG: _doSafePoW started with target: %d, initialHash: %s", 
                target, hexlify(initialHash) if initialHash else "None")
    nonce = 0
    trialValue = float('inf')
    while trialValue > target and state.shutdown == 0:
        nonce += 1
        trialValue = trial_value(nonce, initialHash)
    if state.shutdown != 0:
        logger.debug("DEBUG: _doSafePoW interrupted by shutdown")
        raise StopIteration("Interrupted")
    logger.debug("DEBUG: _doSafePoW completed with nonce: %d, trialValue: %d", 
                nonce, trialValue)
    return [trialValue, nonce]


def _doFastPoW(target, initialHash):
    logger.debug("DEBUG: _doFastPoW started with target: %d, initialHash: %s", 
                target, hexlify(initialHash) if initialHash else "None")
    from multiprocessing import Pool, cpu_count
    try:
        pool_size = cpu_count()
        logger.debug("DEBUG: _doFastPoW detected %d CPU cores", pool_size)
    except:  # noqa:E722
        pool_size = 4
        logger.debug("DEBUG: _doFastPoW defaulting to 4 CPU cores")
    try:
        maxCores = config.getint('bitmessagesettings', 'maxcores')
        logger.debug("DEBUG: _doFastPoW maxcores setting: %d", maxCores)
    except:  # noqa:E722
        maxCores = 99999
        logger.debug("DEBUG: _doFastPoW using default maxcores: %d", maxCores)
    if pool_size > maxCores:
        pool_size = maxCores
        logger.debug("DEBUG: _doFastPoW adjusted pool_size to maxcores: %d", pool_size)

    pool = Pool(processes=pool_size)
    result = []
    for i in range(pool_size):
        result.append(pool.apply_async(_pool_worker, args=(i, initialHash, target, pool_size)))
        logger.debug("DEBUG: _doFastPoW started worker %d", i)

    while True:
        if state.shutdown > 0:
            logger.debug("DEBUG: _doFastPoW interrupted by shutdown")
            try:
                pool.terminate()
                pool.join()
            except:  # nosec B110 # noqa:E722 # pylint:disable=bare-except
                pass
            raise StopIteration("Interrupted")
        for i in range(pool_size):
            if result[i].ready():
                try:
                    result[i].successful()
                except AssertionError:
                    logger.debug("DEBUG: _doFastPoW worker failed", exc_info=True)
                    pool.terminate()
                    pool.join()
                    raise StopIteration("Interrupted")
                result = result[i].get()
                pool.terminate()
                pool.join()
                logger.debug("DEBUG: _doFastPoW completed with nonce: %d, trialValue: %d", 
                            result[1], result[0])
                return result[0], result[1]
        time.sleep(0.2)


def _doCPoW(target, initialHash):
    logger.debug("DEBUG: _doCPoW started with target: %d, initialHash: %s", 
                target, hexlify(initialHash) if initialHash else "None")
    with LogOutput():
        h = initialHash
        m = target
        out_h = ctypes.pointer(ctypes.create_string_buffer(h, 64))
        out_m = ctypes.c_ulonglong(m)
        logger.debug("DEBUG: _doCPoW calling C function")
        nonce = bmpow(out_h, out_m)

    trialValue = trial_value(nonce, initialHash)
    if state.shutdown != 0:
        logger.debug("DEBUG: _doCPoW interrupted by shutdown")
        raise StopIteration("Interrupted")
    logger.debug("DEBUG: _doCPoW completed with nonce: %d, trialValue: %d", 
                nonce, trialValue)
    return [trialValue, nonce]


def _doGPUPoW(target, initialHash):
    logger.debug("DEBUG: _doGPUPoW started with target: %d, initialHash: %s", 
                target, hexlify(initialHash) if initialHash else "None")
    logger.debug("DEBUG: _doGPUPoW calling OpenCL function")
    nonce = openclpow.do_opencl_pow(initialHash.encode("hex"), target)
    trialValue = trial_value(nonce, initialHash)
    if trialValue > target:
        deviceNames = ", ".join(gpu.name for gpu in openclpow.enabledGpus)
        logger.error("DEBUG: _doGPUPoW GPU calculation failed for devices: %s", deviceNames)
        queues.UISignalQueue.put((
            'updateStatusBar', (
                tr._translate(
                    "MainWindow",
                    'Your GPU(s) did not calculate correctly, disabling OpenCL. Please report to the developers.'
                ),
                1)))
        logger.error(
            "Your GPUs (%s) did not calculate correctly, disabling OpenCL. Please report to the developers.",
            deviceNames)
        openclpow.enabledGpus = []
        raise Exception("GPU did not calculate correctly.")
    if state.shutdown != 0:
        logger.debug("DEBUG: _doGPUPoW interrupted by shutdown")
        raise StopIteration("Interrupted")
    logger.debug("DEBUG: _doGPUPoW completed with nonce: %d, trialValue: %d", 
                nonce, trialValue)
    return [trialValue, nonce]


def estimate(difficulty, format=False):  # pylint: disable=redefined-builtin
    """
    .. todo: fix unused variable
    """
    logger.debug("DEBUG: estimate called with difficulty: %d, format: %s", 
                difficulty, format)
    ret = difficulty / 10
    if ret < 1:
        ret = 1

    if format:
        # pylint: disable=unused-variable
        out = str(int(ret)) + " seconds"
        if ret > 60:
            ret /= 60
            out = str(int(ret)) + " minutes"
        if ret > 60:
            ret /= 60
            out = str(int(ret)) + " hours"
        if ret > 24:
            ret /= 24
            out = str(int(ret)) + " days"
        if ret > 7:
            out = str(int(ret)) + " weeks"
        if ret > 31:
            out = str(int(ret)) + " months"
        if ret > 366:
            ret /= 366
            out = str(int(ret)) + " years"
        ret = None  # Ensure legacy behaviour
        logger.debug("DEBUG: estimate formatted output: %s", out)

    logger.debug("DEBUG: estimate returning: %s", ret)
    return ret


def getPowType():
    """Get the proof of work implementation"""
    logger.debug("DEBUG: getPowType called")
    if openclpow.openclEnabled():
        logger.debug("DEBUG: getPowType returning OpenCL")
        return "OpenCL"
    if bmpow:
        logger.debug("DEBUG: getPowType returning C")
        return "C"
    logger.debug("DEBUG: getPowType returning python")
    return "python"


def notifyBuild(tried=False):
    """Notify the user of the success or otherwise of building the PoW C module"""
    logger.debug("DEBUG: notifyBuild called with tried: %s", tried)
    if bmpow:
        msg = tr._translate("proofofwork", "C PoW module built successfully.")
        logger.debug("DEBUG: notifyBuild - success message: %s", msg)
        queues.UISignalQueue.put(('updateStatusBar', (msg, 1)))
    elif tried:
        msg = tr._translate("proofofwork", "Failed to build C PoW module. Please build it manually.")
        logger.debug("DEBUG: notifyBuild - failed message: %s", msg)
        queues.UISignalQueue.put(
            (
                'updateStatusBar', (
                    msg,
                    1
                )
            )
        )
    else:
        msg = tr._translate("proofofwork", "C PoW module unavailable. Please build it.")
        logger.debug("DEBUG: notifyBuild - unavailable message: %s", msg)
        queues.UISignalQueue.put(('updateStatusBar', (msg, 1)))


def buildCPoW():
    """Attempt to build the PoW C module"""
    logger.debug("DEBUG: buildCPoW called")
    if bmpow is not None:
        logger.debug("DEBUG: buildCPoW - already built, skipping")
        return
    if paths.frozen is not None:
        logger.debug("DEBUG: buildCPoW - frozen environment, skipping")
        notifyBuild(False)
        return
    if sys.platform in ["win32", "win64"]:
        logger.debug("DEBUG: buildCPoW - Windows platform, skipping")
        notifyBuild(False)
        return
    try:
        if "bsd" in sys.platform:
            logger.debug("DEBUG: buildCPoW - BSD platform detected")
            # BSD make
            subprocess.check_call([  # nosec B607, B603
                "make", "-C", os.path.join(paths.codePath(), "bitmsghash"),
                '-f', 'Makefile.bsd'])
        else:
            logger.debug("DEBUG: buildCPoW - GNU make detected")
            # GNU make
            subprocess.check_call([  # nosec B607, B603
                "make", "-C", os.path.join(paths.codePath(), "bitmsghash")])
        if os.path.exists(
            os.path.join(paths.codePath(), "bitmsghash", "bitmsghash.so")
        ):
            logger.debug("DEBUG: buildCPoW - module built successfully")
            init()
            notifyBuild(True)
        else:
            logger.debug("DEBUG: buildCPoW - module file not found after build")
            notifyBuild(True)
    except (OSError, subprocess.CalledProcessError) as e:
        logger.debug("DEBUG: buildCPoW - build failed with error: %s", str(e))
        notifyBuild(True)
    except:  # noqa:E722
        logger.warning(
            'Unexpected exception rised when tried to build bitmsghash lib',
            exc_info=True)
        notifyBuild(True)


def run(target, initialHash):
    """Run the proof of work thread"""
    logger.debug("DEBUG: run called with target: %d, initialHash: %s", 
                target, hexlify(initialHash) if initialHash else "None")
    if state.shutdown != 0:
        logger.debug("DEBUG: run - shutdown detected, raising exception")
        raise  # pylint: disable=misplaced-bare-raise
    target = int(target)
    if openclpow.openclEnabled():
        logger.debug("DEBUG: run - trying OpenCL PoW")
        try:
            return _doGPUPoW(target, initialHash)
        except StopIteration:
            logger.debug("DEBUG: run - OpenCL PoW interrupted")
            raise
        except:  # nosec B110 # noqa:E722 # pylint:disable=bare-except
            logger.debug("DEBUG: run - OpenCL PoW failed, falling back", exc_info=True)
            pass  # fallback
    if bmpow:
        logger.debug("DEBUG: run - trying C PoW")
        try:
            return _doCPoW(target, initialHash)
        except StopIteration:
            logger.debug("DEBUG: run - C PoW interrupted")
            raise
        except:  # nosec B110 # noqa:E722 # pylint:disable=bare-except
            logger.debug("DEBUG: run - C PoW failed, falling back", exc_info=True)
            pass  # fallback
    if paths.frozen == "macosx_app" or not paths.frozen:
        logger.debug("DEBUG: run - trying Fast PoW")
        # on my (Peter Surda) Windows 10, Windows Defender
        # does not like this and fights with PyBitmessage
        # over CPU, resulting in very slow PoW
        # added on 2015-11-29: multiprocesing.freeze_support() doesn't help
        try:
            return _doFastPoW(target, initialHash)
        except StopIteration:
            logger.error("DEBUG: run - Fast PoW got StopIteration")
            raise
        except:  # noqa:E722 # pylint:disable=bare-except
            logger.error("DEBUG: run - Fast PoW got exception:", exc_info=True)
    logger.debug("DEBUG: run - falling back to Safe PoW")
    try:
        return _doSafePoW(target, initialHash)
    except StopIteration:
        logger.debug("DEBUG: run - Safe PoW interrupted")
        raise
    except:  # nosec B110 # noqa:E722 # pylint:disable=bare-except
        logger.debug("DEBUG: run - Safe PoW failed", exc_info=True)
        pass  # fallback


def resetPoW():
    """Initialise the OpenCL PoW"""
    logger.debug("DEBUG: resetPoW called")
    openclpow.initCL()


# init


def init():
    """Initialise PoW"""
    # pylint: disable=global-statement
    global bitmsglib, bmpow
    logger.debug("DEBUG: init called")

    openclpow.initCL()
    if sys.platform == "win32":
        logger.debug("DEBUG: init - Windows platform detected")
        if ctypes.sizeof(ctypes.c_voidp) == 4:
            bitmsglib = 'bitmsghash32.dll'
            logger.debug("DEBUG: init - 32-bit Windows detected")
        else:
            bitmsglib = 'bitmsghash64.dll'
            logger.debug("DEBUG: init - 64-bit Windows detected")
        try:
            # MSVS
            logger.debug("DEBUG: init - trying MSVS stdcall DLL")
            bso = ctypes.WinDLL(os.path.join(paths.codePath(), "bitmsghash", bitmsglib))
            logger.info("Loaded C PoW DLL (stdcall) %s", bitmsglib)
            bmpow = bso.BitmessagePOW
            bmpow.restype = ctypes.c_ulonglong
            _doCPoW(2**63, "")
            logger.info("Successfully tested C PoW DLL (stdcall) %s", bitmsglib)
        except ValueError:
            try:
                # MinGW
                logger.debug("DEBUG: init - trying MinGW cdecl DLL")
                bso = ctypes.CDLL(os.path.join(paths.codePath(), "bitmsghash", bitmsglib))
                logger.info("Loaded C PoW DLL (cdecl) %s", bitmsglib)
                bmpow = bso.BitmessagePOW
                bmpow.restype = ctypes.c_ulonglong
                _doCPoW(2**63, "")
                logger.info("Successfully tested C PoW DLL (cdecl) %s", bitmsglib)
            except Exception as e:
                logger.error("Error: %s", e, exc_info=True)
                bso = None
        except Exception as e:
            logger.error("Error: %s", e, exc_info=True)
            bso = None
    else:
        logger.debug("DEBUG: init - non-Windows platform detected")
        try:
            bso = ctypes.CDLL(os.path.join(paths.codePath(), "bitmsghash", bitmsglib))
            logger.debug("DEBUG: init - successfully loaded default library")
        except OSError:
            import glob
            try:
                logger.debug("DEBUG: init - trying to find library with glob")
                bso = ctypes.CDLL(glob.glob(os.path.join(
                    paths.codePath(), "bitmsghash", "bitmsghash*.so"
                ))[0])
            except (OSError, IndexError):
                logger.debug("DEBUG: init - library not found with glob")
                bso = None
        except:  # noqa:E722
            logger.debug("DEBUG: init - error loading library", exc_info=True)
            bso = None
        else:
            logger.info("Loaded C PoW DLL %s", bitmsglib)
    if bso:
        try:
            bmpow = bso.BitmessagePOW
            bmpow.restype = ctypes.c_ulonglong
            logger.debug("DEBUG: init - successfully initialized bmpow")
        except:  # noqa:E722
            logger.debug("DEBUG: init - failed to initialize bmpow", exc_info=True)
            bmpow = None
    else:
        bmpow = None
    if bmpow is None:
        logger.debug("DEBUG: init - bmpow not available, trying to build")
        buildCPoW()
