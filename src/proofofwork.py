# pylint: disable=import-outside-toplevel,too-many-branches,too-many-statements

"""
Proof of work calculation
"""

import ctypes
import hashlib
import os
import subprocess  # nosec B404
import sys
import tempfile
import time
from struct import pack, unpack
from binascii import hexlify

import highlevelcrypto
import openclpow
import paths
import queues
import state
from bmconfigparser import config
from debug import logger
from defaults import (
    networkDefaultProofOfWorkNonceTrialsPerByte,
    networkDefaultPayloadLengthExtraBytes)
from tr import _translate


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
        self.prefix = prefix
        try:
            sys.stdout.flush()
            self._stdout = sys.stdout
            self._stdout_fno = os.dup(sys.stdout.fileno())
        except AttributeError:
            # NullWriter instance has no attribute 'fileno' on Windows
            self._stdout = None
        else:
            self._dst, self._filepath = tempfile.mkstemp()

    def __enter__(self):
        if not self._stdout:
            return
        stdout = os.dup(1)
        os.dup2(self._dst, 1)
        os.close(self._dst)
        sys.stdout = os.fdopen(stdout, 'w')

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self._stdout:
            return
        sys.stdout.close()
        sys.stdout = self._stdout
        sys.stdout.flush()
        os.dup2(self._stdout_fno, 1)

        with open(self._filepath, 'r', encoding='utf-8') as out:
            for line in out:
                logger.info('%s: %s', self.prefix, line.rstrip())
        os.remove(self._filepath)


def _set_idle():
    if 'linux' in sys.platform:
        os.nice(20)
    else:
        try:
            # pylint: disable=no-member,import-error
            sys.getwindowsversion()
            import win32api
            import win32process
            import win32con

            handle = win32api.OpenProcess(
                win32con.PROCESS_ALL_ACCESS, True,
                win32api.GetCurrentProcessId())
            win32process.SetPriorityClass(
                handle, win32process.IDLE_PRIORITY_CLASS)
        except (ImportError, OSError, AttributeError):  # nosec B110
            pass


def trial_value(nonce, initialHash):
    """Calculate PoW trial value"""
    if isinstance(initialHash, str):
        initialHash = initialHash.encode('latin-1')
    
    trialValue, = unpack(
        '>Q', highlevelcrypto.double_sha512(
            pack('>Q', nonce) + initialHash)[0:8])
    return trialValue


def _pool_worker(nonce, initialHash, target, pool_size):
    _set_idle()
    trialValue = float('inf')
    
    if isinstance(initialHash, str):
        initialHash = initialHash.encode('latin-1')
    
    while trialValue > target:
        nonce += pool_size
        trialValue = trial_value(nonce, initialHash)
    return trialValue, nonce


def _doSafePoW(target, initialHash):
    logger.debug('Safe PoW start')
    
    if isinstance(initialHash, str):
        initialHash = initialHash.encode('latin-1')
    
    nonce = 0
    trialValue = float('inf')
    while trialValue > target and state.shutdown == 0:
        nonce += 1
        trialValue = trial_value(nonce, initialHash)
    if state.shutdown != 0:
        raise StopIteration("Interrupted")
    logger.debug('Safe PoW done')
    return trialValue, nonce


def _doFastPoW(target, initialHash):
    logger.debug('Fast PoW start')
    from multiprocessing import Pool, cpu_count
    
    if isinstance(initialHash, str):
        initialHash = initialHash.encode('latin-1')
    
    try:
        pool_size = cpu_count()
    except:  # noqa:E722
        pool_size = 4
    
    maxCores = config.safeGetInt('bitmessagesettings', 'maxcores', 99999)
    pool_size = min(pool_size, maxCores)

    pool = Pool(processes=pool_size)
    result = []
    for i in range(pool_size):
        result.append(pool.apply_async(
            _pool_worker, args=(i, initialHash, target, pool_size)))

    while True:
        if state.shutdown != 0:
            try:
                pool.terminate()
                pool.join()
            except:  # nosec B110 # noqa:E722
                pass
            raise StopIteration("Interrupted")
        for i in range(pool_size):
            if result[i].ready():
                try:
                    result[i].successful()
                except AssertionError:
                    pool.terminate()
                    pool.join()
                    raise StopIteration("Interrupted")
                result_val = result[i].get()
                pool.terminate()
                pool.join()
                logger.debug('Fast PoW done')
                return result_val[0], result_val[1]
        time.sleep(0.2)


def _doCPoW(target, initialHash):
    if isinstance(initialHash, str):
        initialHash = initialHash.encode('latin-1')
    
    if len(initialHash) != 64:
        raise ValueError(f"initialHash must be 64 bytes, got {len(initialHash)}")
    
    with LogOutput():
        h = initialHash
        m = target
        out_h = ctypes.pointer(ctypes.create_string_buffer(h, 64))
        out_m = ctypes.c_ulonglong(m)
        logger.debug('C PoW start')
        
        if bmpow is None:
            raise RuntimeError("C PoW library not loaded")
        
        nonce = bmpow(out_h, out_m)

    trialValue = trial_value(nonce, initialHash)
    if state.shutdown != 0:
        raise StopIteration("Interrupted")
    logger.debug('C PoW done')
    return trialValue, nonce


def _doGPUPoW(target, initialHash):
    logger.debug('GPU PoW start')
    
    if isinstance(initialHash, str):
        initialHash = initialHash.encode('latin-1')
    
    initialHash_hex = hexlify(initialHash).decode('ascii')
    nonce = openclpow.do_opencl_pow(initialHash_hex, target)
    
    trialValue = trial_value(nonce, initialHash)
    if trialValue > target:
        deviceNames = ", ".join(gpu.name for gpu in openclpow.enabledGpus)
        queues.UISignalQueue.put((
            'updateStatusBar', (
                _translate(
                    "MainWindow",
                    "Your GPU(s) did not calculate correctly,"
                    " disabling OpenCL. Please report to the developers."
                ), 1)
        ))
        logger.error(
            'Your GPUs (%s) did not calculate correctly, disabling OpenCL.'
            ' Please report to the developers.', deviceNames)
        openclpow.enabledGpus = []
        raise Exception("GPU did not calculate correctly.")
    
    if state.shutdown != 0:
        raise StopIteration("Interrupted")
    
    logger.debug('GPU PoW done')
    return trialValue, nonce


def getPowType():
    if openclpow.openclEnabled():
        return "OpenCL"
    if bmpow:
        return "C"
    return "python"


def notifyBuild(tried=False):
    if bmpow:
        queues.UISignalQueue.put(('updateStatusBar', (_translate(
            "proofofwork", "C PoW module built successfully."), 1)))
    elif tried:
        queues.UISignalQueue.put(('updateStatusBar', (_translate(
            "proofofwork",
            "Failed to build C PoW module. Please build it manually."), 1)))
    else:
        queues.UISignalQueue.put(('updateStatusBar', (_translate(
            "proofofwork", "C PoW module unavailable. Please build it."), 1)))


def buildCPoW():
    """Attempt to build the PoW C module"""
    global bmpow  # DIESE ZEILE GANZ OBEN EINFÜGEN!
    
    if bmpow is not None:
        return
    if paths.frozen or sys.platform.startswith('win'):
        notifyBuild(False)
        return

    try:
        make_cmd = ['make', '-C', os.path.join(paths.codePath(), 'bitmsghash')]
        if "bsd" in sys.platform:
            make_cmd += ['-f', 'Makefile.bsd']

        subprocess.check_call(make_cmd)  # nosec B603
        
        lib_path = os.path.join(paths.codePath(), 'bitmsghash', 'bitmsghash.so')
        if os.path.exists(lib_path):
            # global bmpow  # DIESE ZEILE LÖSCHEN - sie steht jetzt oben!
            try:
                bso = ctypes.CDLL(lib_path)
                if hasattr(bso, 'BitmessagePOW'):
                    bmpow = bso.BitmessagePOW
                    bmpow.restype = ctypes.c_ulonglong
                    logger.info('Successfully built and loaded C PoW module')
                else:
                    logger.warning('Built library missing BitmessagePOW function')
                    bmpow = None
            except Exception as e:
                logger.warning('Failed to load built library: %s', e)
                bmpow = None
    except (OSError, subprocess.CalledProcessError) as e:
        logger.debug('Build failed: %s', e)
    except Exception as e:  # noqa:E722
        logger.warning(
            'Unexpected exception raised when tried to build bitmsghash lib: %s',
            e, exc_info=True)
    
    notifyBuild(True)


def run(target, initialHash):
    if state.shutdown != 0:
        raise StopIteration("Interrupted")
    
    target = int(target)
    
    if isinstance(initialHash, str):
        initialHash = initialHash.encode('latin-1')
    
    logger.debug('PoW calculation started: target=%s, hash_len=%s', 
                target, len(initialHash))
    
    if openclpow.openclEnabled():
        try:
            return _doGPUPoW(target, initialHash)
        except StopIteration:
            raise
        except Exception as e:
            logger.debug('GPU PoW failed, falling back: %s', e)
    
    if bmpow:
        try:
            return _doCPoW(target, initialHash)
        except StopIteration:
            raise
        except Exception as e:
            logger.debug('C PoW failed, falling back: %s', e)
    
    if paths.frozen == "macosx_app" or not paths.frozen:
        try:
            return _doFastPoW(target, initialHash)
        except StopIteration:
            raise
        except Exception as e:
            logger.debug('Fast Python PoW failed, falling back: %s', e)
    
    return _doSafePoW(target, initialHash)


def getTarget(payloadLength, ttl, nonceTrialsPerByte, payloadLengthExtraBytes):
    return 2 ** 64 / (
        nonceTrialsPerByte * (
            payloadLength + 8 + payloadLengthExtraBytes + ((
                ttl * (
                    payloadLength + 8 + payloadLengthExtraBytes
                )) / (2 ** 16))
        ))


def calculate(
    payload, ttl,
    nonceTrialsPerByte=networkDefaultProofOfWorkNonceTrialsPerByte,
    payloadLengthExtraBytes=networkDefaultPayloadLengthExtraBytes
):
    if isinstance(payload, str):
        payload = payload.encode('utf-8')
    
    target = getTarget(
        len(payload), ttl, nonceTrialsPerByte, payloadLengthExtraBytes)
    
    initialHash = hashlib.sha512(payload).digest()
    
    return run(target, initialHash)


def resetPoW():
    openclpow.initCL()


def init():
    """Initialise PoW"""
    # pylint: disable=broad-exception-caught,global-statement
    global bitmsglib, bmpow  # DIESE ZEILE MUSS GANZ OBEN STEHEN!

    print("DEBUG [proofofwork.init]: Starting PoW initialization (Python 3 version)")

    openclpow.initCL()
    
    if sys.platform.startswith('win'):
        bitmsglib = (
            'bitmsghash32.dll' if ctypes.sizeof(ctypes.c_voidp) == 4 else
            'bitmsghash64.dll')
    else:
        bitmsglib = 'bitmsghash.so'
    
    print(f"DEBUG [proofofwork.init]: Target library: {bitmsglib}")
    
    bmpow = None
    
    lib_path = os.path.join(paths.codePath(), 'bitmsghash', bitmsglib)
    
    if os.path.exists(lib_path):
        print(f"DEBUG [proofofwork.init]: Library exists at {lib_path}")
        try:
            if sys.platform.startswith('win'):
                try:
                    bso = ctypes.WinDLL(lib_path)
                    print("DEBUG [proofofwork.init]: Loaded as WinDLL (MSVS)")
                except (OSError, AttributeError):
                    try:
                        bso = ctypes.CDLL(lib_path)
                        print("DEBUG [proofofwork.init]: Loaded as CDLL (MinGW)")
                    except (OSError, AttributeError) as e:
                        print(f"DEBUG [proofofwork.init]: Failed to load Windows library: {e}")
                        bso = None
            else:
                try:
                    bso = ctypes.CDLL(lib_path)
                    print("DEBUG [proofofwork.init]: Loaded as CDLL")
                except (OSError, AttributeError) as e:
                    print(f"DEBUG [proofofwork.init]: Failed to load library: {e}")
                    bso = None
            
            if bso and hasattr(bso, 'BitmessagePOW'):
                bmpow = bso.BitmessagePOW
                bmpow.restype = ctypes.c_ulonglong
                print("DEBUG [proofofwork.init]: BitmessagePOW function found")
                print("DEBUG [proofofwork.init]: C library loaded (testing disabled)")
            else:
                print("DEBUG [proofofwork.init]: BitmessagePOW function not found")
                bmpow = None
                
        except Exception as e:
            print(f"DEBUG [proofofwork.init]: Error loading library: {e}")
            bmpow = None
    else:
        print(f"DEBUG [proofofwork.init]: Library not found at {lib_path}")
        bmpow = None
    
    if bmpow is None:
        print("DEBUG [proofofwork.init]: Attempting to build C library...")
        buildCPoW()
    
    print("DEBUG [proofofwork.init]: PoW initialization complete")
    pow_type = getPowType()
    print(f"DEBUG [proofofwork.init]: Using PoW type: {pow_type}")
