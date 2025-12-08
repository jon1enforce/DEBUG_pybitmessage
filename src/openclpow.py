"""
Module for Proof of Work using OpenCL
"""
import logging
import os
from struct import pack
import re
import paths
from bmconfigparser import config
from state import shutdown

logger = logging.getLogger('default')

try:
    import numpy
    import pyopencl as cl
    libAvailable = True
    logger.debug("DEBUG: Successfully imported numpy and pyopencl")
except ImportError as e:
    libAvailable = False
    logger.debug("DEBUG: Import failed: %s", str(e))

ctx = False
queue = False
program = False
gpus = []
enabledGpus = []
vendors = []
hash_dt = None


def initCL():
    """Initialize OpenCL engine"""
    global ctx, queue, program, hash_dt  # pylint: disable=global-statement
    logger.debug("DEBUG: initCL() called")
    
    if libAvailable is False:
        logger.debug("DEBUG: OpenCL libraries not available, skipping initialization")
        return
    
    logger.debug("DEBUG: Resetting OpenCL state")
    del enabledGpus[:]
    del vendors[:]
    del gpus[:]
    ctx = False
    
    try:
        logger.debug("DEBUG: Creating numpy dtype for hash")
        hash_dt = numpy.dtype([('target', numpy.uint64), ('v', numpy.str_, 73)])
        
        try:
            logger.debug("DEBUG: Getting OpenCL platforms")
            for platform in cl.get_platforms():
                logger.debug("DEBUG: Processing platform: %s", platform.vendor)
                current_gpus = platform.get_devices(device_type=cl.device_type.GPU)
                gpus.extend(current_gpus)
                logger.debug("DEBUG: Found %d GPU devices on platform %s", 
                           len(current_gpus), platform.vendor)
                
                if config.safeGet("bitmessagesettings", "opencl") == platform.vendor:
                    enabled = platform.get_devices(device_type=cl.device_type.GPU)
                    enabledGpus.extend(enabled)
                    logger.debug("DEBUG: Added %d enabled GPUs from platform %s", 
                                len(enabled), platform.vendor)
                
                if platform.vendor not in vendors:
                    vendors.append(platform.vendor)
                    logger.debug("DEBUG: Added new vendor: %s", platform.vendor)
        
        except Exception as e:
            logger.debug("DEBUG: Error getting platform devices: %s", str(e))
            pass
        
        if enabledGpus:
            logger.debug("DEBUG: Initializing OpenCL context with %d enabled GPUs", 
                        len(enabledGpus))
            ctx = cl.Context(devices=enabledGpus)
            queue = cl.CommandQueue(ctx)
            
            cl_path = os.path.join(paths.codePath(), "bitmsghash", 'bitmsghash.cl')
            logger.debug("DEBUG: Loading OpenCL kernel from: %s", cl_path)
            
            with open(cl_path, 'r') as f:
                fstr = ''.join(f.readlines())
                program = cl.Program(ctx, fstr).build(options="")
                logger.info("Loaded OpenCL kernel")
                logger.debug("DEBUG: Successfully built OpenCL program")
        else:
            logger.info("No OpenCL GPUs found")
            logger.debug("DEBUG: No enabled GPUs available")
            del enabledGpus[:]
    
    except Exception as e:
        logger.error("OpenCL initialization failed: ", exc_info=True)
        logger.debug("DEBUG: OpenCL init error details: %s", str(e))
        del enabledGpus[:]


def openclAvailable():
    """Are there any OpenCL GPUs available?"""
    logger.debug("DEBUG: openclAvailable() called, GPU count: %d", len(gpus))
    return bool(gpus)


def openclEnabled():
    """Is OpenCL enabled (and available)?"""
    logger.debug("DEBUG: openclEnabled() called, enabled GPU count: %d", len(enabledGpus))
    return bool(enabledGpus)


def do_opencl_pow(hash_, target):
    """Perform PoW using OpenCL"""
    logger.debug("DEBUG: do_opencl_pow() called with hash: %s, target: %d", hash_, target)
    
    output = numpy.zeros(1, dtype=[('v', numpy.uint64, 1)])
    if not enabledGpus:
        logger.debug("DEBUG: No enabled GPUs, returning zero")
        return output[0][0]

    try:
        logger.debug("DEBUG: Preparing input data")
        data = numpy.zeros(1, dtype=hash_dt, order='C')
        data[0]['v'] = ("0000000000000000" + hash_).decode("hex")
        data[0]['target'] = target

        logger.debug("DEBUG: Creating OpenCL buffers")
        hash_buf = cl.Buffer(ctx, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=data)
        dest_buf = cl.Buffer(ctx, cl.mem_flags.WRITE_ONLY, output.nbytes)

        kernel = program.kernel_sha512
        worksize = kernel.get_work_group_info(cl.kernel_work_group_info.WORK_GROUP_SIZE, enabledGpus[0])
        logger.debug("DEBUG: Work group size: %d", worksize)

        kernel.set_arg(0, hash_buf)
        kernel.set_arg(1, dest_buf)

        progress = 0
        globamt = worksize * 2000
        logger.debug("DEBUG: Starting OpenCL computation")

        while output[0][0] == 0 and shutdown == 0:
            kernel.set_arg(2, pack("<Q", progress))
            cl.enqueue_nd_range_kernel(queue, kernel, (globamt,), (worksize,))
            
            try:
                cl.enqueue_read_buffer(queue, dest_buf, output)
            except AttributeError:
                cl.enqueue_copy(queue, output, dest_buf)
            
            queue.finish()
            progress += globamt
            
            if progress % (globamt * 10) == 0:  # Log every 10 iterations
                logger.debug("DEBUG: PoW progress - tries: %d", progress)

        if shutdown != 0:
            logger.debug("DEBUG: PoW interrupted by shutdown")
            raise Exception("Interrupted")
        
        logger.debug("DEBUG: PoW completed after %d tries, result: %d", progress, output[0][0])
        return output[0][0]
    
    except Exception as e:
        logger.error("DEBUG: OpenCL PoW failed: %s", str(e))
        raise

# SECURITY PATCH: Input validation for OpenCL config
def validate_opencl_config():
    """Validate OpenCL configuration to prevent injection attacks"""
    opencl_value = config.safeGet('bitmessagesettings', 'opencl')
    if opencl_value and not re.match(r'^[a-zA-Z0-9_\-\.]+$', opencl_value):
        logger.error("SECURITY: Invalid OpenCL config value detected")
        return False
    return True

# Wrap OpenCL functions with security checks
def safe_opencl_enabled():
    """Safely check if OpenCL is enabled"""
    if not validate_opencl_config():
        return False
    return original_opencl_enabled()

# Replace original functions
original_opencl_enabled = openclEnabled
openclEnabled = safe_opencl_enabled
