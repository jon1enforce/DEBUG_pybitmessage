"""
Core classes for loading images and converting them to a Texture.
The raw image data can be keep in memory for further access
"""
import hashlib
import logging
from six import BytesIO

from PIL import Image
from kivy.core.image import Image as CoreImage
from kivy.uix.image import Image as kiImage

logger = logging.getLogger('default')

# constants
RESOLUTION = 300, 300
V_RESOLUTION = 7, 7
BACKGROUND_COLOR = 255, 255, 255, 255
MODE = "RGB"


def generate(Generate_string=None):
    """Generating string"""
    logger.debug("DEBUG: Starting identicon generation")
    logger.debug("DEBUG: Input string: %s", Generate_string)
    
    try:
        hash_string = generate_hash(Generate_string)
        logger.debug("DEBUG: Generated hash: %s", hash_string)
        
        color = random_color(hash_string)
        logger.debug("DEBUG: Generated color: %s", color)
        
        logger.debug("DEBUG: Creating base image with resolution %s", V_RESOLUTION)
        image = Image.new(MODE, V_RESOLUTION, BACKGROUND_COLOR)
        
        image = generate_image(image, color, hash_string)
        logger.debug("DEBUG: Pattern generated on base image")
        
        logger.debug("DEBUG: Resizing image to %s", RESOLUTION)
        image = image.resize(RESOLUTION, 0)
        
        data = BytesIO()
        image.save(data, format='png')
        data.seek(0)
        logger.debug("DEBUG: Image saved to BytesIO buffer")
        
        im = CoreImage(BytesIO(data.read()), ext='png')
        logger.debug("DEBUG: CoreImage created from buffer")
        
        beeld = kiImage()
        beeld.texture = im.texture
        logger.debug("DEBUG: kiImage created with texture")
        
        return beeld
    except Exception as e:
        logger.error("DEBUG: Error in identicon generation: %s", str(e))
        raise


def generate_hash(string):
    """Generating hash"""
    logger.debug("DEBUG: Generating hash from string")
    try:
        if not string:
            logger.warning("DEBUG: Empty string received for hashing")
            string = "default"
            
        # make input case insensitive
        string = str.lower(string)
        logger.debug("DEBUG: Normalized string: %s", string)
        
        hash_object = hashlib.sha256(str.encode(string))  # nosec B324, B303
        hex_digest = hash_object.hexdigest()
        logger.debug("DEBUG: MD5 hash generated: %s", hex_digest)
        
        return hex_digest
    except Exception as e:
        logger.error("DEBUG: Error generating hash: %s", str(e))
        raise


def random_color(hash_string):
    """Getting random color"""
    logger.debug("DEBUG: Generating color from hash: %s", hash_string)
    try:
        # remove first three digits from hex string
        split = 6
        rgb = hash_string[:split]
        logger.debug("DEBUG: RGB hex part: %s", rgb)
        
        split = 2
        r = rgb[:split]
        g = rgb[split:2 * split]
        b = rgb[2 * split:3 * split]
        logger.debug("DEBUG: RGB components - R:%s G:%s B:%s", r, g, b)
        
        color = (int(r, 16), int(g, 16), int(b, 16), 0xFF)
        logger.debug("DEBUG: Final color tuple: %s", color)
        
        return color
    except Exception as e:
        logger.error("DEBUG: Error generating color: %s", str(e))
        raise


def generate_image(image, color, hash_string):
    """Generating images"""
    logger.debug("DEBUG: Generating image pattern with color %s", color)
    try:
        hash_string = hash_string[6:]
        logger.debug("DEBUG: Using hash substring: %s", hash_string)
        
        lower_x = 1
        lower_y = 1
        upper_x = int(V_RESOLUTION[0] / 2) + 1
        upper_y = V_RESOLUTION[1] - 1
        limit_x = V_RESOLUTION[0] - 1
        index = 0
        
        logger.debug("DEBUG: Pattern generation parameters - "
                   "x:%d-%d, y:%d-%d, limit_x:%d",
                   lower_x, upper_x, lower_y, upper_y, limit_x)
        
        for x in range(lower_x, upper_x):
            for y in range(lower_y, upper_y):
                if int(hash_string[index], 16) % 2 == 0:
                    image.putpixel((x, y), color)
                    image.putpixel((limit_x - x, y), color)
                    logger.debug("DEBUG: Pixel set at (%d,%d) and (%d,%d)",
                               x, y, limit_x - x, y)
                index = index + 1
                
        logger.debug("DEBUG: Image pattern generation complete")
        return image
    except Exception as e:
        logger.error("DEBUG: Error generating image pattern: %s", str(e))
        raise
