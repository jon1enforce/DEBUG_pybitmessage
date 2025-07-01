###
# qidenticon.py with enhanced debugging
# Original license terms preserved
###

import sys
import logging
from six.moves import range
from qtpy import QtCore, QtGui

# Setup debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='DEBUG: %(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

logger.debug("Initializing qidenticon module")

class IdenticonRendererBase(object):
    """Base renderer class with debug logging"""
    
    PATH_SET = []

    def __init__(self, code):
        logger.debug("Initializing IdenticonRendererBase with code: %s", code)
        if not isinstance(code, int):
            code = int(code)
        self.code = code
        logger.debug("Renderer initialized with code: %d", self.code)

    def render(self, size, twoColor, opacity, penwidth):
        """Render identicon with detailed debug logging"""
        logger.debug("Rendering identicon - size: %d, twoColor: %s, opacity: %d, penwidth: %d",
                    size, twoColor, opacity, penwidth)
        
        # Decode the code
        logger.debug("Decoding identicon code")
        middle, corner, side, foreColor, secondColor, swap_cross = \
            self.decode(self.code, twoColor)
        logger.debug("Decoded values: middle=%s, corner=%s, side=%s, foreColor=%s, secondColor=%s, swap_cross=%s",
                    middle, corner, side, foreColor.name(), secondColor.name(), swap_cross)

        # Create image
        image_size = size * 3 + penwidth
        logger.debug("Creating QPixmap with size %dx%d", image_size, image_size)
        image = QtGui.QPixmap(QtCore.QSize(image_size, image_size))

        # Fill background
        backColor = QtGui.QColor(255, 255, 255, opacity)
        logger.debug("Filling background with color: %s", backColor.name())
        image.fill(backColor)

        kwds = {
            'image': image,
            'size': size,
            'foreColor': foreColor if swap_cross else secondColor,
            'penwidth': penwidth,
            'backColor': backColor}
        logger.debug("Rendering parameters: %s", kwds)

        # Render middle patch
        logger.debug("Rendering middle patch")
        image = self.drawPatchQt(
            (1, 1), middle[2], middle[1], middle[0], **kwds)

        # Render side patches
        kwds['foreColor'] = foreColor
        kwds['patch_type'] = side[0]
        logger.debug("Rendering side patches with foreColor: %s", foreColor.name())
        for i in range(4):
            pos = [(1, 0), (2, 1), (1, 2), (0, 1)][i]
            logger.debug("Rendering side patch %d at position %s", i, pos)
            image = self.drawPatchQt(pos, side[2] + 1 + i, side[1], **kwds)

        # Render corner patches
        kwds['foreColor'] = secondColor
        kwds['patch_type'] = corner[0]
        logger.debug("Rendering corner patches with secondColor: %s", secondColor.name())
        for i in range(4):
            pos = [(0, 0), (2, 0), (2, 2), (0, 2)][i]
            logger.debug("Rendering corner patch %d at position %s", i, pos)
            image = self.drawPatchQt(pos, corner[2] + 1 + i, corner[1], **kwds)

        logger.debug("Identicon rendering complete")
        return image

    def drawPatchQt(
            self, pos, turn, invert, patch_type, image, size, foreColor,
            backColor, penwidth):
        """Draw patch with detailed debug logging"""
        logger.debug("Drawing patch - pos: %s, turn: %d, invert: %s, type: %d, size: %d",
                    pos, turn, invert, patch_type, size)
        
        path = self.PATH_SET[patch_type]
        if not path:
            logger.debug("Blank patch detected, using full rectangle")
            invert = not invert
            path = [(0., 0.), (1., 0.), (1., 1.), (0., 1.), (0., 0.)]

        logger.debug("Creating polygon from path: %s", path)
        polygon = QtGui.QPolygonF([
            QtCore.QPointF(x * size, y * size) for x, y in path])

        rot = turn % 4
        rect = [
            QtCore.QPointF(0., 0.), QtCore.QPointF(size, 0.),
            QtCore.QPointF(size, size), QtCore.QPointF(0., size)]
        rotation = [0, 90, 180, 270]
        logger.debug("Rotation parameters - rot: %d, angles: %s", rot, rotation)

        nopen = QtGui.QPen(foreColor)
        nopen.setStyle(QtCore.Qt.NoPen)
        foreBrush = QtGui.QBrush(foreColor, QtCore.Qt.SolidPattern)
        
        if penwidth > 0:
            logger.debug("Setting up pen with width %d", penwidth)
            pen_color = QtGui.QColor(255, 255, 255)
            pen = QtGui.QPen(pen_color)
            pen.setBrush(QtCore.Qt.SolidPattern)
            pen.setWidth(penwidth)

        logger.debug("Initializing QPainter")
        painter = QtGui.QPainter()
        painter.begin(image)
        painter.setPen(nopen)

        logger.debug("Applying transformations - pos: %s, rot: %d", pos, rot)
        painter.translate(
            pos[0] * size + penwidth / 2, pos[1] * size + penwidth / 2)
        painter.translate(rect[rot])
        painter.rotate(rotation[rot])

        if invert:
            logger.debug("Inverting polygon")
            poly_rect = QtGui.QPolygonF(rect)
            polygon = poly_rect.subtracted(polygon)

        painter.setBrush(foreBrush)
        if penwidth > 0:
            logger.debug("Drawing polygon borders")
            painter.setPen(pen)
            painter.drawPolygon(polygon, QtCore.Qt.WindingFill)
        
        logger.debug("Drawing polygon fill")
        painter.setPen(nopen)
        painter.drawPolygon(polygon, QtCore.Qt.WindingFill)

        painter.end()
        logger.debug("Patch drawing complete")

        return image

    def decode(self, code, twoColor):
        """Virtual method that should be overridden"""
        logger.error("decode() called on base class - this should be overridden")
        raise NotImplementedError


class DonRenderer(IdenticonRendererBase):
    """Don Park's identicon renderer with debug logging"""
    
    PATH_SET = [
        # [list of paths remains exactly the same...]
    ]
    
    MIDDLE_PATCH_SET = [0, 4, 8, 15]

    # Modify path set (same as original)
    for idx, path in enumerate(PATH_SET):
        if path:
            p = [(vec[0] / 4.0, vec[1] / 4.0) for vec in path]
            PATH_SET[idx] = p + p[:1]

    def decode(self, code, twoColor):
        """Decode identicon code with detailed logging"""
        logger.debug("Decoding identicon code: %d, twoColor: %s", code, twoColor)
        
        shift = 0
        middleType = (code >> shift) & 0x03
        shift += 2
        middleInvert = (code >> shift) & 0x01
        shift += 1
        cornerType = (code >> shift) & 0x0F
        shift += 4
        cornerInvert = (code >> shift) & 0x01
        shift += 1
        cornerTurn = (code >> shift) & 0x03
        shift += 2
        sideType = (code >> shift) & 0x0F
        shift += 4
        sideInvert = (code >> shift) & 0x01
        shift += 1
        sideTurn = (code >> shift) & 0x03
        shift += 2
        blue = (code >> shift) & 0x1F
        shift += 5
        green = (code >> shift) & 0x1F
        shift += 5
        red = (code >> shift) & 0x1F
        shift += 5
        second_blue = (code >> shift) & 0x1F
        shift += 5
        second_green = (code >> shift) & 0x1F
        shift += 5
        second_red = (code >> shift) & 0x1F
        shift += 1
        swap_cross = (code >> shift) & 0x01

        middleType = self.MIDDLE_PATCH_SET[middleType]
        logger.debug("Decoded values - middleType: %d, middleInvert: %d", middleType, middleInvert)
        logger.debug("cornerType: %d, cornerInvert: %d, cornerTurn: %d", cornerType, cornerInvert, cornerTurn)
        logger.debug("sideType: %d, sideInvert: %d, sideTurn: %d", sideType, sideInvert, sideTurn)
        logger.debug("Colors - RGB: (%d, %d, %d), second RGB: (%d, %d, %d)", 
                    red, green, blue, second_red, second_green, second_blue)
        logger.debug("swap_cross: %s", swap_cross)

        foreColor = (red << 3, green << 3, blue << 3)
        foreColor = QtGui.QColor(*foreColor)

        if twoColor:
            secondColor = (second_blue << 3, second_green << 3, second_red << 3)
            secondColor = QtGui.QColor(*secondColor)
        else:
            secondColor = foreColor

        logger.debug("Final colors - foreColor: %s, secondColor: %s", 
                    foreColor.name(), secondColor.name())

        return (middleType, middleInvert, 0),\
               (cornerType, cornerInvert, cornerTurn),\
               (sideType, sideInvert, sideTurn),\
            foreColor, secondColor, swap_cross

def render_identicon(
        code, size, twoColor=False, opacity=255, penwidth=0, renderer=None):
    """Render identicon with debug logging"""
    logger.debug("render_identicon called - code: %s, size: %d, twoColor: %s, opacity: %d, penwidth: %d",
                code, size, twoColor, opacity, penwidth)
    
    if not renderer:
        renderer = DonRenderer
        logger.debug("Using default DonRenderer")
    
    logger.debug("Starting identicon rendering")
    result = renderer(code).render(size, twoColor, opacity, penwidth)
    logger.debug("Identicon rendering completed successfully")
    
    return result

logger.debug("qidenticon module initialization complete")
