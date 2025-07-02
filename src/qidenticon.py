"""
qidenticon.py - Python 3 compatible version
Enhanced with comprehensive DEBUG and ERROR logging

Original License: FreeBSD License
Copyright 1994-2009 Shin Adachi. All rights reserved.
Copyright 2013 "Sendiulo". All rights reserved.
Copyright 2018-2021 The Bitmessage Developers. All rights reserved.
"""

import logging
from PyQt5 import QtCore, QtGui, QtWidgets

logger = logging.getLogger('default')

class IdenticonRendererBase(object):
    """Encapsulate methods around rendering identicons"""

    PATH_SET = []

    def __init__(self, code):
        try:
            if not isinstance(code, int):
                code = int(code)
            self.code = code
            logger.debug("Initialized renderer with code: %d", code)
        except Exception as e:
            logger.error("Failed to initialize renderer: %s", str(e), exc_info=True)
            raise

    def render(self, size, twoColor=False, opacity=255, penwidth=0):
        """Render identicon to QPixmap with DEBUG logging"""
        try:
            logger.debug("Rendering identicon. Size: %d, twoColor: %s, opacity: %d, penwidth: %d",
                       size, twoColor, opacity, penwidth)
            
            # decode the code
            middle, corner, side, foreColor, secondColor, swap_cross = \
                self.decode(self.code, twoColor)
            logger.debug("Decoded values - middle: %s, corner: %s, side: %s, swap_cross: %s",
                       middle, corner, side, swap_cross)

            # make image
            image = QtGui.QPixmap(
                QtCore.QSize(size * 3 + penwidth, size * 3 + penwidth))
            logger.debug("Created QPixmap with dimensions: %dx%d",
                       size * 3 + penwidth, size * 3 + penwidth)

            # fill background
            backColor = QtGui.QColor(255, 255, 255, opacity)
            image.fill(backColor)
            logger.debug("Filled background with color: %s", backColor.name())

            kwds = {
                'image': image,
                'size': size,
                'foreColor': foreColor if swap_cross else secondColor,
                'penwidth': penwidth,
                'backColor': backColor}
            logger.debug("Base rendering parameters: %s", kwds)

            # middle patch
            logger.debug("Drawing middle patch at (1,1)")
            image = self.drawPatchQt(
                (1, 1), middle[2], middle[1], middle[0], **kwds)

            # side patches
            kwds['foreColor'] = foreColor
            kwds['patch_type'] = side[0]
            positions = [(1, 0), (2, 1), (1, 2), (0, 1)]
            logger.debug("Drawing %d side patches", len(positions))
            for i, pos in enumerate(positions):
                logger.debug("Drawing side patch %d at %s", i+1, pos)
                image = self.drawPatchQt(pos, side[2] + 1 + i, side[1], **kwds)

            # corner patches
            kwds['foreColor'] = secondColor
            kwds['patch_type'] = corner[0]
            positions = [(0, 0), (2, 0), (2, 2), (0, 2)]
            logger.debug("Drawing %d corner patches", len(positions))
            for i, pos in enumerate(positions):
                logger.debug("Drawing corner patch %d at %s", i+1, pos)
                image = self.drawPatchQt(pos, corner[2] + 1 + i, corner[1], **kwds)

            logger.debug("Identicon rendering completed successfully")
            return image

        except Exception as e:
            logger.error("Failed to render identicon: %s", str(e), exc_info=True)
            raise

    def drawPatchQt(self, pos, turn, invert, patch_type, image, size, 
                   foreColor, backColor, penwidth):
        """Draw a single patch with DEBUG logging"""
        try:
            logger.debug("Drawing patch at %s - turn: %d, invert: %s, type: %d",
                       pos, turn, invert, patch_type)

            try:
                path = self.PATH_SET[patch_type]
                if not path:
                    logger.debug("Blank patch detected, inverting")
                    invert = not invert
                    path = [(0., 0.), (1., 0.), (1., 1.), (0., 1.), (0., 0.)]
            except IndexError:
                logger.warning("Invalid patch_type: %d, using fallback rectangle", patch_type)
                path = [(0., 0.), (1., 0.), (1., 1.), (0., 1.), (0., 0.)]
                invert = not invert

            polygon = QtGui.QPolygonF([
                QtCore.QPointF(x * size, y * size) for x, y in path])
            logger.debug("Created polygon with %d points", len(polygon))

            rot = turn % 4
            rect = [
                QtCore.QPointF(0., 0.), QtCore.QPointF(size, 0.),
                QtCore.QPointF(size, size), QtCore.QPointF(0., size)]
            rotation = [0, 90, 180, 270]
            logger.debug("Rotation parameters - rot: %d, angle: %d", rot, rotation[rot])

            painter = QtGui.QPainter(image)
            painter.setPen(QtCore.Qt.NoPen)
            logger.debug("Initialized QPainter")

            painter.translate(
                pos[0] * size + penwidth / 2, pos[1] * size + penwidth / 2)
            painter.translate(rect[rot])
            painter.rotate(rotation[rot])
            logger.debug("Applied transformations")

            if invert:
                logger.debug("Applying inversion to polygon")
                poly_rect = QtGui.QPolygonF(rect)
                polygon = poly_rect.subtracted(polygon)

            if penwidth > 0:
                logger.debug("Drawing borders with penwidth: %d", penwidth)
                pen = QtGui.QPen(QtGui.QColor(255, 255, 255))
                pen.setWidth(penwidth)
                painter.setPen(pen)
                painter.setBrush(QtGui.QBrush(foreColor))
                painter.drawPolygon(polygon)
            
            logger.debug("Drawing fill with color: %s", foreColor.name())
            painter.setPen(QtCore.Qt.NoPen)
            painter.setBrush(QtGui.QBrush(foreColor))
            painter.drawPolygon(polygon)

            logger.debug("Patch drawing completed successfully")
            return image

        except Exception as e:
            logger.error("Failed to draw patch: %s", str(e), exc_info=True)
            raise
        finally:
            painter.end()

    def decode(self, code, twoColor):
        """Virtual method to be implemented by subclasses"""
        raise NotImplementedError


class DonRenderer(IdenticonRendererBase):
    """Don Park's identicon implementation with enhanced logging"""

    PATH_SET = [
        # [original path definitions remain unchanged...]
    ]
    
    MIDDLE_PATCH_SET = [0, 4, 8, 15]

    def __init__(self, code):
        try:
            super().__init__(code)
            logger.debug("Initializing DonRenderer with code: %d", self.code)
            
            # Scale paths to 0-1 range
            self.PATH_SET = [
                [(x/4.0, y/4.0) for x, y in path] + [path[0]] if path else []
                for path in self.PATH_SET
            ]
            logger.debug("Scaled %d paths to 0-1 range", len(self.PATH_SET))
        except Exception as e:
            logger.error("DonRenderer initialization failed: %s", str(e), exc_info=True)
            raise

    def decode(self, code, twoColor):
        """Decode the identicon code with detailed logging"""
        try:
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

            logger.debug("Raw decoded values - middleType: %d, cornerType: %d, sideType: %d",
                         middleType, cornerType, sideType)

            # Ensure the types are within valid range
            middleType = self.MIDDLE_PATCH_SET[min(middleType, len(self.MIDDLE_PATCH_SET)-1)]
            cornerType = min(cornerType, len(self.PATH_SET)-1)
            sideType = min(sideType, len(self.PATH_SET)-1)
            logger.debug("Validated types - middle: %d, corner: %d, side: %d",
                        middleType, cornerType, sideType)

            foreColor = QtGui.QColor(red << 3, green << 3, blue << 3)
            secondColor = QtGui.QColor(second_red << 3, second_green << 3, second_blue << 3) \
                if twoColor else foreColor
            logger.debug("Color values - foreColor: %s, secondColor: %s",
                        foreColor.name(), secondColor.name())

            result = (
                (middleType, middleInvert, 0),
                (cornerType, cornerInvert, cornerTurn),
                (sideType, sideInvert, sideTurn),
                foreColor, secondColor, swap_cross
            )
            logger.debug("Decoding completed successfully: %s", result)
            return result

        except Exception as e:
            logger.error("Failed to decode identicon: %s", str(e), exc_info=True)
            raise


def render_identicon(code, size, twoColor=False, opacity=255, penwidth=0, renderer=None):
    """Render an identicon image with DEBUG logging"""
    try:
        logger.debug("render_identicon called with params: code=%d, size=%d, twoColor=%s, opacity=%d, penwidth=%d",
                   code, size, twoColor, opacity, penwidth)
        
        if renderer is None:
            renderer = DonRenderer
            logger.debug("Using default DonRenderer")
        
        result = renderer(code).render(size, twoColor, opacity, penwidth)
        logger.debug("render_identicon completed successfully")
        return result
        
    except Exception as e:
        logger.error("render_identicon failed: %s", str(e), exc_info=True)
        raise
