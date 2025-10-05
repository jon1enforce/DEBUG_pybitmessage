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

    # Define the complete PATH_SET here as class variable
    PATH_SET = [
        # 0: full square
        [(0, 0), (4, 0), (4, 4), (0, 4)],
        # 1: left-top triangle
        [(0, 0), (4, 0), (0, 4)],
        # 2: right-top triangle  
        [(0, 0), (4, 0), (4, 4)],
        # 3: left-bottom triangle
        [(0, 0), (0, 4), (4, 4)],
        # 4: right-bottom triangle
        [(4, 0), (4, 4), (0, 4)],
        # 5: top rectangle
        [(0, 0), (4, 0), (4, 2), (0, 2)],
        # 6: right rectangle
        [(2, 0), (4, 0), (4, 4), (2, 4)],
        # 7: bottom rectangle
        [(0, 2), (4, 2), (4, 4), (0, 4)],
        # 8: left rectangle
        [(0, 0), (2, 0), (2, 4), (0, 4)],
        # 9: center square
        [(1, 1), (3, 1), (3, 3), (1, 3)],
        # 10: diamond
        [(2, 0), (4, 2), (2, 4), (0, 2)],
        # 11: inverted diamond
        [(0, 0), (4, 0), (2, 2)],  # top triangle
        [(4, 0), (4, 4), (2, 2)],  # right triangle
        [(0, 4), (4, 4), (2, 2)],  # bottom triangle  
        [(0, 0), (0, 4), (2, 2)],  # left triangle
        # 15: empty (special case)
        []
    ]

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

            # Validate patch types before rendering
            middle, corner, side = self._validate_patch_types(middle, corner, side)

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
            positions = [(1, 0), (2, 1), (1, 2), (0, 1)]
            logger.debug("Drawing %d side patches", len(positions))
            for i, pos in enumerate(positions):
                logger.debug("Drawing side patch %d at %s", i+1, pos)
                kwds['patch_type'] = side[0]
                image = self.drawPatchQt(pos, side[2] + 1 + i, side[1], **kwds)

            # corner patches
            kwds['foreColor'] = secondColor
            positions = [(0, 0), (2, 0), (2, 2), (0, 2)]
            logger.debug("Drawing %d corner patches", len(positions))
            for i, pos in enumerate(positions):
                logger.debug("Drawing corner patch %d at %s", i+1, pos)
                kwds['patch_type'] = corner[0]
                image = self.drawPatchQt(pos, corner[2] + 1 + i, corner[1], **kwds)

            logger.debug("Identicon rendering completed successfully")
            return image

        except Exception as e:
            logger.error("Failed to render identicon: %s", str(e), exc_info=True)
            # Return a fallback image instead of crashing
            return self._create_fallback_image(size, opacity)

    def _validate_patch_types(self, middle, corner, side):
        """Validate that all patch types are within valid range"""
        try:
            middle_type, middle_invert, middle_turn = middle
            corner_type, corner_invert, corner_turn = corner
            side_type, side_invert, side_turn = side
            
            max_patch_type = len(self.PATH_SET) - 1
            
            # Clamp all types to valid range
            middle_type = max(0, min(middle_type, max_patch_type))
            corner_type = max(0, min(corner_type, max_patch_type))
            side_type = max(0, min(side_type, max_patch_type))
            
            logger.debug("Validated patch types - middle: %d, corner: %d, side: %d (max: %d)",
                        middle_type, corner_type, side_type, max_patch_type)
            
            return (
                (middle_type, middle_invert, middle_turn),
                (corner_type, corner_invert, corner_turn), 
                (side_type, side_invert, side_turn)
            )
            
        except Exception as e:
            logger.error("Error validating patch types: %s, using defaults", str(e))
            # Return safe default values
            safe_patch = (0, 0, 0)  # Use first patch type, no invert, no turn
            return safe_patch, safe_patch, safe_patch

    def _create_fallback_image(self, size, opacity):
        """Create a simple fallback image when rendering fails"""
        try:
            image = QtGui.QPixmap(QtCore.QSize(size * 3, size * 3))
            image.fill(QtGui.QColor(200, 200, 200, opacity))
            
            painter = QtGui.QPainter(image)
            painter.setPen(QtGui.QPen(QtGui.QColor(100, 100, 100), 2))
            painter.setBrush(QtGui.QBrush(QtGui.QColor(150, 150, 150, opacity)))
            painter.drawRect(0, 0, size * 3, size * 3)
            painter.drawText(image.rect(), QtCore.Qt.AlignCenter, "?")
            painter.end()
            
            logger.info("Created fallback identicon image")
            return image
        except Exception as e:
            logger.error("Failed to create fallback image: %s", str(e))
            # Ultimate fallback
            return QtGui.QPixmap(QtCore.QSize(size * 3, size * 3))

    def drawPatchQt(self, pos, turn, invert, patch_type, image, size, 
                   foreColor, backColor, penwidth):
        """Draw a single patch with DEBUG logging"""
        painter = None
        try:
            logger.debug("Drawing patch at %s - turn: %d, invert: %s, type: %d",
                       pos, turn, invert, patch_type)

            # Validate and clamp patch_type to valid range
            max_patch_type = len(self.PATH_SET) - 1
            if patch_type < 0 or patch_type > max_patch_type:
                logger.warning("Invalid patch_type: %d (valid range: 0-%d), clamping to %d",
                             patch_type, max_patch_type, max(0, min(patch_type, max_patch_type)))
                patch_type = max(0, min(patch_type, max_patch_type))

            # Get the path - handle empty paths specially
            path = self.PATH_SET[patch_type]
            if not path:  # Empty path (like type 15)
                logger.debug("Empty patch detected, inverting")
                invert = not invert
                path = [(0., 0.), (1., 0.), (1., 1.), (0., 1.), (0., 0.)]
            else:
                # Scale path to 0-1 coordinates
                path = [(x/4.0, y/4.0) for x, y in path]
                # Close the path if not already closed
                if path[0] != path[-1]:
                    path.append(path[0])

            polygon = QtGui.QPolygonF([
                QtCore.QPointF(x * size, y * size) for x, y in path])
            logger.debug("Created polygon with %d points for patch_type %d", len(polygon), patch_type)

            rot = turn % 4
            rect = [
                QtCore.QPointF(0., 0.), QtCore.QPointF(size, 0.),
                QtCore.QPointF(size, size), QtCore.QPointF(0., size)]
            rotation = [0, 90, 180, 270]
            logger.debug("Rotation parameters - rot: %d, angle: %d", rot, rotation[rot])

            painter = QtGui.QPainter(image)
            painter.setRenderHint(QtGui.QPainter.Antialiasing)
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
            logger.error("Failed to draw patch at %s: %s", pos, str(e))
            # Return the original image unchanged
            return image
        finally:
            if painter and painter.isActive():
                painter.end()

    def decode(self, code, twoColor):
        """Virtual method to be implemented by subclasses"""
        raise NotImplementedError


class DonRenderer(IdenticonRendererBase):
    """Don Park's identicon implementation with enhanced logging"""

    MIDDLE_PATCH_SET = [0, 4, 8, 15]

    def __init__(self, code):
        try:
            # Call parent constructor first
            super().__init__(code)
            logger.debug("Initializing DonRenderer with code: %d", self.code)
            logger.debug("Available patch types: 0-%d", len(self.PATH_SET) - 1)
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
            cornerType = max(0, min(cornerType, len(self.PATH_SET)-1))
            sideType = max(0, min(sideType, len(self.PATH_SET)-1))
            
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
            logger.debug("Decoding completed successfully")
            return result

        except Exception as e:
            logger.error("Failed to decode identicon: %s", str(e), exc_info=True)
            # Return safe default values
            safe_patch = (0, 0, 0)
            return safe_patch, safe_patch, safe_patch, QtGui.QColor(100, 100, 100), QtGui.QColor(150, 150, 150), False


def render_identicon(code, size, twoColor=False, opacity=255, penwidth=0, renderer=None):
    """Render an identicon image with DEBUG logging"""
    try:
        logger.debug("render_identicon called with params: code=%d, size=%d, twoColor=%s, opacity=%d, penwidth=%d",
                   code, size, twoColor, opacity, penwidth)
        
        if renderer is None:
            renderer = DonRenderer
            logger.debug("Using default DonRenderer")
        
        instance = renderer(code)
        logger.debug("Renderer PATH_SET size: %d", len(instance.PATH_SET))
        
        result = instance.render(size, twoColor, opacity, penwidth)
        logger.debug("render_identicon completed successfully")
        return result
        
    except Exception as e:
        logger.error("render_identicon failed: %s", str(e), exc_info=True)
        # Create a simple fallback image
        fallback = QtGui.QPixmap(QtCore.QSize(size * 3, size * 3))
        fallback.fill(QtGui.QColor(200, 200, 200, opacity))
        return fallback
