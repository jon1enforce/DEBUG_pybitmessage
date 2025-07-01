"""Convenience functions for random operations. Not suitable for security / cryptography operations."""

import random
import logging

logger = logging.getLogger('default')

NoneType = type(None)


def seed():
    """Initialize random number generator"""
    logger.debug("DEBUG: Initializing random number generator seed")
    random.seed()
    logger.debug("DEBUG: Random seed initialized")


def randomshuffle(population):
    """Method randomShuffle.

    shuffle the sequence x in place.
    shuffles the elements in list in place,
    so they are in a random order.
    As Shuffle will alter data in-place,
    so its input must be a mutable sequence.
    In contrast, sample produces a new list
    and its input can be much more varied
    (tuple, string, xrange, bytearray, set, etc)
    """
    logger.debug("DEBUG: Entering randomshuffle()")
    logger.debug("DEBUG: Input population type: %s, length: %d", 
                type(population), len(population))
    
    if not isinstance(population, (list, bytearray)):
        logger.debug("DEBUG: Input is not mutable sequence, original type: %s", 
                    type(population))
        population = list(population)
        logger.debug("DEBUG: Converted to list, new length: %d", len(population))
    
    original_order = str(population[:5]) + "..." if len(population) > 5 else str(population)
    logger.debug("DEBUG: Original order (first 5 elements): %s", original_order)
    
    random.shuffle(population)
    
    shuffled_order = str(population[:5]) + "..." if len(population) > 5 else str(population)
    logger.debug("DEBUG: Shuffled order (first 5 elements): %s", shuffled_order)
    logger.debug("DEBUG: Exiting randomshuffle()")


def randomsample(population, k):
    """Method randomSample.

    return a k length list of unique elements
    chosen from the population sequence.
    Used for random sampling
    without replacement, its called
    partial shuffle.
    """
    logger.debug("DEBUG: Entering randomsample()")
    logger.debug("DEBUG: Input population type: %s, length: %d", 
                type(population), len(population))
    logger.debug("DEBUG: Requested sample size k: %d", k)
    
    if k > len(population):
        logger.debug("DEBUG: Sample size k larger than population, adjusting to population size")
        k = len(population)
    
    if k < 0:
        logger.debug("DEBUG: Negative sample size requested, setting to 0")
        k = 0
    
    result = random.sample(population, k)
    logger.debug("DEBUG: Sampled %d elements: %s", len(result), str(result[:5]) + "..." if len(result) > 5 else str(result))
    logger.debug("DEBUG: Exiting randomsample()")
    return result


def randomrandrange(x, y=None):
    """Method randomRandrange.

    return a randomly selected element from
    range(start, stop). This is equivalent to
    choice(range(start, stop)),
    but doesnt actually build a range object.
    """
    logger.debug("DEBUG: Entering randomrandrange()")
    logger.debug("DEBUG: Parameters - x: %s, y: %s", x, y)
    
    if isinstance(y, NoneType):
        logger.debug("DEBUG: Single parameter mode, generating range(0, %d)", x)
        result = random.randrange(x)  # nosec
    else:
        logger.debug("DEBUG: Two parameter mode, generating range(%d, %d)", x, y)
        result = random.randrange(x, y)  # nosec
    
    logger.debug("DEBUG: Generated random number: %d", result)
    logger.debug("DEBUG: Exiting randomrandrange()")
    return result


def randomchoice(population):
    """Method randomchoice.

    Return a random element from the non-empty
    sequence seq. If seq is empty, raises
    IndexError.
    """
    logger.debug("DEBUG: Entering randomchoice()")
    logger.debug("DEBUG: Input population type: %s, length: %d", 
                type(population), len(population))
    
    if len(population) == 0:
        logger.debug("DEBUG: Empty population detected, will raise IndexError")
        raise IndexError("Cannot choose from an empty sequence")
    
    result = random.choice(population)  # nosec
    logger.debug("DEBUG: Selected random element: %s", result)
    logger.debug("DEBUG: Exiting randomchoice()")
    return result
