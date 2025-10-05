"""
Cryptographically secure random operations. 
NOW SUITABLE for security / cryptography operations.
Uses secrets module for cryptographically secure random number generation.
"""

import secrets
import logging

logger = logging.getLogger('default')

NoneType = type(None)


def seed():
    """Initialize random number generator - now cryptographically secure by default"""
    logger.debug("DEBUG: Cryptographically secure RNG initialized (no seed needed)")
    # secrets verwendet systemeigenen CSPRNG, benötigt kein manuelles Seeding
    logger.debug("DEBUG: Secure RNG ready")


def randomshuffle(population):
    """Method randomShuffle.

    shuffle the sequence x in place using cryptographically secure RNG.
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
    
    # Cryptographically secure shuffle
    for i in range(len(population) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        population[i], population[j] = population[j], population[i]
    
    shuffled_order = str(population[:5]) + "..." if len(population) > 5 else str(population)
    logger.debug("DEBUG: Shuffled order (first 5 elements): %s", shuffled_order)
    logger.debug("DEBUG: Exiting randomshuffle()")


def randomsample(population, k):
    """Method randomSample.

    return a k length list of unique elements
    chosen from the population sequence using cryptographically secure RNG.
    Used for random sampling without replacement.
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
    
    # Cryptographically secure sample
    result = []
    population_list = list(population)
    for _ in range(k):
        if not population_list:
            break
        idx = secrets.randbelow(len(population_list))
        result.append(population_list.pop(idx))
    
    logger.debug("DEBUG: Sampled %d elements: %s", len(result), str(result[:5]) + "..." if len(result) > 5 else str(result))
    logger.debug("DEBUG: Exiting randomsample()")
    return result


def randomrandrange(x, y=None):
    """Method randomRandrange.

    return a cryptographically secure randomly selected element from
    range(start, stop).
    """
    logger.debug("DEBUG: Entering randomrandrange()")
    logger.debug("DEBUG: Parameters - x: %s, y: %s", x, y)
    
    if isinstance(y, NoneType):
        logger.debug("DEBUG: Single parameter mode, generating range(0, %d)", x)
        result = secrets.randbelow(x)  # Cryptographically secure
    else:
        logger.debug("DEBUG: Two parameter mode, generating range(%d, %d)", x, y)
        result = secrets.randbelow(y - x) + x  # Cryptographically secure
    
    logger.debug("DEBUG: Generated secure random number: %d", result)
    logger.debug("DEBUG: Exiting randomrandrange()")
    return result


def randomchoice(population):
    """Method randomchoice.

    Return a cryptographically secure random element from the non-empty
    sequence seq. If seq is empty, raises IndexError.
    """
    logger.debug("DEBUG: Entering randomchoice()")
    logger.debug("DEBUG: Input population type: %s, length: %d", 
                type(population), len(population))
    
    if len(population) == 0:
        logger.debug("DEBUG: Empty population detected, will raise IndexError")
        raise IndexError("Cannot choose from an empty sequence")
    
    # Cryptographically secure choice
    result = population[secrets.randbelow(len(population))]
    logger.debug("DEBUG: Selected secure random element: %s", result)
    logger.debug("DEBUG: Exiting randomchoice()")
    return result


def randomrandom():
    """Cryptographically secure replacement for random.random()
    Returns a float in [0.0, 1.0) using secure RNG
    """
    logger.debug("DEBUG: Generating cryptographically secure random float")
    result = secrets.randbelow(2**53) / (2**53)  # High precision float
    logger.debug("DEBUG: Generated secure random float: %f", result)
    return result
def random():
    """Cryptographically secure replacement for random.random()"""
    return secrets.randbelow(2**53) / (2**53)

def randrange(start, stop=None, step=1):
    """Cryptographically secure replacement for random.randrange()"""
    if stop is None:
        return secrets.randbelow(start)
    return secrets.randbelow(stop - start) + start

def randint(a, b):
    """Cryptographically secure replacement for random.randint()"""
    return a + secrets.randbelow(b - a + 1)

def choice(seq):
    """Cryptographically secure replacement for random.choice()"""
    if not seq:
        raise IndexError("Cannot choose from an empty sequence")
    return seq[secrets.randbelow(len(seq))]

def sample(population, k):
    """Cryptographically secure replacement for random.sample()"""
    if k > len(population):
        raise ValueError("Sample larger than population")
    
    result = []
    population_list = list(population)
    for _ in range(k):
        idx = secrets.randbelow(len(population_list))
        result.append(population_list.pop(idx))
    return result

def shuffle(population):
    """Cryptographically secure replacement for random.shuffle()"""
    if not isinstance(population, (list, bytearray)):
        population = list(population)
    
    for i in range(len(population) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        population[i], population[j] = population[j], population[i]

def uniform(a, b):
    """Cryptographically secure replacement for random.uniform()"""
    return a + (b - a) * random()

# Kompatibilitäts-Funktionen (alte helper_random API)
def randomrandom():
    return random()

def randomrandrange(x, y=None):
    return randrange(x, y)

def randomchoice(population):
    return choice(population)

def randomsample(population, k):
    return sample(population, k)

def randomshuffle(population):
    return shuffle(population)    
