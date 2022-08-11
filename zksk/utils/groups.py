import math
import secrets
import hashlib
import warnings

from petlib.bn import Bn

from zksk.consts import DEFAULT_GROUP
from zksk.exceptions import InvalidExpression


def get_random_point(group=None, random_bits=256, seed=None):
    """
    Generate some random group generators.

    Args:
        num: Number of generators to generate.
        group: Group
        random_bits: Number of bits of a random string to create a point.

    >>> from petlib.ec import EcPt
    >>> a = get_random_point()
    >>> b = get_random_point()
    >>> isinstance(a, EcPt)
    True
    >>> isinstance(b, EcPt)
    True
    >>> a != b
    True
    >>> get_random_point(seed=1)
    EcPt(037697679766c26bb7b76c65d2639fb983dea7c859c63b3047168dbc1b)
    """

    if group is None:
        group = DEFAULT_GROUP

    num_bytes = math.ceil(random_bits / 8)
    if seed is None:
        randomness = secrets.token_bytes(num_bytes)
    else:
        randomness = hashlib.sha512(b"%i" % seed).digest()[:num_bytes]

    return group.hash_to_point(randomness)


def make_generators(num, group=None, random_bits=256, seed=42):
    """
    Create some random group generators.

    .. WARNING ::

        There is a negligible chance that some generators will be the same.

    Args:
        num: Number of generators to generate.
        group: Group
        random_bits: Number of bits of a random number used to create a generator.

    >>> from petlib.ec import EcPt
    >>> generators = make_generators(3)
    >>> len(generators) == 3
    True
    >>> isinstance(generators[0], EcPt)
    True
    """
    if group is None:
        group = DEFAULT_GROUP
    generators = [
        get_random_point(
            group, random_bits, seed=seed + i if seed is not None else None
        )
        for i in range(num)
    ]
    return generators


def get_random_num(bits):
    """
    Draw a random number of given bitlength.

    >>> x = get_random_num(6)
    >>> x < 2**6
    True
    """
    order = Bn(2).pow(bits)
    return order.random()


def sum_bn_array(arr, modulus):
    """
    Sum an array of big numbers under a modulus.

    >>> a = [Bn(5), Bn(7)]
    >>> m = 10
    >>> sum_bn_array(a, m)
    2
    """
    if not isinstance(modulus, Bn):
        modulus = Bn(modulus)
    res = Bn(0)
    for elem in arr:
        if not isinstance(elem, Bn):
            elem = Bn(elem)
        res = res.mod_add(elem, modulus)
    return res


def ensure_bn(x):
    """
    Ensure that value is big number.

    >>> isinstance(ensure_bn(42), Bn)
    True
    >>> isinstance(ensure_bn(Bn(42)), Bn)
    True
    """
    if isinstance(x, Bn):
        return x
    else:
        return Bn(x)
