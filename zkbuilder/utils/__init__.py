import os

from collections import defaultdict

from petlib.ec import EcGroup

from zkbuilder.exceptions import InvalidExpression


def check_groups(list_of_secret_vars, list_of_generators):
    """
    Check that if two secrets in the proof are the same, the generators at corresponding indices
    induce groups of same order.  Can be deactivated in the future since it can forbid using
    different groups in one proof.

    The primary goal is to ensure same responses for same secrets will not yield false negatives of
    check_responses_consistency due to different group order modular reductions.

    TODO: Update docs, variable names.

    Args:
        list_of_secret_vars: a list of secrets names of type Secret.
        list_of_generators: a list of generators (bases).
    """
    # We map the unique secrets to the indices where they appear
    mydict = defaultdict(list)
    for idx, word in enumerate(list_of_secret_vars):
        mydict[word].append(idx)

    # Now we use this dictionary to check all the generators related to a particular secret live in
    # the same group
    for (word, gen_idx) in mydict.items():
        # Word is the key, gen_idx is the value = a list of indices
        ref_order = list_of_generators[gen_idx[0]].group.order()

        for index in gen_idx:
            if list_of_generators[index].group.order() != ref_order:
                raise InvalidExpression(
                    "A shared secret has generators which yield different group orders: ", word,
                )

    return True


DEFAULT_GROUP = EcGroup(713)


def get_random_point(group=None, random_bits=256):
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
    """
    if group is None:
        group = DEFAULT_GROUP
    return group.hash_to_point(os.urandom(random_bits))


def get_generators(num, group=None, random_bits=256):
    """
    Generate some random group generators.

    .. WARNING ::

        The generators are not guaranteed to be different.

    Args:
        num: Number of generators to generate.
        group: Group
        random_bits: Number of bits of a random number used to create a generator.

    >>> from petlib.ec import EcPt
    >>> generators = get_generators(3)
    >>> len(generators) == 3
    True
    >>> isinstance(generators[0], EcPt)
    True
    """
    if group is None:
        group = DEFAULT_GROUP
    generators = [get_random_point(group, random_bits) for _ in range(num)]
    return generators

