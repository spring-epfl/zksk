"""
.. _`Blackronym`:
    https://www.cypherpunks.ca/~iang/pubs/blacronym-wpes.pdf

"""
import os, sys

from zkbuilder.primitives.dlrep import *
from zkbuilder.base import *
from zkbuilder.composition import *
from zkbuilder.pairings import *


def decompose_into_n_bits(value, n):
    """Array of bits, least significant bit first"""
    base = [1 if value.is_bit_set(b) else 0 for b in range(value.num_bits())]
    extra_bits = n - len(base)
    if extra_bits < 0:
        raise Exception("Not enough bits to represent value")
    return base + [0] * extra_bits


def to_Bn(num):
    if isinstance(num, Bn):
        return num
    else:
        return Bn(num)


class RangeProof(ExtendedProof):
    r"""
    A range proof statement.

    .. math::

        PK \{ value: ``lower_limit \leq value < upper\_limit`` \}

    Args:
        com: Pedersen commitment ``com = value * g + randomizer * h``
        g: First Pedersen-commitment base point
        h: Second Pedersen-commitment base point
        lower_limit: Lower limit
        upper_limit: Upper limit
        value: Value for which we construct a range proof
        randomizer: Randomizer of the commitment
    """

    def __init__(self, com, g, h, lower_limit, upper_limit, value, randomizer):
        self.lower_limit, self.upper_limit = to_Bn(lower_limit), to_Bn(upper_limit)
        self.num_bits = (self.upper_limit - self.lower_limit - 1).num_bits()


class PowerTwoRangeProof(ExtendedProof):
    r"""
    A power-two range proof statement.

    .. math::

        PK \{ value: ``lower_limit \leq value < num\_bits`` \}

    Args:
        com: Pedersen commitment, ``com = value * g + randomizer * h``
        g: First Pedersen commitment base point
        h: Second Pedersen commitment base point
        num_bits: The number of bits of the committed value
        value: Value for which we construct a range proof (prover only)
        randomizer: Randomizer of the commitment (prover only)
    """
    def __init__(self, com, g, h, num_bits, value=None, randomizer=None):
        if not value.value is None and not randomizer.value is None:
            # Not sure why we need these here? To do the order checks?
            # TODO: do we need to set secret_vars explicitly? Yes,
            # But is there a better way to do this? Maybe force overriding?
            self.secret_vars = [value, randomizer]
            self.is_prover = True
        else:
            self.is_prover = False

        # TODO: not clear how and why to set these
        self.generators = [g, h]

        self.com = com
        self.g, self.h = g, h
        self.num_bits = num_bits

        # The constructed proofs need extra randomizers as secrets
        self.randomizers = [Secret() for _ in range(self.num_bits)]

        # Move to super initializer with default argument
        self.constructed_proof = None
        self.simulation = False

    def precommit(self):
        """
        Must return: precommitment
        """
        g, h = self.g, self.h
        order = self.g.group.order()

        value = self.secret_vars[0].value
        value_as_bits = decompose_into_n_bits(value, self.num_bits)

        # Set true value to computed secrets
        for rand in self.randomizers:
            rand.value = order.random()

        precommitment = [ b * g + r.value * h for b, r in zip(value_as_bits, self.randomizers)]

        # Compute revealed randomizer
        rand = Bn(0)
        power = Bn(1)
        for r in self.randomizers:
            rand = rand.mod_add(r.value * power, order)
            power *= 2
        rand = rand.mod_sub(self.secret_vars[1].value, order)
        precommitment.append(rand)

        return precommitment

    def construct_proof(self, precommitment):
        # TODO: Why is this essential? and not automatic?
        self.precommitment = precommitment

        if self.is_prover:
            # Indicators that tell us which or-clause is true
            value = self.secret_vars[0].value
            value_as_bits = decompose_into_n_bits(value, self.num_bits)
            zero_simulated = [b == 1 for b in value_as_bits]
            one_simulated = [b == 0 for b in value_as_bits]

        bit_proofs = []
        for i in range(self.num_bits):
            p0 = DLRep(precommitment[i], self.randomizers[i] * self.h)
            p1 = DLRep(precommitment[i] - self.g, self.randomizers[i] * self.h)

            # When we are a prover, mark which disjunct is true
            if self.is_prover:
                p0.simulation = zero_simulated[i]
                p1.simulation = one_simulated[i]

            bit_proofs.append(p0 | p1)

        self.constructed_proof = AndProof(*bit_proofs)

        return self.constructed_proof

    # TODO: name of check is too specific, e.g., for range proofs we need another post check
    def is_valid(self):
        """TODO (internal)

        """
        rand = self.precommitment[self.num_bits]

        # Combine bit commitments into value commitment
        combined = self.g.group.infinite()
        power = Bn(1)
        for c in self.precommitment[:self.num_bits]:
            combined += power * c
            power *= 2

        return combined == self.com + rand * self.h

