r"""
"Range proof": ZK proof that a committed value lies within a range.

.. math::

    PK \{ (r, x): \underbrace{C = x G + r H}_{Commitment} \land \underbrace{l \leq x < u}_{Range} \}

This module implements a Shoemaker's range proof, a conjuction of or-proofs for each bit of the
value.

"""

from petlib.bn import Bn

from zksk import Secret
from zksk.primitives.dlrep import DLRep
from zksk.extended import ExtendedProofStmt
from zksk.composition import AndProofStmt


def decompose_into_n_bits(value, n):
    """Array of bits, least significant bit first"""
    base = [1 if value.is_bit_set(b) else 0 for b in range(value.num_bits())]
    extra_bits = n - len(base)
    if extra_bits < 0:
        raise Exception("Not enough bits to represent value")
    return base + [0] * extra_bits


class PowerTwoRangeStmt(ExtendedProofStmt):
    r"""
    A power-two range proof statement.

    .. math::

        PK \{ (r, x): C = x G + r H \land 0 \leq x < 2^n \}

    Args:
        com: Value of the Pedersen commitment, :math:`C = x G + r H`
        g: First commitment base point :math:`G`
        h: Second commitment base point :math:`H`
        lower_limit: Lower limit :math:`l`
        upper_limit: Upper limit :math:`u`
        num_bits: The number of bits of the committed value :math:`n`
        x: Value for which we construct a range proof (prover only)
        randomizer: Randomizer of the commitment :math:`r` (prover only)
    """

    def __init__(self, com, g, h, num_bits, x=None, randomizer=None):
        if not x.value is None and not randomizer.value is None:
            self.x = x
            self.randomizer = randomizer
            self.is_prover = True
        else:
            self.is_prover = False

        self.com = com
        self.g = g
        self.h = h
        self.order = g.group.order()
        self.num_bits = num_bits

        # The constructed proofs need extra randomizers as secrets
        self.randomizers = [Secret() for _ in range(self.num_bits)]

    def precommit(self):
        """
        Commit to the bit-decomposition of the value.
        """
        actual_value = self.x.value
        value_as_bits = decompose_into_n_bits(actual_value, self.num_bits)

        # Set true value to computed secrets
        for rand in self.randomizers:
            rand.value = self.order.random()

        precommitment = {}
        precommitment["Cs"] = [
            b * self.g + r.value * self.h for b, r in zip(value_as_bits, self.randomizers)
        ]

        # Compute revealed randomizer
        rand = Bn(0)
        power = Bn(1)
        for r in self.randomizers:
            rand = rand.mod_add(r.value * power, self.order)
            power *= 2
        rand = rand.mod_sub(self.randomizer.value, self.order)
        precommitment["rand"] = rand

        return precommitment

    def construct_stmt(self, precommitment):
        """
        Construct the internal proof statement.
        """
        if self.is_prover:
            # Indicators that tell us which or-clause is true
            actual_value = self.x.value
            value_as_bits = decompose_into_n_bits(actual_value, self.num_bits)
            zero_simulated = [b == 1 for b in value_as_bits]
            one_simulated = [b == 0 for b in value_as_bits]

        bit_proofs = []
        for i in range(self.num_bits):
            p0 = DLRep(precommitment["Cs"][i], self.randomizers[i] * self.h)
            p1 = DLRep(precommitment["Cs"][i] - self.g, self.randomizers[i] * self.h)

            # When we are a prover, mark which disjunct is true
            if self.is_prover:
                p0.set_simulated(zero_simulated[i])
                p1.set_simulated(one_simulated[i])

            bit_proofs.append(p0 | p1)

        return AndProofStmt(*bit_proofs)

    def validate(self, precommitment):
        """
        Check the commitment to the bit-decomposition is correct.
        """
        rand = precommitment["rand"]

        # Combine bit commitments into value commitment
        combined = self.g.group.infinite()
        power = Bn(1)
        for c in precommitment["Cs"]:
            combined += power * c
            power *= 2

        return combined == self.com + rand * self.h


class RangeStmt(PowerTwoRangeStmt):
    r"""
    Range proof statement.

    .. math::

        PK \{ (r, x): x g + r h \land l \leq x < u \}

    Args:
        com: Value of the Pedersen commitment, :math:`C = x G + r H`
        g: First commitment base point :math:`G`
        h: Second commitment base point :math:`H`
        lower_limit: Lower limit :math:`l`
        upper_limit: Upper limit :math:`u`
        x: Value for which we construct a range proof
        randomizer: Randomizer of the commitment :math:`r`
    """

    def __init__(self, com, g, h, lower_limit, upper_limit, x=None, randomizer=None):
        lower_limit, upper_limit = to_Bn(lower_limit), to_Bn(upper_limit)
        num_bits = (self.upper_limit - self.lower_limit - 1).num_bits()
        super().__init__(self, co, g, h, num_bits=num_bits, x=x, randomizer=randomizer)
