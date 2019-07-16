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
from zksk.utils import make_generators, get_random_num, ensure_bn
from zksk.composition import AndProofStmt


def decompose_into_n_bits(value, n):
    """Array of bits, least significant bit first"""
    base = [1 if value.is_bit_set(b) else 0 for b in range(value.num_bits())]
    extra_bits = n - len(base)
    if extra_bits < 0:
        raise Exception("Not enough bits to represent value")
    return base + [0] * extra_bits


def next_exp_of_power_of_two(value):
    """Return smallest l such that value < 2**l"""
    return 1 if value == 0 else value.bit_length()


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

        # TODO: Should we combine com with the inner proof?
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
        actual_value = ensure_bn(self.x.value)
        value_as_bits = decompose_into_n_bits(actual_value, self.num_bits)

        # Set true value to computed secrets
        for rand in self.randomizers:
            rand.value = self.order.random()

        precommitment = {}
        precommitment["Cs"] = [
            b * self.g + r.value * self.h
            for b, r in zip(value_as_bits, self.randomizers)
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
            actual_value = ensure_bn(self.x.value)
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


class RangeStmt(ExtendedProofStmt):
    r"""
    Range proof statement.

    .. math::

        PK \{ (r, x): x G + r H \land l \leq x < u \}

    See "`Efficient Protocols for Set Membership and Range Proofs`_" by Camenisch
    et al., 2008.

    .. _`Efficient Protocols for Set Membership and Range Proofs`:
        https://infoscience.epfl.ch/record/128718/files/CCS08.pdf

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
        self.com = com
        self.g = g
        self.h = h
        self.lower_limit = lower_limit
        self.upper_limit = upper_limit
        # TODO: Shout if x does not have a value set. We need a value for the
        # range proofs.
        self.x = x
        self.randomizer = randomizer

        self.num_bits = next_exp_of_power_of_two(upper_limit)

    def construct_stmt(self, _):
        r"""
        Construct a conjunction of two range-power-of-two proofs:

        .. math ::

            PK\{ (r, x, x_1, x_2): C = x G + r H \land \
                   C_1 = x_1 G + r H \land \\
                   C_2 = x_2 G + r H \land \\
                   0 \leq x_1 + 2^n < 2^n \land \
                   0 \leq x_2 < 2^n,

        where :math:`n` is the smallest such that :math:`u < 2^n`,
        :math:`x_1 = x - u + 2^n`, and :math:`x_2 = x - l`.

        """
        if self.x is not None:
            x1 = Secret(
                    value=self.x.value - self.upper_limit + 2 ** self.num_bits)
            x2 = Secret(
                    value=self.x.value - self.lower_limit)
        else:
            x1 = None
            x2 = None

        com1 = self.com + (self.upper_limit - 2 ** self.num_bits) * self.g
        com2 = self.com + self.lower_limit * self.g
        p1 = PowerTwoRangeStmt(
            com=com1,
            g=self.g,
            h=self.h,
            num_bits=self.num_bits,
            x=x1,
            randomizer=self.randomizer,
        )
        p2 = PowerTwoRangeStmt(
            com=com2,
            g=self.g,
            h=self.h,
            num_bits=self.num_bits,
            x=x2,
            randomizer=self.randomizer,
        )

        p1._precommit(), p2._precommit()
        return p1 & p2


def createRangeStmt(com, x, r, a, b, g, h):
    a = ensure_bn(a)
    b = ensure_bn(b)
    nr_bits = (b - a - 1).num_bits()
    offset = 2**nr_bits - (b - a)

    com_shifted1 = com - a * g
    com_shifted2 = com_shifted1 - offset * g
    x1 = Secret(x.value - a)
    x2 = Secret(x.value - a - offset)

    com_stat = DLRep(com, x * g + r * h)

    p1 = PowerTwoRangeStmt(
        com=com_shifted1,
        g=g,
        h=h,
        num_bits=nr_bits,
        x=x1,
        randomizer=r,
    )

    p2 = PowerTwoRangeStmt(
        com=com_shifted2,
        g=g,
        h=h,
        num_bits=nr_bits,
        x=x2,
        randomizer=r,
    )

    return com_stat & p1 & p2
