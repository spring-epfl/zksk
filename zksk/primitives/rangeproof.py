r"""
Range proof: ZK proof that a committed value lies within a range.

.. math::

    PK \{ (r, x): \underbrace{C = x G + r H}_{Commitment} \land \underbrace{l \leq x < u}_{Range} \}

This module implements a Schoenmakers' range proof, a conjuction of or-proofs for each bit of the
value.

"""

import warnings

from petlib.bn import Bn
from petlib.ec import EcGroup

from zksk import Secret
from zksk.primitives.dlrep import DLRep
from zksk.exceptions import ValidationError
from zksk.extended import ExtendedProofStmt
from zksk.utils import make_generators, get_random_num, ensure_bn
from zksk.composition import AndProofStmt


def decompose_into_n_bits(value, n):
    """Array of bits, least significant bit first"""
    if value < 0:
        raise Exception("Can't represent negative values")

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
        num_bits: The number of bits of the committed value :math:`n`
        x: Value for which we construct a range proof (prover only)
        randomizer: Randomizer of the commitment :math:`r` (prover only)
    """

    def __init__(self, com, g, h, num_bits, x=None, randomizer=None):
        if not x.value is None and not randomizer.value is None:
            self.x = x
            self.randomizer = randomizer
            self.is_prover = True

            # Ensure secret is in range
            self.x.value = ensure_bn(self.x.value)
            if self.x.value < 0:
                warnings.warn("Secret is negative")
            if self.x.value.num_bits() > num_bits:
                warnings.warn("Secret has more than {} bits".format(num_bits))
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

    def simulate_precommit(self):
        randomizers = [self.order.random() for _ in range(self.num_bits)]
        precommitment = {}
        precommitment["Cs"] = [r * self.h for r in randomizers]
        precommitment["Cs"][0] += self.com

        # Compute revealed randomizer
        rand = Bn(0)
        power = Bn(1)
        for r in randomizers:
            rand = rand.mod_add(r * power, self.order)
            power *= 2
        precommitment["rand"] = rand

        return precommitment

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

        if combined != self.com + rand * self.h:
            raise ValidationError("The commitments do not combine correctly")


class GenericRangeStmtMaker:
    r"""
    Auxiliary builder class for generic range proofs.

    .. math::

        PK \{ (r, x): x G + r H \land a \leq x < b \}

    See "`Efficient Protocols for Set Membership and Range Proofs`_" by Camenisch
    et al., 2008.

    In practice, use the :py:obj:`zksk.primitives.rangeproof.RangeStmt` object directly:

    >>> group = EcGroup()
    >>> x = Secret(value=3)
    >>> randomizer = Secret(value=group.order().random())
    >>> g = group.hash_to_point(b"1")
    >>> h = group.hash_to_point(b"2")
    >>> lo = 0
    >>> hi = 5
    >>> com = x * g + randomizer * h
    >>> stmt = RangeStmt(com.eval(), g, h, lo, hi, x, randomizer)
    >>> nizk = stmt.prove()
    >>> stmt.verify(nizk)
    True

    See :py:meth:`GenericRangeStmtMaker.__call__` for the construction signature.

    .. `Efficient Protocols for Set Membership and Range Proofs`:
        https://infoscience.epfl.ch/record/128718/files/CCS08.pdf

    """

    def __call__(self, com, g, h, a, b, x, r):
        """
        Get a conjunction of two range-power-of-two proofs.

        Args:
            com: Value of the Pedersen commitment, :math:`C = x G + r H`
            g: First commitment base point :math:`G`
            h: Second commitment base point :math:`H`
            a: Lower limit :math:`a`
            b: Upper limit :math:`b`
            x: Value for which we construct a range proof
            r: Randomizer of the commitment :math:`r`
        """
        a = ensure_bn(a)
        b = ensure_bn(b)
        num_bits = (b - a - 1).num_bits()
        offset = 2 ** num_bits - (b - a)

        com_shifted1 = com - a * g
        com_shifted2 = com_shifted1 + offset * g
        x1 = Secret()
        x2 = Secret()
        if x.value is not None:
            x1.value = x.value - a
            x2.value = x.value - a + offset

            # Ensure secret is in range
            if x.value < a or x.value >= b:
                warnings.warn("Secret outside of given range [{}, {})".format(a, b))

        com_stmt = DLRep(com, x * g + r * h)

        p1 = PowerTwoRangeStmt(
            com=com_shifted1, g=g, h=h, num_bits=num_bits, x=x1, randomizer=r,
        )

        p2 = PowerTwoRangeStmt(
            com=com_shifted2, g=g, h=h, num_bits=num_bits, x=x2, randomizer=r,
        )

        return com_stmt & p1 & p2


class GenericRangeOnlyStmtMaker:
    r"""
    Auxiliary builder class for generic range proofs.

    .. math::
        PK \{ (x): a \leq x < b \}

    See "`Efficient Protocols for Set Membership and Range Proofs`_" by Camenisch
    et al., 2008.

    .. _`Efficient Protocols for Set Membership and Range Proofs`:
        https://infoscience.epfl.ch/record/128718/files/CCS08.pdf

    In practice, use the :py:obj:`zksk.primitives.rangeproof.RangeStmt` object directly:

    >>> x = Secret(value=3)
    >>> lo = 0
    >>> hi = 5
    >>> stmt = RangeOnlyStmt(lo, hi, x)
    >>> nizk = stmt.prove()
    >>> stmt.verify(nizk)
    True

    See :py:meth:`GenericRangeStmtMaker.__call__` for the construction signature.
    """

    def __call__(self, a, b, x=None):
        """
        Get a conjunction of two range-power-of-two proofs.
        Args:
            a: Lower limit :math:`a`
            b: Upper limit :math:`b`
            x: Value for which we construct a range proof
        """
        group = EcGroup()
        g = group.hash_to_point(b"g")
        h = group.hash_to_point(b"h")

        r = Secret(value=group.order().random())
        com = (x * g + r * h).eval()

        a = ensure_bn(a)
        b = ensure_bn(b)
        num_bits = (b - a - 1).num_bits()
        offset = 2 ** num_bits - (b - a)
        com_shifted1 = com - a * g
        com_shifted2 = com_shifted1 + offset * g

        x1 = Secret()
        x2 = Secret()
        if x is not None:
            x1.value = x.value - a
            x2.value = x.value - a + offset

        com_stmt = DLRep(com, x * g + r * h)
        p1 = PowerTwoRangeStmt(
            com=com_shifted1, g=g, h=h, num_bits=num_bits, x=x1, randomizer=r,
        )
        p2 = PowerTwoRangeStmt(
            com=com_shifted2, g=g, h=h, num_bits=num_bits, x=x2, randomizer=r,
        )

        return com_stmt & p1 & p2


# TODO: Make a regular class.
RangeStmt = GenericRangeStmtMaker()
RangeOnlyStmt = GenericRangeOnlyStmtMaker()
