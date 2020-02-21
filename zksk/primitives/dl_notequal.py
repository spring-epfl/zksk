r"""
ZK proof of inequality of two discrete logarithms.

.. math::

    PK\{ (x): H_0 = x h_0 \land H_1 \neq x h_1 \}

See Protocol 1 in "`Thinking Inside the BLAC Box: Smarter Protocols for Faster Anonymous
Blacklisting`_" by Henry and Goldberg, 2013:

.. _`Thinking Inside the BLAC Box: Smarter Protocols for Faster Anonymous
    Blacklisting`: https://www.cypherpunks.ca/~iang/pubs/blacronym-wpes.pdf
"""

from zksk.expr import Secret, wsum_secrets
from zksk.exceptions import ValidationError
from zksk.extended import ExtendedProofStmt, ExtendedVerifier
from zksk.composition import AndProofStmt
from zksk.primitives.dlrep import DLRep


class DLNotEqual(ExtendedProofStmt):
    r"""
    ZK proof statement of inequality of two discrete logarithms.

    .. math::

        PK\{ (x): H_0 = x h_0 \land H_1 \neq x h_1 \}

    The statement is constructed from two pairs: :math:`(H_0, h_0)`, :math:`(H_1, h_1)`, and a
    :py:class:`expr.Secret` object representing a secret :math:`x`.

    The proof can be made `binding`: bind the :math:`x` to another proof. If the proof is not
    binding, it is not possible to assert that the same :math:`x` was used in any other proof (even
    in, say, an AND conjunction).

    Args:
        valid_pair (tuple): Pair of two Elliptic curve points :math:`(H_0, h_0)` such that
            :math:`H_0 = x h_0`
        invalid_pair (tuple): Pair of two Elliptic curve points :math:`(H_1, h_1)` such that
            :math:`H_1 \neq x h_1`
        x (:py:class:`expr.Secret`): Secret.
        bind (bool): Whether the proof is binding.
        simulated (bool): If this proof is a part of an or-proof: whether it should be simulated.
    """

    def __init__(self, valid_pair, invalid_pair, x, bind=False, simulated=False):
        if len(valid_pair) != 2 or len(invalid_pair) != 2:
            raise TypeException("The valid_pair and invalid_pair must be pairs")

        self.x = x

        # The internal ZK proof uses two constructed secrets
        self.alpha, self.beta = Secret(), Secret()

        self.lhs = [valid_pair[0], invalid_pair[0]]
        self.g = valid_pair[1]
        self.h = invalid_pair[1]

        self.bind = bind
        self.set_simulated(simulated)

    def precommit(self):
        """Build the left-hand side of the internal proof statement."""
        order = self.g.group.order()
        blinder = order.random()

        # Set the value of the two internal secrets
        self.alpha.value = self.x.value * blinder % order
        self.beta.value = -blinder % order

        precommitment = blinder * (self.x.value * self.h - self.lhs[1])
        return precommitment

    def construct_stmt(self, precommitment):
        """
        Build the internal proof statement.

        See the formula in Protocol 1 of the `Thinking Inside the BLAC Box: Smarter Protocols for
        Faster Anonymous Blacklisting` paper.
        """
        infty = self.g.group.infinite()
        p1 = DLRep(infty, self.alpha * self.g + self.beta * self.lhs[0])
        p2 = DLRep(precommitment, self.alpha * self.h + self.beta * self.lhs[1])
        statements = [p1, p2]

        if self.bind:
            # If the binding parameter is set, we add a DLRep member repeating
            # the first member without randomizing the secret.
            statements.append(DLRep(self.lhs[0], self.x * self.g))

        return AndProofStmt(*statements)

    def validate(self, precommitment):
        """
        Verify the the proof statement is indeed proving the inequality of discret logs.
        """
        if precommitment == self.g.group.infinite():
            raise ValidationError("The commitment should not be the unity element")

    def simulate_precommit(self):
        """
        Draw a base at random (not unity) from the bases' group.
        """
        group = self.g.group
        precommitment = group.order().random() * group.generator()
        return precommitment
