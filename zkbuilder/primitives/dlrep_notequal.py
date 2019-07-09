"""
ZK proof of inequality of two discrete logarithms.

See Protocol 1 in "`Thinking Inside the BLAC Box: Smarter Protocols for Faster Anonymous
Blacklisting`_" by Henry and Goldberg, 2013:

.. _`Thinking Inside the BLAC Box: Smarter Protocols for Faster Anonymous
    Blacklisting`: https://www.cypherpunks.ca/~iang/pubs/blacronym-wpes.pdf
"""

from zkbuilder.base import *
from zkbuilder.expr import Secret, wsum_secrets
from zkbuilder.composition import *
from zkbuilder.primitives.dlrep import *


class DLRepNotEqualProof(ExtendedProof):
    """
    ZK-proof statement of inequality of two discrete logarithms.

    Using the notation from the BLAC paper:

    .. math:: PK{ x: H_0 = x * h_0 \land H_1 \neq x * h_1 }

    Instantiates a Proof of inequal logarithms: takes (H0, h0), (H1, h1), [x=Secret(value=...)] such
    that H0 = x*h0 and H1 != x*h1.  All these arguments should be iterable. The binding keyword
    argument allows to make the proof bind the x to an other proof.  If not set to True, it is not
    possible to assert the same x was used in an other proof (even in an And conjunction)!
    """

    def __init__(self, valid_tuple, invalid_tuple, secret_vars, binding=False):
        if len(valid_tuple) != 2 or len(invalid_tuple) != 2:
            raise Exception("The valid_tuple and invalid_tuple must be 2-tuples")

        # The internal ZK proof uses two constructed secrets
        self.alpha, self.beta = Secret(), Secret()

        self.lhs = [valid_tuple[0], invalid_tuple[0]]
        self.generators = [valid_tuple[1], invalid_tuple[1]]

        self.binding = binding
        self.constructed_proof = None
        self.secret_vars = secret_vars
        self.simulation = False

    def precommit(self):
        """
        Generates the precommitments needed to build the inner constructed proof, in this case the left-hand side of the second term.
        """
        order = self.generators[0].group.order()
        cur_secret = self.secret_values[self.secret_vars[0]]
        blinder = order.random()

        # Set the value of the two internal secrets
        self.alpha.value = cur_secret * blinder % order
        self.beta.value = -blinder % order

        precommitment = {}
        precommitment["com"] = blinder * (cur_secret * self.generators[1] - self.lhs[1])

        return precommitment

    def construct_proof(self, precommitment):
        """
        Builds the internal AndProof associated to a DLRepNotEqualProof. See formula in Protocol 1 of the BLAC paper.
        """
        infty = self.generators[0].group.infinite()
        p1 = DLRep(infty, self.alpha * self.generators[0] + self.beta * self.lhs[0])
        p2 = DLRep(precommitment["com"], self.alpha * self.generators[1] + self.beta * self.lhs[1])
        proofs = [p1, p2]

        if self.binding:
            # If the binding parameter is set, we add a DLRep member repeating
            # the first member without randomizing the secret.
            proofs.append(DLRep(self.lhs[0], self.secret_vars[0] * self.generators[0]))

        self.constructed_proof = AndProof(*proofs)
        return self.constructed_proof

    def is_valid(self):
        """
        Verifies the second part of the constructed proof is indeed about to prove the secret is not the discrete logarithm.
        """
        return self.precommitment["com"] != self.generators[0].group.infinite()

    def simulate_precommit(self):
        """
        Draws a base at random (not unity) from the generators' group.
        """
        group = self.generators[0].group
        precommitment = {}
        precommitment["com"] = group.order().random() * group.generator()
        return precommitment
