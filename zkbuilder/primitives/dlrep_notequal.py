"""
See https://www.cypherpunks.ca/~iang/pubs/blacronym-wpes.pdf
"""

import os
import sys

from zkbuilder.base import *
from zkbuilder.composition import *
from zkbuilder.primitives.dlrep import *


class DLRepNotEqualProof(BaseProof):
    def __init__(self, valid_tuple, invalid_tuple, secret_vars, binding=False):
        """
        Instantiates a Proof of inequal logarithms: takes (H0,h0), (H1,h1), [x=Secret(value=...)] such that H0 = x*h0 and H1 != x*h1.
        All these arguments should be iterable. The binding keyword argument allows to make the proof bind the x to an other proof.
        If not set to True, it is not possible to assert the same x was used in an other proof (even in an And conjunction)!
        """
        self.ProverClass, self.VerifierClass = (
            DLRepNotEqualProver,
            DLRepNotEqualVerifier,
        )
        self.precommitment_size = 1
        if len(valid_tuple) != 2 or len(invalid_tuple) != 2:
            raise Exception("Wrong parameters for DLRepNotEqualProof")
        # Declare two inner secrets whicch will depend on x
        self.aliases = [Secret("alpha"), Secret("beta")]
        self.lhs = [valid_tuple[0], invalid_tuple[0]]
        self.generators = [valid_tuple[1], invalid_tuple[1]]
        self.binding = binding
        self.constructed_proof = None
        self.secret_vars = secret_vars
        self.simulation = False

    def build_constructed_proof(self, precommitment):
        """
        Builds the internal AndProof associated to a DLRepNotEqualProof. See formula in Protocol 1 of the BLAC paper.
        """
        new_lhs = [self.generators[0].group.infinite()] + precommitment
        self.precommitment = precommitment
        p = []
        for i in range(len(new_lhs)):
            p.append(
                DLRep(
                    new_lhs[i],
                    wsum_secrets(self.aliases, [self.generators[i], self.lhs[i]]),
                )
            )
        if self.binding:
            # If the binding parameter is set, we add a DLRep member repeating the first member without randomizing the secret.
            p.append(DLRep(self.lhs[0], self.secret_vars[0] * self.generators[0]))
        self.constructed_proof = AndProof(*p)
        return self.constructed_proof

    def check_adequate_lhs(self):
        """
        Verifies the second part of the constructed proof is indeed about to prove the secret is not the discrete logarithm.
        """
        for el in self.precommitment:
            if el == self.generators[0].group.infinite():
                return False
        return True


class DLRepNotEqualProver(BaseProver):
    def precommit(self):
        """
        Generates the precommitments needed to build the inner constructed proof, in this case the left-hand side of the second term.
        """
        cur_secret = self.secret_values[self.proof.secret_vars[0]]
        self.blinder = self.proof.generators[0].group.order().random()
        # Choose a value for the two internal secrets
        new_secrets = (
            cur_secret * self.blinder % self.proof.generators[0].group.order(),
            -self.blinder % self.proof.generators[0].group.order(),
        )
        self.precommitment = [
            self.blinder * (cur_secret * self.proof.generators[1] - self.proof.lhs[1])
        ]
        self.process_precommitment(new_secrets)
        return self.precommitment


class DLRepNotEqualVerifier(BaseVerifier):
    """ A wrapper for an AndVerifier such that the proof can be initialized without the full information.
    """

    pass
