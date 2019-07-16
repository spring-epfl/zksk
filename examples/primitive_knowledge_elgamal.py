"""
Example proof primitive for proving knowledge of an additive ElGamal
plaintext. Constructing this proof is simple because it can be directly
expressed in terms of existing building blocks, in this case, DLReps.

WARNING: if you update this file, update the line numbers in the documentation.
"""

from petlib.ec import EcGroup
from petlib.bn import Bn

from zksk.extended import ExtendedProofStmt
from zksk import Secret, DLRep

import attr


@attr.s
class PublicKey:
    """
    Very basic ElGamal public key
    """

    g = attr.ib()
    h = attr.ib()


class AdditiveElgamalPlaintextProof(ExtendedProofStmt):
    r"""
    Proof of plaintext knowledge of an additive ElGamal ciphertext

    Given an additive ElGamal ciphertext

    .. math:: c = (c_1, c_2) = (rG, rH + mG)

    against a public key :math:`H` this proof proves knowledge of the
    message :math:`m` and the randomizer :math:`r` used to create the
    ciphertext `c`. In particular, it computes the following proof:

    .. math:: PK\{ (x, r) : c_1 = rG \land c_2 = rH + m G \}

    """

    def __init__(self, ctxt, pk, msg, randomizer):
        self.ctxt = ctxt
        self.pk = pk
        self.msg = msg
        self.randomizer = randomizer

    def construct_stmt(self, precommitment):
        part1 = DLRep(self.ctxt[0], self.randomizer * self.pk.g)
        part2 = DLRep(self.ctxt[1], self.randomizer * self.pk.h + self.msg * self.pk.g)
        return part1 & part2


group = EcGroup()
g = group.generator()
x = group.order().random()
h = x * g
pk = PublicKey(g,h)

# Create ElGamal ciphertext
m = Secret(Bn(42))
r = Secret(group.order().random())
c = (r.value * g, r.value * h + m.value * g)

stmt = AdditiveElgamalPlaintextProof(c, pk, m, r)
proof = stmt.prove()

stmt_prime = AdditiveElgamalPlaintextProof(c, pk, Secret(), Secret())
assert stmt_prime.verify(proof)
