"""
Simplified version of the real DLNotEqual defined in ``primitives``.

This version is here to support the tutorial.
"""

from zksk.expr import Secret, wsum_secrets
from zksk.exceptions import ValidationError
from zksk.extended import ExtendedProofStmt
from zksk.primitives.dlrep import DLRep
from zksk.utils import make_generators


class DLNotEqual(ExtendedProofStmt):
    def __init__(self, valid_tuple, invalid_tuple, x):
        self.lhs = [valid_tuple[0], invalid_tuple[0]]
        self.generators = [valid_tuple[1], invalid_tuple[1]]
        self.x = x

        # The internal ZK proof uses two constructed secrets
        self.alpha, self.beta = Secret(), Secret()

    def precommit(self):
        order = self.generators[0].group.order()
        blinder = order.random()

        # Set the value of the two internal secrets
        self.alpha.value = self.x.value * blinder % order
        self.beta.value = -blinder % order

        precommitment = blinder * (self.x.value * self.generators[1] - self.lhs[1])
        return precommitment

    def construct_stmt(self, precommitment):
        infty = self.generators[0].group.infinite()
        p1 = DLRep(infty, self.alpha * self.generators[0] + self.beta * self.lhs[0])
        p2 = DLRep(precommitment, self.alpha * self.generators[1] + self.beta * self.lhs[1])
        return p1 & p2

    def validate(self, precommitment):
        if precommitment == self.generators[0].group.infinite():
            raise ValidationError("Invalid precommitment")

    def simulate_precommit(self):
        group = self.generators[0].group
        precommitment = group.order().random() * group.generator()
        return precommitment


g, h = make_generators(2)
x = Secret(value=42)
a = 42 * g
b = 41 * h
stmt = DLNotEqual((a, g), (b, h), x)
nizk = stmt.prove()
stmt.verify(nizk)
