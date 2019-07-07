"""
see https://www.cypherpunks.ca/~iang/pubs/blacronym-wpes.pdf
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

class RangeProof(BaseProof):
    def __init__(self, com, g, h, lower_limit, upper_limit, value, randomizer):
        """Constructs a range proof statement

        Constructs a range proof statement that

             ``lower_limit <= value < upper_limit``

        Args:
            com: A Pedersen commitment, ``com = value * g + randomizer * h``
            g: First Pedersen commitment base point
            h: Second Pedersen commitment base point
            lower_limit: Lower limit
            upper_limit: Upper limit
            value: The value for which we construct a range proof
            randomizer: The randomizer of com
        """
        self.lower_limit, self.upper_limit = to_Bn(lower_limit), to_Bn(upper_limit)
        self.nr_bits = (self.upper_limit - self.lower_limit - 1).num_bits()

        pass


class PowerTwoRangeProof(BaseProof):
    def __init__(self, com, g, h, nr_bits, value=None, randomizer=None):
        """Constructs a range proof statement

        Constructs a range proof statement that

             ``0 <= value < 2**nr_bits``

        Args:
            com: A Pedersen commitment, ``com = value * g + randomizer * h``
            g: First Pedersen commitment base point
            h: Second Pedersen commitment base point
            nr_bits: The number of bits of the committed value
            value: The value for which we construct a range proof (prover only)
            randomizer: The randomizer of com (prover only)
        """
        self.ProverClass = PowerTwoRangeProver
        self.VerifierClass = PowerTwoRangeVerifier

        if not value is None and not randomizer is None:
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
        self.nr_bits = nr_bits

        # TODO: I think I'd rather avoid this altogether
        self.aliases = [Secret() for _ in range(self.nr_bits)]

        # TODO: why do we need to set this manually?
        self.precommitment_size = self.nr_bits + 1

        # Move to super initializer with default argument
        self.constructed_proof = None
        self.simulation = False

    def build_constructed_proof(self, precommitment):
        # TODO: Why is this essential? and not automatic?
        self.precommitment = precommitment

        rand_secrets = self.aliases

        if self.is_prover:
            # Indicators that tell us which or-clause is true
            value = self.secret_vars[0].value
            value_as_bits = decompose_into_n_bits(value, self.nr_bits)
            zero_simulated = [b == 1 for b in value_as_bits]
            one_simulated = [b == 0 for b in value_as_bits]

        bit_proofs = []
        for i in range(self.nr_bits):
            p0 = DLRep(precommitment[i], rand_secrets[i] * self.h)
            p1 = DLRep(precommitment[i] - self.g, rand_secrets[i] * self.h)

            if self.is_prover:
                p0.simulation = zero_simulated[i]
                p1.simulation = one_simulated[i]

            bit_proofs.append(p0 | p1)

        self.constructed_proof = AndProof(*bit_proofs)

        return self.constructed_proof

    # TODO: name of check is too specific, e.g., for range proofs we need another post check
    def check_adequate_lhs(self):
        """TODO (internal)

        """
        rand = self.precommitment[self.nr_bits]

        # Combine bit commitments into value commitment
        combined = self.g.group.infinite()
        power = Bn(1)
        for c in self.precommitment[:self.nr_bits]:
            combined += power * c
            power *= 2

        return combined == self.com + rand * self.h

class PowerTwoRangeProver(BaseProver):
    def internal_precommit(self):
        """
        Must return: precommitment, and any new secrets
        """
        g, h = self.proof.g, self.proof.h
        order = self.proof.g.group.order()

        value = self.proof.secret_vars[0].value
        value_as_bits = decompose_into_n_bits(value, self.proof.nr_bits)
        bit_randomizers = [order.random() for _ in range(self.proof.nr_bits)]
        precommitment = [ b * g + r * h for b, r in zip(value_as_bits, bit_randomizers)]

        # Compute revealed randomizer
        rand = Bn(0)
        power = Bn(1)
        for r in bit_randomizers:
            rand = rand.mod_add(r * power, order)
            power *= 2
        rand = rand.mod_sub(self.proof.secret_vars[1].value, order)
        precommitment.append(rand)

        return precommitment, bit_randomizers


class PowerTwoRangeVerifier(BaseVerifier):
    """ A wrapper for an AndVerifier such that the proof can be initialized without the full information.
    """
    pass

def main():
    print("Running main!")
    mG = BilinearGroupPair()
    G = mG.G1

    value = Secret(value=Bn(10))
    randomizer = Secret(value=G.order().random())

    g = G.generator()
    h = 10 * G.generator() # FIXME

    com = value * g + randomizer * h

    proof = PowerTwoRangeProof(com.eval(), g, h, 20, value, randomizer)
    proof_prime = PowerTwoRangeProof(com.eval(), g, h, 20)

    pp = proof.prove()
    assert(proof_prime.verify(pp))

if __name__ == "__main__":
    main()
