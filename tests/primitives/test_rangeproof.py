"""
Unit tests for rangeproofs.

TODO: Add tests for failure conditions.

"""

from petlib.bn import Bn

from zkbuilder import Secret
from zkbuilder.pairings import BilinearGroupPair
from zkbuilder.primitives.rangeproof import PowerTwoRangeProof
from zkbuilder.utils.debug import SigmaProtocol


def test_rangeproof():
    group_pair = BilinearGroupPair()
    group = group_pair.G1

    value = Secret(value=Bn(10))
    randomizer = Secret(value=group.order().random())

    g = group.generator()
    h = 10 * group.generator() # FIXME
    limit = 20

    com = value * g + randomizer * h

    p1 = PowerTwoRangeProof(com.eval(), g, h, limit, value, randomizer)
    p2 = PowerTwoRangeProof(com.eval(), g, h, limit, Secret(), Secret())

    tr = p1.prove()
    assert(p2.verify(tr))

    p1 = PowerTwoRangeProof(com.eval(), g, h, limit, value, randomizer)
    p2 = PowerTwoRangeProof(com.eval(), g, h, limit, Secret(), Secret())

    prover = p1.get_prover()
    verifier = p2.get_verifier()
    protocol = SigmaProtocol(verifier, prover)
    assert protocol.verify()
    assert verifier.proof.is_valid()
