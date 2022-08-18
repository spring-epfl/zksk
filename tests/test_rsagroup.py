import pytest

from petlib.bn import Bn

from zksk import Secret
from zksk.primitives.dlrep import DLRep
from zksk.utils.debug import SigmaProtocol
from zksk.rsa_group import RSAGroup, IntPt, rsa_dlrep_trusted_setup


def test_rsagroup_interactive_1():
    [g, h] = rsa_dlrep_trusted_setup(bits=1024, num=2)
    n = g.group.modulus
    sk1, sk2 = n.random(), n.random()
    pk = sk1 * g + sk2 * h

    x1 = Secret()
    x2 = Secret()
    p = DLRep(pk, x1 * g + x2 * h)
    prover = p.get_prover({x1: sk1, x2: sk2})
    verifier = p.get_verifier()
    protocol = SigmaProtocol(verifier, prover)
    assert protocol.verify()


def test_rsagroup_and_interactive_1():
    [g, h] = rsa_dlrep_trusted_setup(bits=1024, num=2)
    n = g.group.modulus
    sk1, sk2 = n.random(), n.random()
    pk1 = sk1 * g
    pk2 = sk2 * h

    x1 = Secret()
    x2 = Secret()
    p = DLRep(pk1, x1 * g) & DLRep(pk2, x2 * h)
    prover = p.get_prover({x1: sk1, x2: sk2})
    verifier = p.get_verifier()
    protocol = SigmaProtocol(verifier, prover)
    assert protocol.verify()


def test_rsagroup_or_interactive_1():
    [g, h] = rsa_dlrep_trusted_setup(bits=1024, num=2)
    n = g.group.modulus
    sk1, sk2 = n.random(), n.random()
    pk1 = sk1 * g
    pk2 = IntPt(Bn(1), RSAGroup(n))

    x1 = Secret()
    x2 = Secret()
    p = DLRep(pk1, x1 * g) | DLRep(pk2, x2 * h)
    p.subproofs[1].set_simulated()
    prover = p.get_prover({x1: sk1, x2: sk2})
    verifier = p.get_verifier()
    protocol = SigmaProtocol(verifier, prover)
    assert protocol.verify()
