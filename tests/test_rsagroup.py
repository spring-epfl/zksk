import pytest

from petlib.bn import Bn

from zksk import Secret
from zksk.primitives.dlrep import DLRep, DLRepProver
from zksk.utils.debug import SigmaProtocol
from zksk.utils.groups import get_quad_res


def test_rsagroup_interactive_1():
    p = Bn.get_prime(256, safe=1)
    q = Bn.get_prime(256, safe=1)
    n = p * q

    g = get_quad_res(n)
    h = ((p - 1) * (q - 1)).random() * g
    sk1, sk2 = n.random(), n.random()
    pk = sk1 * g + sk2 * h

    x1 = Secret()
    x2 = Secret()
    p = DLRep(pk, x1 * g + x2 * h)
    prover = p.get_prover({x1: sk1, x2: sk2})
    verifier = p.get_verifier()
    protocol = SigmaProtocol(verifier, prover)
    assert protocol.verify()
