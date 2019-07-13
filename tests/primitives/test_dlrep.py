import string
import random

import pytest

from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt

from zksk import Secret
from zksk.expr import wsum_secrets
from zksk.exceptions import StatementMismatch, InvalidExpression
from zksk.primitives.dlrep import DLRep, DLRepProver
from zksk.utils.debug import SigmaProtocol
from zksk.utils import make_generators, get_random_point


def test_dlrep_interactive_1(group):
    sk, g = group.order().random(), group.generator()
    pk = sk * g

    x = Secret()
    p = DLRep(pk, x * g)
    prover = p.get_prover({x: sk})
    verifier = p.get_verifier()
    protocol = SigmaProtocol(verifier, prover)
    assert protocol.verify()


def test_dlrep_interactive_2(group):
    g, h = make_generators(2, group)
    x, y = Secret(), Secret()

    p = DLRep(10 * g + 15 * h, x * g + y * h)
    prover = p.get_prover({x: 10, y: 15})
    verifier = p.get_verifier()
    protocol = SigmaProtocol(verifier, prover)
    assert protocol.verify()


def test_dlrep_interactive_3(group):
    """Emulate actual workflow with independent provers and verifiers."""
    sk, g = group.order().random(), group.generator()
    pk = sk * g

    x = Secret()
    p1 = DLRep(pk, x * g)
    prover = p1.get_prover({x: sk})

    x = Secret()
    p2 = DLRep(pk, x * g)
    verifier = p2.get_verifier()

    protocol = SigmaProtocol(verifier, prover)
    assert protocol.verify()


def test_dlrep_non_interactive_1(group):
    g, h = make_generators(2, group)
    expr = Secret(value=3) * g + Secret(value=4) * h
    p = DLRep(expr.eval(), expr)
    tr = p.prove()
    prover = p.get_prover()
    assert p.verify(tr)


def test_dlrep_non_interactive_2(group):
    g, = make_generators(1, group)
    x = Secret()
    p = DLRep(4 * g, x * g)
    tr = p.prove({x: 4})
    assert p.verify(tr)


def test_dlrep_non_interactive_with_message(group):
    g, h = make_generators(2, group)

    expr = Secret(value=3) * g + Secret(value=4) * h
    p = DLRep(expr.eval(), expr)
    tr = p.prove(message="mymessage")

    assert DLRep(expr.eval(), expr).verify(tr, message="mymessage")


def test_dlrep_bad_hash(group):
    g, h = make_generators(2, group=group)
    x, y = Secret(), Secret()
    secret_dict = {x: 2, y: 3}
    p1 = DLRep(2 * g + 3 * h, x * g + y * h)
    p2 = DLRep(2 * g + 3 * h, y * h + x * g)
    tr = p1.prove(secret_dict)
    assert p1.verify(tr)

    with pytest.raises(StatementMismatch):
        p2.verify(tr)


def test_dlrep_wrong_secrets(group):
    g = group.generator()
    g1 = 2 * g
    g2 = 5 * g
    x1 = Secret()
    x2 = Secret()
    p = DLRep(g, x1 * g1 + x2 * g2)
    prover = p.get_prover({x1: 10, x2: 15})
    verifier = p.get_verifier()

    protocol = SigmaProtocol(verifier, prover)
    assert not protocol.verify()


def test_dlrep_wrong_public_elements(group):
    g, h = make_generators(2, group=group)
    x, y = Secret(value=3), Secret(value=4)
    expr = x * g + y * h

    public_wrong = get_random_point()
    p = DLRep(public_wrong, expr)

    prover = p.get_prover()
    verifier = p.get_verifier()
    protocol = SigmaProtocol(verifier, prover)
    assert not protocol.verify()


def test_dlrep_wrong_response_non_interactive(group):
    g, h = make_generators(2, group=group)
    x, y = Secret(value=3), Secret(value=4)
    expr = x * g + y * h

    p = DLRep(expr.eval(), expr)
    tr = p.prove(message="mymessage")

    # Turn one of the responses random
    tr.responses[1] = group.order().random()

    assert not p.verify(tr, message="mymessage")


def test_dlrep_simulation(group):
    g, h = make_generators(2, group=group)
    x, y = Secret(value=3), Secret(value=4)
    expr = x * g + y * h
    p = DLRep(expr.eval(), expr)

    tr = p.simulate()
    assert (not p.verify(tr)) and p.verify_simulation_consistency(tr)


def test_diff_groups_dlrep(group):
    g, h = make_generators(2, group)
    x, y = Secret(), Secret()

    # Precondition for the test.
    other_group = EcGroup(706)
    assert other_group != group, "Test assumption is broken."
    h = other_group.generator()

    expr = x * g + y * h
    z = get_random_point(group)
    with pytest.raises(InvalidExpression):
        p = DLRep(z, expr)


@pytest.mark.parametrize("num", [2, 10])
def test_generators_sharing_a_secret(group, num):
    generators = make_generators(num, group)
    unique_secret = 4

    x = Secret()
    secret_vals = [Bn(unique_secret) for _ in range(num)]
    lhs = group.wsum(secret_vals, generators)
    rhs = wsum_secrets([x] * num, generators)

    p = DLRep(lhs, rhs)
    prover = p.get_prover({x: unique_secret})
    assert isinstance(prover, DLRepProver)

    _, commitment = prover.commit()
    assert isinstance(commitment, EcPt)


@pytest.mark.parametrize("num", [2, 10])
def test_get_many_different_provers(group, num):
    generators = make_generators(num, group)

    secrets  = [Secret(name="secret_%i" % i) for i in range(num)]
    secrets_vals = [Bn(i) for i in range(num)]
    secret_dict = {secret: val for secret, val in zip(secrets, secrets_vals)}

    p = DLRep(
        group.wsum(secrets_vals, generators),
        wsum_secrets(secrets, generators)
    )
    prover = p.get_prover(secret_dict)
    _, commitment = prover.commit()
    assert isinstance(commitment, EcPt)


def test_same_random_values_in_commitments(group):
    g, = make_generators(1, group)
    generators = [g, g, g]

    pub = group.wsum([Bn(100), Bn(100), Bn(100)], generators)
    x = Secret()
    p = DLRep(pub, wsum_secrets([x, x, x], generators))
    prover = p.get_prover({x: 100})
    commitments = prover.commit()

