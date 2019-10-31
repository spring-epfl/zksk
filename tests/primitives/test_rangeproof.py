"""
Unit tests for rangeproofs.

TODO: Add tests for failure conditions of PowerTwoRangeStmt

"""
import pytest

from petlib.bn import Bn
from petlib.ec import EcGroup

from zksk import Secret
from zksk.pairings import BilinearGroupPair
from zksk.primitives.rangeproof import PowerTwoRangeStmt, RangeStmt, RangeOnlyStmt
from zksk.utils import make_generators
from zksk.utils.debug import SigmaProtocol


def test_power_two_range_stmt_non_interactive():
    group_pair = BilinearGroupPair()
    group = group_pair.G1

    value = Secret(value=Bn(10))
    randomizer = Secret(value=group.order().random())

    g, h = make_generators(2, group)
    limit = 20

    com = value * g + randomizer * h

    p1 = PowerTwoRangeStmt(com.eval(), g, h, limit, value, randomizer)
    p2 = PowerTwoRangeStmt(com.eval(), g, h, limit, Secret(), Secret())

    tr = p1.prove()
    assert p2.verify(tr)


def test_power_two_range_stmt_interactive():
    group_pair = BilinearGroupPair()
    group = group_pair.G1

    value = Secret(value=Bn(10))
    randomizer = Secret(value=group.order().random())

    g, h = make_generators(2, group)
    limit = 20

    com = value * g + randomizer * h

    p1 = PowerTwoRangeStmt(com.eval(), g, h, limit, value, randomizer)
    p2 = PowerTwoRangeStmt(com.eval(), g, h, limit, Secret(), Secret())

    (p1 & p2).get_prover()

    prover = p1.get_prover()
    verifier = p2.get_verifier()
    protocol = SigmaProtocol(verifier, prover)
    assert protocol.verify()
    verifier.stmt.full_validate()


def test_range_stmt_non_interactive_start_at_zero(group):
    x = Secret(value=3)
    randomizer = Secret(value=group.order().random())

    g, h = make_generators(2, group)
    lo = 0
    hi = 5

    com = x * g + randomizer * h
    stmt = RangeStmt(com.eval(), g, h, lo, hi, x, randomizer)

    tr = stmt.prove()
    assert stmt.verify(tr)


def test_range_stmt_non_interactive_start_at_nonzero(group):
    x = Secret(value=14)
    randomizer = Secret(value=group.order().random())

    g, h = make_generators(2, group)
    lo = 7
    hi = 15

    com = x * g + randomizer * h
    stmt = RangeStmt(com.eval(), g, h, lo, hi, x, randomizer)

    tr = stmt.prove()
    assert stmt.verify(tr)


def test_range_stmt_non_interactive_outside_range(group):
    x = Secret(value=15)
    randomizer = Secret(value=group.order().random())

    g, h = make_generators(2, group)
    lo = 7
    hi = 15

    com = x * g + randomizer * h
    stmt = RangeStmt(com.eval(), g, h, lo, hi, x, randomizer)

    with pytest.raises(Exception):
        tr = stmt.prove()


def test_range_proof_outside():
    group = EcGroup()
    x = Secret(value=15)
    randomizer = Secret(value=group.order().random())

    g, h = make_generators(2, group)
    lo = 0
    hi = 14

    com = x * g + randomizer * h
    stmt = RangeStmt(com.eval(), g, h, lo, hi, x, randomizer)
    with pytest.raises(Exception):
        nizk = stmt.prove()
        stmt.verify(nizk)


def test_range_proof_outside_range_above():
    x = Secret(value=7)
    lo = 0
    hi = 6
    stmt = RangeOnlyStmt(lo, hi, x)
    with pytest.raises(Exception):
        nizk = stmt.prove()
        assert stmt.verify(nizk) == False


def test_range_proof_outside_range_below():
    x = Secret(value=1)
    lo = 2
    hi = 7
    stmt = RangeOnlyStmt(lo, hi, x)
    with pytest.raises(Exception):
        nizk = stmt.prove()
        stmt.verify(nizk)
