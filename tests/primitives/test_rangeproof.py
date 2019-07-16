"""
Unit tests for rangeproofs.

TODO: Add tests for failure conditions.

"""
import pytest

from petlib.bn import Bn

from zksk import Secret
from zksk.pairings import BilinearGroupPair
from zksk.primitives.rangeproof import PowerTwoRangeStmt, RangeStmt, createRangeStmt
from zksk.utils.debug import SigmaProtocol


def test_power_two_range_stmt_non_interactive():
    group_pair = BilinearGroupPair()
    group = group_pair.G1

    value = Secret(value=Bn(10))
    randomizer = Secret(value=group.order().random())

    g = group.generator()
    h = 10 * group.generator()  # FIXME
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

    g = group.generator()
    h = 10 * group.generator()  # FIXME
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


@pytest.mark.skip
def test_range_stmt_non_interactive(group):
    x = Secret(value=3)
    randomizer = Secret(value=group.order().random())

    g = group.generator()
    h = 10 * group.generator()  # FIXME
    lo = 0
    hi = 5

    com = x * g + randomizer * h

    stmt = RangeStmt(com.eval(), g, h, lower_limit=lo, upper_limit=hi,
            x=x, randomizer=randomizer)

    tr = stmt.prove({x: 3})
    assert stmt.verify(tr)

def test_range_stmt_non_interactive_start_at_zero(group):
    x = Secret(value=3)
    randomizer = Secret(value=group.order().random())

    g = group.generator()
    h = 10 * group.generator()  # FIXME
    lo = 0
    hi = 5

    com = x * g + randomizer * h
    stmt = createRangeStmt(com.eval(), x, randomizer, lo, hi, g, h)

    tr = stmt.prove()
    assert stmt.verify(tr)

def test_range_stmt_non_interactive_start_at_nonzero(group):
    x = Secret(value=14)
    randomizer = Secret(value=group.order().random())

    g = group.generator()
    h = 10 * group.generator()  # FIXME
    lo = 7
    hi = 15

    com = x * g + randomizer * h
    stmt = createRangeStmt(com.eval(), x, randomizer, lo, hi, g, h)

    tr = stmt.prove()
    assert stmt.verify(tr)

def test_range_stmt_non_interactive_outside_range(group):
    x = Secret(value=15)
    randomizer = Secret(value=group.order().random())

    g = group.generator()
    h = 10 * group.generator()  # FIXME
    lo = 7
    hi = 15

    com = x * g + randomizer * h
    stmt = createRangeStmt(com.eval(), x, randomizer, lo, hi, g, h)

    with pytest.raises(Exception):
        tr = stmt.prove()
