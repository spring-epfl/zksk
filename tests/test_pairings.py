# TODO: Fix the disastrous variable naming.
# TODO: Split into more granular unit tests.

import pytest

from bplib.bp import BpGroup
from petlib import pack

from zksk.pairings import BilinearGroupPair, G1Point, AdditivePoint


@pytest.fixture
def bp_group():
    return BpGroup()


@pytest.fixture
def group_pair():
    return BilinearGroupPair()


def test_gt_order(bp_group, group_pair):
    """
    Given a group GT defining a pairing e(G1,G2)->GT, GTGRoup behaves similarly.
    """
    GT = group_pair.GT
    assert GT == group_pair.groups()[2]
    assert bp_group.order() == GT.order()


def test_g1_point(bp_group, group_pair):
    """
    G1Point class which overrides G1 and G2 points in such a way
    that pt.group actually returns the G1/G2 groups and not the GT. Also, these
    points allow internal pair.
    """
    g = bp_group.pair(bp_group.gen1(), bp_group.gen2())
    gmg = group_pair.GT.generator()
    assert g == gmg.pt
    assert bp_group.pair(bp_group.gen1(), bp_group.gen2()) == gmg.pt
    assert g == group_pair.G1.generator().pair(group_pair.G2.generator()).pt


def test_additive_point(bp_group, group_pair):
    """
    AdditivePoint class defines GT points additively
    """
    g = bp_group.pair(bp_group.gen1(), bp_group.gen2())
    gmg = group_pair.GT.generator()
    assert g == gmg.pt
    assert gmg == AdditivePoint(g, group_pair)
    assert AdditivePoint(g**(g.group.order()), group_pair) == group_pair.GT.infinite()

    r = bp_group.order().random()
    g1, g1mg = g**r, r*gmg
    assert g1 == g1mg.pt
    assert g1*g1*g1 == (g1mg+g1mg+g1mg).pt
    assert g1.export() == g1mg.export()
    assert g1.group == g1mg.bp.bpgp


def test_g1_g2_groups(bp_group, group_pair):
    G1, G2, GT = group_pair.groups()
    g1, g2 = G1.generator(), G2.generator()
    assert G1.infinite().pt == bp_group.gen1().inf(bp_group)
    assert G1.infinite() == G1Point(bp_group.gen1().inf(bp_group), group_pair)
    assert g1*0 ==G1.infinite()
    assert g1*0 == g1*bp_group.order()
    assert G2.infinite().pt == bp_group.gen2().inf(bp_group)
    assert g2*0 == G2.infinite()
    assert g2*0 == g2*bp_group.order()


def test_pack_unpack_g1(group_pair):
    """
    Testing packing and unpacking G1 element
    """
    group_pair = BilinearGroupPair()
    g1 = group_pair.G1
    order = g1.order()
    pt1 = order.random() * g1.generator()

    data = pack.encode(pt1)
    pt2 = pack.decode(data)

    assert pt1 == pt2


def test_pack_unpack_g2(group_pair):
    """
    Testing packing and unpacking G2 element
    """
    group_pair = BilinearGroupPair()
    g2 = group_pair.G2
    order = g2.order()
    pt1 = order.random() * g2.generator()

    data = pack.encode(pt1)
    pt2 = pack.decode(data)

    assert pt1 == pt2


def test_pack_unpack_gt(group_pair):
    """
    Testing packing and unpacking GT element
    """
    group_pair = BilinearGroupPair()
    gt = group_pair.GT
    order = gt.order()
    pt1 = order.random() * gt.generator()

    data = pack.encode(pt1)
    pt2 = pack.decode(data)

    assert pt1 == pt2
