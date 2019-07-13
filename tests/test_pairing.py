from zksk.pairings import *
import petlib.pack as pack

# Testing packing and unpacking g1 element
def test_pack_unpack_g1():
    bgp = BilinearGroupPair()
    g1 = bgp.G1
    order = g1.order()
    pt1 = order.random() * g1.generator()

    data = pack.encode(pt1)
    pt2 = pack.decode(data)

    assert pt1 == pt2


# Testing packing and unpacking g2 element
def test_pack_unpack_g2():
    bgp = BilinearGroupPair()
    g2 = bgp.G2
    order = g2.order()
    pt1 = order.random() * g2.generator()

    data = pack.encode(pt1)
    pt2 = pack.decode(data)

    assert pt1 == pt2


# Testing packing and unpacking g2 element
def test_pack_unpack_gt():
    bgp = BilinearGroupPair()
    gt = bgp.GT
    order = gt.order()
    pt1 = order.random() * gt.generator()

    data = pack.encode(pt1)
    pt2 = pack.decode(data)

    assert pt1 == pt2
