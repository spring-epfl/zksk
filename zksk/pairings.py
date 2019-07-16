"""
Wrapper around ``bplib`` points that ensures additive notation for all points.
"""

import attr

from bplib.bp import BpGroup, G1Elem, G2Elem, GTElem

import petlib.pack as pack
import msgpack


class BilinearGroupPair:
    """
    A bilinear group pair.

    Contains two origin groups G1, G2 and the image group GT. The underlying
    ``bplib.bp.BpGroup`` object is also embedded.
    """

    def __init__(self, bp_group=None):
        if bp_group is None:
            self.bpgp = BpGroup()
        self.GT = GTGroup(self)
        self.G1 = G1Group(self)
        self.G2 = G2Group(self)

    def groups(self):
        """
        Returns the three groups in the following order :  G1, G2, GT.
        """
        return self.G1, self.G2, self.GT


class GTGroup:
    """
    Wrapper for the GT group with additive points.

    Allows to retrieve groups G1 and G2.

    The group ID is set to 0 to allow comparisons between groups of different
    types to raise an explicit Exception.

    Args:
        bp (:py:class:`BilinearGroupPair`): Group pair.
    """

    def __init__(self, bp):
        self.bp = bp
        self.gen = None
        self.inf = None

    def infinite(self):
        if self.inf is None:
            self.inf = AdditivePoint(self.generator().pt.one(self.bp.bpgp), self.bp)
        return self.inf

    def order(self):
        return self.bp.bpgp.order()

    def generator(self):
        if self.gen is None:
            self.gen = self.bp.G1.generator().pair(self.bp.G2.generator())
        return self.gen

    def sum(self, points):
        res = self.infinite()
        for p in points:
            res = res + p
        return res

    def wsum(self, weights, generators):
        res = self.infinite()
        for w, g in zip(weights, generators):
            res = res + w * g
        return res


# TODO: Why should this not just be called GTPoint?
class AdditivePoint:
    """
    A wrapper for GT points that uses additive notation.

    Args:
        pt (``bplib.bp.GTElem``): Wrapped point.
        bp (:py:class:`BilinearGroupPair`): Group pair.
    """

    def __init__(self, pt, bp):
        self.pt = pt
        self.bp = bp
        self.group = self.bp.GT

    def export(self, form=0):
        return self.pt.export(form) if form else self.pt.export()

    def __mul__(self, nb):
        """
        Overrides the multiplicative syntax by an additive one.

        Special case in 0 as the underlying ``bplib`` function is broken for
        this value.
        """
        if nb == 0:
            return AdditivePoint(self.pt / self.pt, self.bp)
        return AdditivePoint(self.pt ** nb, self.bp)

    def __eq__(self, other):
        return self.pt == other.pt

    def __add__(self, other):
        """
        Replace the multiplicative syntax between two points by an additive one.
        """
        return AdditivePoint(self.pt * (other.pt), self.bp)

    __rmul__ = __mul__

    def __repr__(self):
        return "GTPt(" + str(self.pt.__hash__()) + ")"


class G1Point:
    """
    Wrapper for G1 points so they can be paired with a G2 point.

    Args:
        pt (``bplib.bp.G1Point``): Point.
        bp (:py:class:`BilinearGroupPair`): Group pair.
    """

    def __init__(self, pt, bp):
        self.pt = pt
        self.bp = bp
        self.group = self.bp.G1

    def __eq__(self, other):
        return self.pt == other.pt

    def __add__(self, other):
        return G1Point(self.pt + other.pt, self.bp)

    def __sub__(self, other):
        return self + (-1 * other)

    def __mul__(self, nb):
        return G1Point(self.pt * nb, self.bp)

    def export(self, form=0):
        return self.pt.export(form) if form else self.pt.export()

    def __eq__(self, other):
        return self.pt == other.pt

    __rmul__ = __mul__

    def pair(self, other):
        return AdditivePoint(self.bp.bpgp.pair(self.pt, other.pt), self.bp)

    def __repr__(self):
        return "G1Pt(" + str(self.pt.__hash__()) + ")"


class G2Point:
    """
    Wrapper for G2 points.

    Args:
        pt (``bplib.bp.G2Point``): Point.
        bp (:py:class:`BilinearGroupPair`): Group pair.
    """

    def __init__(self, pt, bp):
        self.pt = pt
        self.bp = bp
        self.group = self.bp.G2

    def __eq__(self, other):
        return self.pt == other.pt

    def __add__(self, other):
        return G2Point(self.pt + other.pt, self.bp)

    def __sub__(self, other):
        return self + (-1 * other)

    def __mul__(self, nb):
        return G2Point(self.pt * nb, self.bp)

    def export(self, form=0):
        return self.pt.export(form) if form else self.pt.export()

    def __eq__(self, other):
        return self.pt == other.pt

    __rmul__ = __mul__

    def __repr__(self):
        return "G2Pt(" + str(self.pt.__hash__()) + ")"


class G1Group:
    """
    Wrapper for G1 that behaves like normal ``petlib.ec.EcGroup``.

    Args:
        bp (:py:class:`BilinearGroupPair`): Group pair.
    """

    def __init__(self, bp):
        self.bp = bp
        self.gen = None
        self.inf = None

    def generator(self):
        if self.gen is None:
            self.gen = G1Point(self.bp.bpgp.gen1(), self.bp)
        return self.gen

    def infinite(self):
        if self.inf is None:
            self.inf = G1Point(self.generator().pt.inf(self.bp.bpgp), self.bp)
        return self.inf

    def order(self):
        return self.bp.bpgp.order()

    def __eq__(self, other):
        return self.bp.bpgp == other.bp.bpgp and self.__class__ == other.__class__

    def hash_to_point(self, string):
        return G1Point(self.bp.bpgp.hashG1(string), self.bp)

    # TODO throw these on a base class
    def sum(self, points):
        res = self.infinite()
        for p in points:
            res = res + p
        return res

    # TODO throw these on a base class
    def wsum(self, weights, generators):
        res = self.infinite()
        for w, g in zip(weights, generators):
            res = res + w * g
        return res


class G2Group:
    """
    Wrapper for the G2 group.

    Args:
        bp (:py:class:`BilinearGroupPair`): Group pair.

    """

    def __init__(self, bp):
        self.bp = bp
        self.gen = None
        self.inf = None

    def generator(self):
        if self.gen is None:
            self.gen = G2Point(self.bp.bpgp.gen2(), self.bp)
        return self.gen

    def infinite(self):
        if self.inf is None:
            self.inf = G2Point(self.generator().pt.inf(self.bp.bpgp), self.bp)
        return self.inf

    def order(self):
        return self.bp.bpgp.order()

    # TODO throw these on a base class
    def sum(self, points):
        res = self.infinite()
        for p in points:
            res = res + p
        return res

    def wsum(self, weights, generators):
        res = self.infinite()
        for w, g in zip(weights, generators):
            res = res + w * g
        return res


def pt_enc(obj):
    """Encoder for the wrapped points."""
    nid = obj.bp.bpgp.nid
    data = obj.pt.export()
    packed_data = msgpack.packb((nid, data))
    return packed_data


def pt_dec(bptype, xtype):
    """Decoder for the wrapped points."""

    def dec(data):
        nid, data = msgpack.unpackb(data)
        bp = BilinearGroupPair()
        pt = bptype.from_bytes(data, bp.bpgp)
        return xtype(pt, bp)

    return dec


# Register encoders and decoders for pairing points
pack.register_coders(G1Point, 111, pt_enc, pt_dec(G1Elem, G1Point))
pack.register_coders(G2Point, 112, pt_enc, pt_dec(G2Elem, G2Point))
pack.register_coders(AdditivePoint, 113, pt_enc, pt_dec(GTElem, AdditivePoint))
