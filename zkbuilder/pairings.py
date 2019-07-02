from bplib.bp import BpGroup, G1Elem, G2Elem, GTElem


def test():
    """
    Some wrappers to use on top of Bplib groups so groups and points behave well with most of the methods used in petlib.ec

    Given a group GT defining a pairing e(G1,G2)->GT, we create a variant GTGRoup which behaves similarly, with more tools:
    >>> G = BpGroup()
    >>> m = BilinearGroupPair()
    >>> mG = m.GT
    >>> G.order() == mG.order()
    True

    >>> mG == m.groups()[2]
    True

    We define the G1Point class which overrides G1 and G2 points in such a way that pt.group actually returns the G1/G2 groups and not the GT
    Also, these points allow internal pair

    >>> g = G.pair(G.gen1(), G.gen2())
    >>> gmg  = mG.generator()
    >>> g == gmg.pt
    True
    >>> G.pair(G.gen1(), G.gen2()) == gmg.pt
    True
    >>> g == m.G1.generator().pair(m.G2.generator()).pt
    True

    We define the AdditivePoint class which defines GT points additively:
    >>> gmg == AdditivePoint(g, m)
    True
    >>> AdditivePoint(g**(g.group.order()), m) == mG.infinite()
    True

    I.e it overrides the multiplicative syntax of Bplib GT points by an additive one
    >>> r = G.order().random()
    >>> g1, g1mg = g**r, r*gmg
    >>> g1 == g1mg.pt
    True
    >>> g1*g1*g1 == (g1mg+g1mg+g1mg).pt
    True
    >>> g1.export() == g1mg.export()
    True
    >>> g1.group == g1mg.bp.bpgp
    True


    We also derive G1 and G2 groups from GT
    >>> G1, G2, gt = m.groups()
    >>> g1, g2 = G1.generator(), G2.generator()
    >>> G1.infinite().pt == G.gen1().inf(G)
    True
    >>> G1.infinite() == G1Point(G.gen1().inf(G), m)
    True
    >>> g1*0 ==G1.infinite()
    True
    >>> g1*0 == g1*G.order()
    True
    >>> G2.infinite().pt == G.gen2().inf(G)
    True
    >>> g2*0 == G2.infinite()
    True
    >>> g2*0 == g2*G.order()
    True
    """
    return


class BilinearGroupPair:
    """
    Abtracts a bilinear group pair containing two origin groups G1,G2 and the image group GT.
    The underlying bplib.bp.BpGroup object is also embedded.
    """

    def __init__(self):
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
    A wrapper for the GT group such that it creates additive points and allows to retrieve groups G1 and G2.
    The group ID is set to 0 to allow comparisons between groups of different types to raise an explicit Exception.
    """

    def __init__(self, bp):
        """
        :param bp: The BilinearGroupPair instance embedding our groups
        """
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

    def wsum(self, weights, generators):
        res = self.infinite()
        for w, g in zip(weights, generators):
            res = res + w * g
        return res


class AdditivePoint:
    """
    A wrapper for GT points so they use additive notation.
    """

    def __init__(self, pt, bp):
        """
        :param pt: A bplib.bp.GTElem
        :param bp: The BilinearGroupPair instance embedding our groups
        """
        self.pt = pt
        self.bp = bp
        self.group = self.bp.GT

    def export(self, form=0):
        return self.pt.export(form) if form else self.pt.export()

    def __mul__(self, nb):
        """
        Overrides the multiplicative syntax (point ** scalar) by an additive one (scalar* point)
        Special case in 0 since the underlying bplib function is broken for this value.
        """
        if nb == 0:
            return AdditivePoint(self.pt / self.pt, self.bp)
        return AdditivePoint(self.pt ** nb, self.bp)

    def __eq__(self, other):
        return self.pt == other.pt

    def __add__(self, other):
        """
        Replaces the multiplicative syntax between two points by an additive one.
        """
        return AdditivePoint(self.pt * (other.pt), self.bp)

    __rmul__ = __mul__

    def __repr__(self):
        return "GTPt(" + str(self.pt.__hash__()) + ")"


class G1Point:
    """
    A wrapper for G1 points so they can be paired with a G2 point by pt.pair(other)
    """

    def __init__(self, ecpt, bpairing):
        self.pt = ecpt
        self.bp = bpairing
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
    A wrapper for bplib.bp.G2Elem points
    """

    def __init__(self, ecpt, bpairing):
        self.pt = ecpt
        self.bp = bpairing
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
    A wrapper for the G1 (behaving like an EcGroup) group.
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

    def wsum(self, weights, generators):
        res = self.infinite()
        for w, g in zip(weights, generators):
            res = res + w * g
        return res


class G2Group:
    """
    A wrapper for the G2 group.
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

    def wsum(self, weights, generators):
        res = self.infinite()
        for w, g in zip(weights, generators):
            res = res + w * g
        return res


if __name__ == "__main__":
    import doctest

    doctest.testmod()
