from bplib.bp import BpGroup, G1Elem, G2Elem, GTElem
from SigmaProtocol import *

def test():
    """
    Some wrappers to use on top of Bplib groups so groups and points behave well with most of the methods used in petlib.ec

    Given a group GT defining a pairing e(G1,G2)->GT, we create a variant MyGTGRoup which behaves similarly, with more tools:
    >>> G = BpGroup()
    >>> mG = MyGTGroup(G)
    >>> G.order() == mG.order()
    True
    >>> g, gmg =G.pair(G.gen1(), G.gen2()), mG.generator()
    >>> g == gmg.pt
    True
    >>> g == mG.pair(mG.gen1(), mG.gen2()).pt
    True

    We define the AdditivePoint class which defines GT points additively:
    >>> gmg == AdditivePoint(g)
    True
    >>> AdditivePoint(g**(g.group.order())) == mG.infinite()
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
    >>> g1.group == g1mg.group
    True


    We also derive G1 and G2 groups from GT
    >>> G1, G2 = mG.groups()
    >>> g1, g2 = G1.generator(), G2.generator()
    >>> G1.infinite() == G.gen1().inf(G)
    True
    >>> g1*0 ==G1.infinite()
    True
    >>> g1*0 == g1*G.order()
    True
    >>> G2.infinite() == G.gen2().inf(G)
    True
    >>> g2*0 == G2.infinite()
    True
    >>> g2*0 == g2*G.order()
    True
    """
    return 1


class MyGTGroup:
    """
    A wrapper for the GT group such that it creates additive points and allows to retrieve groups G1 and G2.
    """
    def __init__(self, bp):
        self.bp = bp

    def groups(self):
        return MyG1Group(self.bp), MyG2Group(self.bp)

    def infinite(self):
        g1, g2 = self.bp.gen1(), self.bp.gen2()
        gT = self.bp.pair(g1, g2)
        return AdditivePoint(gT.one(self.bp))

    def order(self):
        return self.bp.order()

    def generator(self):
        return AdditivePoint(self.bp.pair(self.bp.gen1(), self.bp.gen2()))

    def pair(self, p1, p2):
        return AdditivePoint(self.bp.pair(p1, p2))

    def gen1(self):
        return self.bp.gen1()

    def gen2(self):
        return self.bp.gen2()

class AdditivePoint:
    """
    A wrapper for GT points so they use additive notation.
    """
    def __init__(self, pt):
        self.pt = pt
        self.group = self.pt.group

    def export(self, form=0):
        return self.pt.export(form) if form else self.pt.export()

    def __mul__(self, nb):
        return AdditivePoint(self.pt**nb)

    def __eq__(self, other):
        return self.pt == other.pt

    def __add__(self, other):
        return AdditivePoint(self.pt*(other.pt))

    __rmul__=__mul__

class PairablePoint:
    """
    A wrapper for G1 (resp G2) points so they can be paired with a G2 (resp G1) point by pt.pair(other)
    """
    def __init__(self, ecpt):
        """
        TODO : decide if self.group returns the GT group or the G1 (or G2) group. If the latter, decide how to determine G1/G2
        """
        self.ecpt = ecpt
        self.group = MyGTGroup(self.ecpt.group)
    
    
    def __add__(other):
        return PairablePoint(self.ecpt+other.ecpt)

    def __mul__(self, nb):
        return PairablePoint(self.ecpt*nb)
    
    def export(self, form=0):
        return self.ecpt.export(form) if form else self.ecpt.export()

    def __eq__(self, other):
        return self.ecpt == other.ecpt
    
    __rmul__ = __mul__

    def pair(self, other):
        return AdditivePoint(self.ecpt.group.pair(self, other))



class MyG1Group:
    """
    A wrapper for the G1 (behaving like an EcGroup) group.
    """
    def __init__(self, bp):
        self.bp = bp

    def generator(self):
        return self.bp.gen1()

    def infinite(self):
        return self.generator().inf(self.bp)

    def order(self):
        return self.bp.order()

class MyG2Group:
    """
    A wrapper for the G2 group.
    """
    def __init__(self, bp):
        self.bp = bp

    def generator(self):
        return self.bp.gen2()

    def infinite(self):
        return self.generator().inf(self.bp)

    def order(self):
        return self.bp.order()
        

if __name__ == "__main__":
    import doctest
    doctest.testmod()