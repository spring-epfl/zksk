from bplib.bp import BpGroup, G1Elem, G2Elem, GTElem
from SigmaProtocol import *

"""
check everything because bidule.group actually returns the GT group and not the G1/G2 groups (do our classes mimic them well?)
"""

class AdditivePoint:
    def __init__(self, pt):
        self.pt = pt

    def export(self, form=0):
        return self.pt.export(form) if form else self.pt.export()

    def __mul__(self, nb):
        return self.pt**nb

    def __eq__(self, other):
        return self.pt == other.pt

    def __add__(self, other):
        return self.pt*(other.pt)
        

    __rmul__=__mul__



class MyG1Group:
    def __init__(self, bp):
        self.bp = bp

    def generator(self):
        return self.bp.gen1()

    def infinite(self):
        return self.generator().inf(self.bp)

    def order(self):
        return self.bp.order()

class MyG2Group:
    def __init__(self, bp):
        self.bp = bp

    def generator(self):
        return self.bp.gen2()

    def infinite(self):
        return self.generator().inf(self.bp)

    def order(self):
        return self.bp.order()

class MyGTGroup:
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

        







"""
model from https://www.oreilly.com/library/view/python-cookbook/0596001673/ch15s10.html:

from _ _future_ _ import nested_scopes
import new

def enhance_method(klass, method_name, replacement):
    'replace a method with an enhanced version'
    method = getattr(klass, method_name)
    def enhanced(*args, **kwds): return replacement(method, *args, **kwds)
    setattr(klass, method_name, new.instancemethod(enhanced, None, klass))

def method_logger(old_method, self, *args, **kwds):
    'example of enhancement: log all calls to a method'
    print '*** calling: %s%s, kwds=%s' % (old_method._ _name_ _, args, kwds)
    return_value = old_method(self, *args, **kwds) # call the original method
    print '*** %s returns: %r' % (old_method._ _name_ _, return_value)
    return return_value

def demo(  ):
    class Deli:
        def order_cheese(self, cheese_type):
            print 'Sorry, we are completely out of %s' % cheese_type

    d = Deli(  )
    d.order_cheese('Gouda')

    enhance_method(Deli, 'order_cheese', method_logger)
    d.order_cheese('Cheddar')
"""