from bplib.bp import BpGroup, G1Elem, G2Elem, GTElem
from SigmaProtocol import *


class MyBpGroup:
    def __init__(self, bp):
        self.bp = bp

    def groups(self):
        return self.bp.gen1().group, self.bp.gen2().group

    def infinite(self):
        g1, g2 = self.bp.gen1(), self.bp.gen2()
        gT = self.bp.pair(g1, g2)
        return gT.zero(self.bp)

    def order(self):
        return self.bp.order()

    def generator(self):
        return self.bp.pair(self.bp.gen1(), self.bp.gen2())



class AdditivePoint:
    def __init__(self, pt):
        self.pt = pt

    def export(self, form=POINT_CONVERSION_COMPRESSED):
        return self.pt.export(form)

    def __eq__(self, other):
        return self.pt == other.pt

    def __add__(self, other):
        return self.pt*(other.pt)

    def __mul__(self, nb):
        return self.pt**nb







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