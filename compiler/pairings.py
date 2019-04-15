from bplib.bp import BpGroup, G1Elem, G2Elem, GTElem
from SigmaProtocol import *
#class MyBpGroup(BpGroup):



""" def enhance_method(klass, method_name, replacement):
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
"""
def additive_scalar(self, scalar):
    return self**scalar

#enhance self.mul with scalars so it returns self.exp (DLRep tries to multiply xigi)
#enhance (create?) self.add with group elements so it calls self.mul (DLRep tries to add all the xigi)

G = BpGroup()
Zp = G.order()

Ga = Zp.random() * G.gen1()
Ha = Zp.random() * G.gen2()
k = G.pair(Ga, Ha)
print(k.group.order())
y = k+k # same object! ???
u = k**Zp.random()
print("\nk:", k, "\nk+k:", k+k, "\nk*k", k*k, "\nk**2", k**2)
print("Set u = k**Zp.random()")
print("\nu:",u,"\nu+u:", u+u, "\nu*u:",u*u, "\nu**2:",u**2)


print(u+u == u*u)
print(u*u == u**2)


def groups(GTgroup):
    return GTgroup.gen1().group, GTgroup.gen2().group

def infinite(GTgroup):
    G1, G2 = groups(GTgroup)
    return GTgroup.pair(G1.infinite(), G2.infinite())

def generator(GTgroup):
    G1, G2 = groups(GTgroup)
    return (GTgroup.pair(G1.generator(), G1.generator()))




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