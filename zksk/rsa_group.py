from petlib.bn import Bn

# Creates a class for RSA group elements which is structured in the same way as petlib.ec.EcPt, to allow users to use RSA groups in their proofs.
class RSAGroup:
    # Must take a Bignum as argument
    def __init__(self, value):
        self.value = value

    def order(self):
        return self.value

    def infinite(self):
        return IntPt(1, self)

    def wsum(self, weights, elems):
        res = IntPt(0, self)
        for i in range(0, len(elems)):
            res = res + (weights[i] * elems[i])
        return res


class IntPt:
    # Must take one bignum and one RSAGroup as arguments
    def __init__(self, value, modulus):
        self.pt = value
        self.group = modulus

    def __add__(self, o):
        return IntPt((self.pt + o.pt) % self.group.value, self.group)

    def __rmul__(self, o):
        return IntPt(pow(self.pt, o, self.group.value), self.group)
