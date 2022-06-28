from petlib.bn import Bn

# Creates a class for RSA group elements which is structured in the same way as petlib.ec.EcPt, to allow users to use RSA groups in their proofs.
class RSAGroup:
    def __init__(self, value):
        self.value = value

    def order(self):
        return Bn(self.value)

    def infinite(self):
        return IntPt(1, self)


class IntPt:
    def __init__(self, value, modulus):
        self.pt = value
        self.group = modulus

    def __add__(self, o):
        return IntPt((self.pt + o.pt) % self.group.value, self.group)

    def __rmul__(self, o):
        return IntPt(pow(self.pt, int(o), self.group.value), self.group)
