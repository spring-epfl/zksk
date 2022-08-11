"""
Allow zero knowledge proofs in subgroups of RSA groups (groups of integers modulo the product of two safe primes), instead of only in groups of prime order.

Example:
PK{(alpha): y = alpha * g}
where y, and g are elements of a subgroup of an RSA group of order p * q, for two safe primes p and q. We assume there is a trusted setup which keeps p and q secret from both the Prover and the Verifier, which sends y, g, and p * q to both parties, and which sends alpha to the Prover.

The protocol we follow for proofs of discrete logarithm representations is inspired from page 34 of Boneh, Bünz and Fisch, Batching Techniques for Accumulators with Applications to IOPs and Stateless Blockchains, Crypto 2019.
"""
# To do: Allow ZKPs of other cryptographic primitives in RSA groups.
import math

from petlib.bn import Bn
from petlib.pack import *

# This sets up the RSA group and the subgroup generators
# Example:
# [g,h] = rsa_dlrep_trusted_setup(bits=1024,num = 2)
# g and h are two generators of the subgroup of quadratic residues of an RSA group of order the product of two 1024 bit primes.
def rsa_dlrep_trusted_setup(bits=1024, num=1):
    p = Bn.get_prime(bits, safe=1)
    q = Bn.get_prime(bits, safe=1)
    n = p * q
    b = n.num_bits()
    while True:
        q = Bn.from_num(Bn(2).pow(bits).random())
        if q < n and math.gcd(int(q), int(n)) == 1:
            break
    g = IntPt((q * q) % n, RSAGroup(n))
    res = [g]

    num -= 1
    while num != 0:
        res.append(((p - 1) * (q - 1)).random() * g)
        num -= 1
    return res


# This class mimics petlib.ec.EcGroup, but for RSA groups.
class RSAGroup:
    # Must take a Bignum as argument
    def __init__(self, modulus):
        self.modulus = modulus

    def infinite(self):
        return IntPt(1, self)

    def wsum(self, weights, elems):
        res = IntPt(Bn(1), self)
        for i in range(0, len(elems)):
            res = res + (weights[i] * elems[i])
        return res

    def __eq__(self, other):
        return self.modulus == other.modulus


# This class mimics petlib.ec.EcPt, but for elements of RSA groups.
class IntPt:
    # Must take one bignum and one RSAGroup as arguments
    def __init__(self, value, modulus):
        self.pt = value
        self.group = modulus

    def __add__(self, o):
        return IntPt((self.pt * o.pt) % self.group.modulus, self.group)

    def __rmul__(self, o):
        if o < 0:
            return IntPt(
                pow(self.pt.mod_inverse(self.group.modulus), -o, self.group.modulus),
                self.group,
            )
        else:
            return IntPt(pow(self.pt, o, self.group.modulus), self.group)

    def __eq__(self, other):
        return (self.pt == other.pt) and (self.group == other.group)


def enc_RSAGroup(obj):
    return encode(obj.modulus)


def dec_RSAGroup(data):
    return RSAGroup(decode(data))


def enc_IntPt(obj):
    return encode([obj.pt, obj.group])


def dec_IntPt(data):
    d = decode(data)
    return IntPt(d[0], d[1])


register_coders(RSAGroup, 10, enc_RSAGroup, dec_RSAGroup)
register_coders(IntPt, 11, enc_IntPt, dec_IntPt)
