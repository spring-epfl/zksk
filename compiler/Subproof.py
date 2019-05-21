from petlib.ec import EcPt
from petlib.bn import Bn
from functools import reduce
import pdb


class RightSide:
    """
    A class that can be obtained by composing (with the addition operator) elements of type Secret with element of type petlib.ec.EcPt.
    It is an abstraction for x1 * g1 + x2 * g2 + ... + xn * gn where xi-s have unknown or known values.
    This is essentially a class that types this syntactic sugar: Secret(\"x1\") * g1 + Secret(\"x2\") * g2 + ...  where gi-s are instances of petlib.ec.EcPt
    c.f. DLRepProof to see how RightSide is used.
    Secret("x") can be assigned a value at its creation by creating it like so: Secret("x", val) where val is of type petlib.bn.Bn
    """

    def __init__(self, secret, ecPt):
        """
        :param secret: of type Secret
        :param ecPt: of type petlib.ec.EcPt
        """
        if not isinstance(secret, Secret):
            raise Exception(
                "in {0} * {1}, the first parameter should be a string ".format(
                    secret, ecPt
                )
            )
        self.secrets = [secret]
        self.pts = [ecPt]

    def __add__(self, other):
        """
        :param other: of type RightSide
        :return: a new element of type RightSide representing self + other
        """
        if not isinstance(other, RightSide):
            raise Exception(
                '${0} doesn\'t correspond to something like "x1" * g1 + "x2" * g2 + ... + "xn" * gn'
            )
        self.secrets.extend(other.secrets)
        self.pts.extend(other.pts)
        return self

    def eval(self):
        """
        this method allows for writing things such as 
        x1 = petlib.bn.Bn(10)
        x2 = petlib.bn.Bn(20)
        rhs = Secret("x1", x1) * g1 + Secret("x2", x2) 
        proof = DLRepProof(rhs.eval(), rhs) # this is where we can be a little bit lazy and not write DLRepProof(x1 * g1 + x2 * g2, rhs)
        proof.get_prover({"x1": x1, "x2": x2})
        :return: the value to which this RightSide is equal to if each Secret has already been assigned a value at its creation
        """
        for secret in self.secrets:
            if secret.value == None:
                raise Exception(
                    "trying to evaluate secret {0} which was set with no value".format(
                        secret.name
                    )
                )

        def ith_mul(i):
            return self.secrets[i].value * self.pts[i]

        summation = ith_mul(0)
        for i in range(1, len(self.secrets)):
            summation += ith_mul(i)
        return summation


class Secret:
    def __init__(self, name, value=None):
        """
        :param name: a string equal to the name of this secret 
        :param value: an optional petlib.bn.Bn number equal to the secret value. This can be left for later at the creation of the prover.
        """
        self.name = name
        self.value = value

    def __mul__(self, ecPt):
        """
        :param ecPt: an instance of petlib.ec.EcPt
        :return: a RightSide fresh instance abstracting the multiplication between this Secret and ecPt
        """
        return RightSide(self, ecPt)


def create_rhs(secrets_names, generators):
    return reduce(
        lambda x1, x2: x1 + x2,
        map(lambda t: Secret(t[0]) * t[1], zip(secrets_names, generators)),
    )
