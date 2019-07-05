"""
Tiny expression language suitable for expressing statements on discrete logarithm representations

>>> from petlib.ec import EcGroup
>>> group = EcGroup()
>>> g = group.hash_to_point(b"1")
>>> h = group.hash_to_point(b"2")
>>> a = Secret()
>>> b = Secret()
>>> expr = a * g + b * h

"""

class Expression:
    """
    Arithmetic expression of secrets and group elements.

    It is an abstraction for :math:`x_0 g_0 + x_1 g_2 + ... + x_n g_n`, where :math:`x_i`-s are
    declared secrets.

    Implementation-wise, parses the sum into an ordered list of Secrets and an ordered list of
    generators.

    Args:
        secret (Secret): Secret object.
        base: Base point on an elliptic curve.
    """

    def __init__(self, secret, base):
        if not isinstance(secret, Secret):
            raise Exception(
                "in {0} * {1}, the first parameter should be a Secret ".format(
                    secret, base
                )
            )
        self.secrets = [secret]
        self.pts = [base]

    def __add__(self, other):
        """
        Merge Expression objects along addition.

        Args:
            other (Expression): Another expression

        Returns:
            Expression: New expression
        """
        if not isinstance(other, Expression):
            raise Exception(
                '${0} doesn\'t correspond to something "x1" * g1 + "x2" * g2 + ... + "xn" * gn'
            )
        self.secrets.extend(other.secrets)
        self.pts.extend(other.pts)
        return self

    def eval(self):
        """Evaluate the expression, if all secret values are available.

        TODO: Take secret_dict as optional input.
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
    """
    A secret value in a zero-knowledge proof.

    Args
        name: String to enforce as name of the Secret. Useful for debugging.
        value: Optional secret value.

    """
    def __init__(self, name=None, value=None):
        self.name = name or str(hash(self))
        self.value = value

    def __mul__(self, base):
        """
        Args:
            base: Base point on an elliptic curve.

        Returns:
            Expression: Fresh instance abstracting the multiplication between this Secret and base
        """
        return Expression(self, base)

    __rmul__ = __mul__

    def __repr__(self):
        return self.name

    def __hash__(self):
        if hasattr(self, "name"):
            return hash(self.name)
        else:
            return super().__hash__()


def wsum_secrets(secrets, generators):
    """
    Returns a complete Expression object when passed a list of Secret instances and a list of
    generators, of same length.
    """
    if len(secrets) != len(generators):
        raise Exception("Bad wsum")

    sum_ = secrets[0] * generators[0]
    for idx in range(len(generators) - 1):
        sum_ = sum_ + secrets[idx + 1] * generators[idx + 1]
    return sum_

