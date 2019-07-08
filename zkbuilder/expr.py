
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

import struct
import hashlib

from zkbuilder.exceptions import InvalidExpression, IncompleteValuesError


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
            raise InvalidExpression(
                "In {0} * {1}, the first parameter should be a Secret".format(
                    secret, base
                )
            )
        self._secrets = [secret]
        self._bases = [base]

    def __add__(self, other):
        """
        Merge Expression objects along addition.

        Args:
            other (Expression): Another expression

        Returns:
            Expression: New expression
        """
        if not isinstance(other, Expression):
            raise InvalidExpression(
                "Invalid expression. Only linear combinations of group elements are supported."
            )
        self._secrets.extend(other._secrets)
        self._bases.extend(other._bases)
        return self

    @property
    def secrets(self):
        return tuple(self._secrets)

    @property
    def bases(self):
        return tuple(self._bases)

    def eval(self):
        """Evaluate the expression, if all secret values are available.

        TODO: Take secret_dict as optional input.
        """
        for secret in self._secrets:
            if secret.value is None:
                raise IncompleteValuesError(
                    "Secret {0} does not have a value".format(secret.name)
                )

        def ith_mul(i):
            return self._secrets[i].value * self._bases[i]

        summation = ith_mul(0)
        for i in range(1, len(self._secrets)):
            summation += ith_mul(i)
        return summation

    def __repr__(self):
        fragments = []
        for secret, base in zip(self._secrets, self._bases):
            fragments.append("Expression({}, {})".format(secret, base))
        return " + ".join(fragments)


class Secret:
    """
    A secret value in a zero-knowledge proof.

    Args
        name: String to enforce as name of the Secret. Useful for debugging.
        value: Optional secret value.

    """

    NUM_NAME_BYTES = 8

    def __init__(self, value=None, name=None):
        if name is None:
            name = self._generate_unique_name()
        self.name = name
        self.value = value

    def _generate_unique_name(self):
        h = struct.pack(">q", hash(self))
        return hashlib.sha256(h).hexdigest()[:self.NUM_NAME_BYTES * 4]

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
        if self.value is None and self.name is None:
            return "Secret()"
        elif self.value is None:
            return "Secret(name={})".format(repr(self.name))
        elif self.name is None:
            return "Secret({})".format(self.value)
        else:
            return "Secret({}, {})".format(self.value, repr(self.name))

    def __hash__(self):
        if hasattr(self, "name"):
            return hash(("Secret", self.name))
        else:
            return super().__hash__()


def wsum_secrets(secrets, generators):
    """
    Build expression as a dot product of given secrets and generators.
    """
    if len(secrets) != len(generators):
        raise ValueError("Should have as many secrets as generators.")

    result = secrets[0] * generators[0]
    for idx in range(len(generators) - 1):
        result = result + secrets[idx + 1] * generators[idx + 1]
    return result
