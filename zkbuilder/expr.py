
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

from collections import defaultdict

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

    # Number of bytes in a randomly-generated name of a secret.
    NUM_NAME_BYTES = 8

    def __init__(self, value=None, name=None):
        if name is None:
            name = self._generate_unique_name()
        self.name = name
        self.value = value

    def _generate_unique_name(self):
        h = struct.pack(">q", super().__hash__())
        return hashlib.sha256(h).hexdigest()[:self.NUM_NAME_BYTES * 4]

    def __mul__(self, base):
        """
        Construct an expression that represents this secrets multipled by the base.

        Args:
            base: Base point on an elliptic curve.

        Returns:
            Expression
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
        return hash(("Secret", self.name))

    def __eq__(self, other):
        return (hash(self) == hash(other)) and self.value == other.value


def wsum_secrets(secrets, generators):
    """
    Build expression representing a dot product of given secrets and generators.

    >>> from zkbuilder.utils import make_generators
    >>> x, y = Secret(), Secret()
    >>> g, h = make_generators(2)
    >>> expr = wsum_secrets([x, y], [g, h])
    >>> expr.bases == (g, h)
    True
    >>> expr.secrets == (x, y)
    True

    Args:
        secrets: :py:class:`Secret` objects :math`s_i`
        generators: Group generators :math:`g_i`

    Returns:
        Expression: :math:`s_0 g_0 + s_1 g_1 + ... + s_n g_n`
    """
    if len(secrets) != len(generators):
        raise ValueError("Should have as many secrets as generators.")

    result = secrets[0] * generators[0]
    for idx in range(len(generators) - 1):
        result = result + secrets[idx + 1] * generators[idx + 1]
    return result


def update_secret_values(secrets_dict):
    """
    Update values of secrets according to the given mapping.

    >>> x, y = Secret(), Secret()
    >>> secrets_dict = {x: 1, y: 2}
    >>> update_secret_values(secrets_dict)
    >>> x.value
    1
    >>> y.value
    2

    Args:
        secrets_dict: A mapping from :py:class:`Secret` objects to their expected values.
    """
    for k, v in secrets_dict.items(): k.value = v


def check_groups(secrets, generators):
    """
    Check that if two secrets are the same, their generators induce groups of same order.

    The primary goal is to ensure same responses for same secrets will not yield false negatives of
    :py:meth:`base.Verifier.check_responses_consistency` due to different group-order modular reductions.

    TODO: Consider deactivating in the future as this forbids using different groups in one proof.
    TODO: Update docs, variable names.

    Args:
        secrets: :py:class:`expr.Secret` objects.
        generators: Generators, Elliptic curve points.
    """
    # We map the unique secrets to the indices where they appear
    mydict = defaultdict(list)
    for idx, word in enumerate(secrets):
        mydict[word].append(idx)

    # Now we use this dictionary to check all the generators related to a particular secret live in
    # the same group
    for (word, gen_idx) in mydict.items():
        # Word is the key, gen_idx is the value = a list of indices
        ref_order = generators[gen_idx[0]].group.order()

        for index in gen_idx:
            if generators[index].group.order() != ref_order:
                raise InvalidExpression(
                    "A shared secret has generators which yield different group orders: ", word,
                )

    return True

