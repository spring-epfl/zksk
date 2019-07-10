import re
import pytest

from petlib.ec import EcPt

from zkbuilder.exceptions import IncompleteValuesError, InvalidExpression
from zkbuilder.expr import Secret, Expression, wsum_secrets
from zkbuilder.utils import DEFAULT_GROUP, get_generators


def test_secret_named():
    x = Secret(name="x")
    assert x.name == "x"


def test_secret_different_anonymous_secrets():
    x, y = Secret(), Secret()
    assert x.name != y.name
    assert hash(x) != hash(y)


@pytest.mark.parametrize(
    "x,pattern",
    [
        (Secret(), r"Secret\(name='.+'\)"),
        (Secret(name="x"), r"Secret\(name='x'\)"),
        (Secret(value=42), r"Secret\(42, '.+'\)"),
        (Secret(value=42, name="x"), r"Secret\(42, 'x'\)"),
    ],
)
def test_secret_repr(x, pattern):
    assert re.match(pattern, repr(x)) is not None


def test_expr_1(group):
    g = group.generator()
    x = Secret()
    expr = Expression(x, g)
    assert expr.bases == (g,)
    assert expr.secrets == (x,)


def test_expr_2(group):
    g = group.generator()
    x = Secret()
    expr = x * g
    assert expr.bases == (g,)
    assert expr.secrets == (x,)


def test_expr_eval_no_values_specified(group):
    g = group.generator()
    g1 = 2 * g
    g2 = 5 * g

    rhs = Secret(name="x1") * g1 + Secret(name="x2") * g2
    with pytest.raises(IncompleteValuesError):
        rhs.eval()


@pytest.mark.parametrize("other", [
    Secret(),
    2,
    "gibberish"
])
def test_expr_invalid_expression(group, other):
    g = group.generator()
    expr = Secret() * g

    with pytest.raises(InvalidExpression):
        expr + other


@pytest.mark.parametrize("num", [2, 10])
def test_expr_repr(group, num):
    secrets = [Secret() for _ in range(num)]
    generators = get_generators(num, group)
    expr = wsum_secrets(secrets, generators)

    expected_repr = " + ".join(
        "Expression({}, {})".format(x, g) for x, g in zip(secrets, generators)
    )
    assert expected_repr == repr(expr)
