"""
Examples of using secrets and expressions.

WARNING: if you update this file, update the line numbers in the documentation.
"""

from petlib.ec import EcGroup

from zksk import Secret, DLRep

group = EcGroup()
g = group.generator()

# Different way to define secrets.
x = Secret()
x = Secret(value=42)

# If secret come with values, prover will get them.
x = Secret(value=4, name="x")
y = x.value * g
stmt = DLRep(y, x * g)
prover = stmt.get_prover()

# Otherwise, a prover needs to have the values as a dictionary.
x = Secret(name="x")
value = 4
stmt = DLRep(value * g, x * g)
prover = stmt.get_prover({x: value})

# Example of a bit more complex expression.
x = Secret()
y = Secret()
g = group.hash_to_point(b"one")
h = group.hash_to_point(b"two")
expr = x * g + y * h

# Expressions can be evaluated.
x = Secret(value=5)
expr = x * g
expr.eval()

# Evaluations can simplify definitions of proof statements.
stmt = DLRep(expr.eval(), expr)
