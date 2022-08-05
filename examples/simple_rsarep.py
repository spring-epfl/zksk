"""
Proof of knowledge of a discrete logarithm in a subgroup of an RSA group:
PK{ (x): y = x * g}
"""

from petlib.bn import Bn

from zksk import Secret, DLRep
from zksk.utils import groups

p = Bn.get_prime(128, safe=1)
q = Bn.get_prime(128, safe=1)
n = p * q

# Create a generator for a subgroup of the RSA group of order n.
g = groups.get_quad_res(n)

# Preparing the secret.
# In practice, this should probably be a big integer (petlib.bn.Bn)
x = Secret()

# Setup the proof statement.

# First, compute the "left-hand side".
y = 3 * g

# Next, create the proof statement.
stmt = DLRep(y, x * g)

# Simulate the prover and the verifier interacting.
prover = stmt.get_prover({x: 3})
verifier = stmt.get_verifier()

commitment = prover.commit()
challenge = verifier.send_challenge(commitment)
response = prover.compute_response(challenge)
assert verifier.verify(response)

# Non-interactive proof.
nizk = stmt.prove({x: 3})
assert stmt.verify(nizk)
