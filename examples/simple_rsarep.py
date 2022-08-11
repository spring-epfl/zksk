"""
Proof of knowledge of a discrete logarithm in a subgroup of an RSA group:
PK{ (x): y = x * g}
"""

from petlib.bn import Bn

from zksk import Secret, DLRep
from zksk.rsa_group import rsa_dlrep_trusted_setup

# Create a generator for a subgroup of an RSA group.
[g] = rsa_dlrep_trusted_setup(bits=1024, num=1)

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
