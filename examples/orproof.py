"""
Or-composition of two discrete-logarithm knowledge proofs:
PK{ (x0, x1): (Y0 = x0 * G0) | (Y1 = x1 * G1) }

WARNING: if you update this file, update the line numbers in the documentation.
"""

from petlib.ec import EcGroup

from zkbuilder import Secret, DLRep
from zkbuilder.composition import OrProof

group = EcGroup()

# Create the base points on the curve.
g0 = group.hash_to_point(b"one")
g1 = group.hash_to_point(b"two")

# Preparing the secrets.
# In practice, they probably should be big integers (petlib.bn.Bn)
x0 = Secret(value=3)
x1 = Secret(value=40)

# Set up the proof statement.

# First, compute the values, "left-hand side".
y0 = x0.value * g0
y1 = x1.value * g1

# Next, create the proof statement.
stmt = DLRep(y0, x0 * g0) | DLRep(y1, x1 * g1)

# This is an equivalent way to create the proof statement above.
stmt_1 = DLRep(y0, x0 * g0)
stmt_2 = DLRep(y1, x1 * g1)

equivalent_stmt = OrProof(stmt_1, stmt_2)

assert stmt.get_proof_id() == equivalent_stmt.get_proof_id()

# Simulate the prover and verifier interacting.

prover = stmt.get_prover()
verifier = stmt.get_verifier()

commitment = prover.commit()
challenge = verifier.send_challenge(commitment)
response = prover.compute_response(challenge)
assert verifier.verify(response)
