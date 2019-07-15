from petlib.ec import EcGroup

from zksk import Secret, DLRep

group = EcGroup()

# Create the base points on the curve.
g0 = group.hash_to_point(b"one")
g1 = group.hash_to_point(b"two")
g2 = group.hash_to_point(b"three")

# Preparing the secrets.
# In practice, they probably should be big integers (petlib.bn.Bn)
x0 = Secret(value=3)
x1 = Secret(value=40)
x2 = Secret(value=50)

# Set up the proof statement.
y0 = x0.value * g0
y1 = x1.value * g1
y2 = x2.value * g2
stmt = (DLRep(y0, x0 * g0) | DLRep(y1, x1 * g1)) & DLRep(y2, x2 * g2)

# Execute the protocol.
prover = stmt.get_prover()
verifier = stmt.get_verifier()

commitment = prover.commit()
challenge = verifier.send_challenge(commitment)
response = prover.compute_response(challenge)
assert verifier.verify(response)

