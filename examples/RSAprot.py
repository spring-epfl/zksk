from zksk import Secret, DLRep
from zksk.utils import groups
from zksk import rsa_group
from zksk.primitives.dlrep import DLRepVerifier
from petlib.bn import Bn, force_Bn

p = Bn.get_prime(128, safe=1)
q = Bn.get_prime(128, safe=1)
assert p != q
n = p * q
x = Secret()
g = groups.get_quad_res(n)
y = 3 * g
stmt = DLRep(y, x * g)

prover = stmt.get_prover({x: 3})
verifier = stmt.get_verifier()

commitment = prover.commit()
challenge = verifier.send_challenge(commitment)
response = prover.compute_response(challenge)

print(verifier.verify(response))
