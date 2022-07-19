from zksk import Secret, DLRep
from zksk import utils
from zksk.rsa_group import RSAGroup
from petlib.bn import Bn

p = Bn.get_prime(128, safe=1)
q = Bn.get_prime(128, safe=1)
assert p != q
n = p * q
x = Secret()
g = utils.groups.get_quad_res(n)
y = 3 * g
stmt = DLRep(y, x * g)

prover = stmt.get_prover({x: 3})
verifier = stmt.get_verifier()

commitment = prover.commit()
challenge = verifier.send_challenge(commitment)
response = prover.compute_response(challenge)
# proof = stmt.prove({x: 3})
print(verifier.verify(response))
