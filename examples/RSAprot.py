from zksk import Secret, DLRep
from zksk import utils
from petlib.bn import Bn

p = Bn.get_prime(128, safe=1)
q = Bn.get_prime(128, safe=1)
assert p != q
n = p * q
x = Secret()
g = utils.groups.get_quad_res(n)
y = 3 * g
stmt = DLRep(y, x * g)
proof = stmt.prove({x: 3})
print(stmt.verify(proof))
