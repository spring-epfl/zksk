from zksk import Secret, DLRep
from zksk import utils
import petlib
from zksk.rsa_group import RSAGroup, IntPt

n = 35
x = Secret()
g = IntPt(29, RSAGroup(n))
y = 3 * g
stmt = DLRep(y, x * g)
proof = stmt.prove({x: 3})
print(stmt.verify(proof))
