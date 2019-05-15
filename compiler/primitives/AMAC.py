from primitives.DLRep import * 
from Subproof import *
from CompositionProofs import *


""" We provide two templates for the Algebraic MACs and Keyed-Verification Anonymous Credentials, 
to show the syntax the ZKC would use in a "real-world" implementation.
The prior operations of hashing and deriving the problem's variables are left to the reader, 
we only focus on the zero-knowledge proofs encapsulation.
The first tool functions can help a realistic implementation.
The GGM proof is the part 4.2 and the DDH is the part 4.3 of the following paper :
https://eprint.iacr.org/2013/516.pdf
"""


def setup_ggm(nid = 713):
    """Comes from Petlib. Generates the ggm parameters for an EC group nid"""
    G = EcGroup(nid)
    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    o = G.order()
    return (G, g, h, o)

def keyGen_ggm(params, n): # n is the number of messages we'll pass
    """ Generates the key parameters in a ggm implementation.
    """
    o = params[3]
    h = params[2]
    [rands = o.random() for _ in range(2*n)
    
    x = rands[:len(A)//2]   #length n   
    y = rands[len(A)//2:]   #length n
    z = o.random() 
    return (z, x, y)

def Hx(z, rands, messages):
    """From Petlib. A checksum-like helper function Hx"""
    assert len(messages) == len(rands) - 1
    total = z    
    for xi, mi in zip(rands, messages):
        total = total + (xi * mi)
    return total

# X, x are returned by Keygen
# u, u_prime are returned by MAC(x, messages) on the issuer side
def amac_ggm(iparams, sk, u, u_prime, messages):
    """ The GGM scheme in itself : an other implementation is found in petlib example files
    at https://github.com/gdanezis/petlib/blob/master/examples/amacs.py.
    """
    Cx, X = iparams
    x, x0b = sk

    secret_names = ["x"+str(i) for i in range(n)]

    [constructed_u = el*u for el in messages]
    final_u = [u]
    final_u.extend(constructed_u)
    u_proof = DLRepProof(final_u, secret_names, u_prime)

    C_proof = DLRepProof([g, h], ["x0", "x0b"], Cx)

    [h_proofs = DLRepProof([h], secret_names[i+1], X[i+1]) for i in range(n-1)
    h_and = AndProof(h_proofs)

    amac = AndProof(u_proof, C_proof, h_and)
    secret_dict = dict(zip(secret_names, x))
    protocol = SigmaProtocol(amac.get_verifier, amac.get_prover(secret_dict))
    assert protocol.run()


def amac_ddh(iparams, sk, sigma, messages): 
    """ The DDH scheme in itself. The sigma parameter is homogeneous to the (u,u') parameter in the GGM scheme.
    """

    "Get the parameters"
    X, Y, Cx, Cy, Cz = iparams
    x, y, z, xb, yb, zb = sk
    x_names = ["x"+str(i) for i in range(n+1)]
    y_names = ["y"+str(i) for i in range(n+1)]

    "Construct the proof. Obviously it can be done in less lines at the cost of readability"
    sigma_proof=[]  # A list of DLRep proofs
    sigma_proof.append(DLRepProof(sigma[0]*(n+1), x_names,  sigma[1]))
    sigma_proof.append(DLRepProof(sigma[0]*(n+1), y_names,  sigma[2]))
    sigma_proof.append(DLRepProof(sigma[0], ["z"],  sigma[3]))

    c_proofs = [DLRepProof(lhs, Secret(name+'0')*g + Secret(name+'b')*h) for lhs, name in zip([Cx, Cy, Cz],["x","y","z"])]

    [x_proofs = DLRepProof([h], x_names[i+1], X[i+1]) for i in range(n)
    x_and = AndProof(x_proofs) #An And of DLRep
    
    [y_proofs = DLRepProof([h], y_names[i+1], Y[i+1]) for i in range(n)
    y_and = AndProof(y_proofs)  #An And of DLRep


    ddh_proof = AndProof(sigma_proof, c_proofs, y_and, x_and)

    "Build the secret dictionary"
    secret_dict = dict(zip(secret_names, secret_values))

    "Let's run it !"
    ddh_proof = AndProof(sigma_proof, c_proofs, y_and, x_and)
    prot = SigmaProtocol(ddh_proof.get_verifier, ddh_proof.get_prover(secret_dict))
    assert prot.run()

def prepare_messages(point, messages)
    [raised = m * point for m in messages]
    final_raised = [point]
    final_raised.extend(raised)
    return final_raised