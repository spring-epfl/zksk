from DLRep import * 
from Subproof import *
from CompositionProofs import *

"""A template for the proof of knowledge of a signature pi5 detailed on page 7 of the following paper : https://eprint.iacr.org/2008/136.pdf
It uses group pairings, DLRep and And Proofs."""


def build_pi5(r, delta, e, s, m, A1, A2, generators, h0)
"""
public info should be : 
    - w (public key), 
    - h0 (base of the public key), 
    - generators (of length len(m)+2)
    - a generator of a group GT for pairing epair(g1,g2)->gT

"""
gT = genT.group
L = len(m)
A2 = e*A1
g0, g1, g2 = generators[0], generators[1], generators[2]
dl1 = DLRepProof(A1, Secret("r1")*g1 + Secret("r2"*g2))
dl2 = DLRepProof(A2, Secret("delta1")*g1 + Secret("delta2")*g2)

signature = AndProof(dl1, dl2)


gen_pairs = [gT.pair(generators[k], h0) for k in range(L+2)]

lhs = gT.pair(A2, w)/gen_pairs[0]
generators = [gT.pair(A2, h0), gT.pair(generators[1], w), gen_pairs[1]]
generators.extend(gen_pairs[1:])

secret_dict = {"-e":-e, "r1":r[0], "delta1":delta[0], "s":s}
"""
Here notice that the secret -e will have secret name -e and the protocol will not find out it is the opposite of e.
It does not matter because the only part of the protocol using this knowledge is the verifier checking the responses are consistent, 
which does not apply here since the elements raised to this e are not part of groups with a same order (verification doesn't apply)
"""
secret_dict.update({"m"+str(k+1):m[k]for k in range(len(m))})
secret_names = secret_dict.keys()

"""
gen_pairs is an array of the form epair(gi, h0)
generators is the list of elements to multiply i.e all pairings
secret_names are the exponents (ordered) ie (-)e, r1, delta1, s, m_i as specified in the protocol
secret_dict binds the secret names to their value
"""

pairings_proof = DLRepProof(lhs, create_rhs(secret_names, generators))

sigProof = AndProof(signature, pairings_proof)
#The sigature proof is ready to be used, either with an interactive sigma protocol, 
# a NI proof or even a simulation (just specify dummy secrets for the proof building and then pass an empty dict to the prover)