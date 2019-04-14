from DLRep import * 
from Subproof import *
from CompositionProofs import *

"""A template for the proof of knowledge of a signature pi5 detailed on page 7 of the following paper : https://eprint.iacr.org/2008/136.pdf
It uses group pairings, DLRep and And Proofs."""


def pi5(r, delta, e, s, m, A1, A2, generators, h0)
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
generators = [gT.pair(A2, w), gen_pairs[0],  gT.pair(A2, h0), gT.pair(generators[1], w), gen_pairs[1]]
generators.extend(gen_pairs[1:])

secret_dict.update({"m"+str(k+1):m[k]for k in range(len(m))})
secret_names = secret_dict.keys()

"""
gen_pairs is an array of the form epair(gi, h0)
generators is the list of elements to multiply i.e all pairings (terms from the equation in the paper are rearranged from a/b = c*d to 1 = a^-1 * b *c*d)
secret_names are the exponents, in order ie (-)e, r1, delta1, s, m_i as specified in the protocol
secretèdict binds the secret names to their value
"""


pairings_proof = 1