from DLRep import * 
from Subproof import *
from CompositionProofs import *
from SigmaProtocol import *

class Signer:
    def __init__(generators, henerators):
        self.generators = generators
        self.henerators = henerators
        self.h0 = henerators[0]
        self.group = self.h0.group
        self.gamma = 0
    
    def keyGen(self):
        self.gamma = self.h0.group.order.random()
        self.w = gamma*h0
        return self.w

    def sign(self):
        """
        Signs a committed message Cm ie returns A,e,s such that A = (g0 + s*g1 + Cm) * 1/e+gamma
        >>> G = MyGTGroup()
        >>> gens = [2,3,4]*G.gen1()
        >>> hens = [2,3,4]*G.gen2()
        >>> s = Signer(gens, hens)
        >>> s.verifier.lhs = 12*gens[1]
        >>> A,e,s2 = s.sign()
        >>> (e + s.gamma)*A == self.verifier.lhs
        True
        """
        if self.gamma == 0:
            self.keyGen()
        pedersen_product = self.verifier.lhs
        e = self.generators[0].group.order().random()
        s2 = self.generators[0].group.order().random()
        prod = self.generators[0]+s2*self.generators[1]+pedersen_product
        A = ((gamma+e).mod_inverse(self.group.order())*prod
        return A,e,s2


def pedersen_tosign(messages, generators):
    """
    Prepare a pedersen commitment for the correct construction of the sequence to be signed.
    Returns a non-interactive proof as well as a verifier object able to verify the said proof.
    """
    #Test the generator length to see if we were passed g0 (power 1)
    if len(generators)==len(messages)+2:
        generators = generators[1:]
    s1 = self.generators[0].group.order().random()
    #define secret names as s' m1 m2 ...mL
    names = ["s'"] + ["m"+str(i+1) for i in range(len(messages)+1)] 
    secrets = [s1] + messages
    pedersen_proof = DLRepProof(create_lhs(generators, secrets), create_rhs(names, generators))
    pedersen_prover = pedersen_proof.get_prover(dict(zip(names, secrets)))
    return pedersen_prover.get_NI_proof(), pedersen_proof.get_verifier()

def verify_signature(A,e,s, w, generators, h0, messages):
    product = [generators[0]] + create_lhs(generators[1:], [s]+messages)
    return A.pair(w+e*h0) == product.pair(h0)
    





def sign_and_verify(messages, signer:Signer):
    """
    Wrapper method which given a set of generators and messages, performs the whole protocol from the key generation to the signature verification.
    """
    generators, henerators = signer.generators, signer.henerators
    pedersen_NI, signer.verifier = pedersen_tosign(messages, generators)

    #verification is done on the signer side. can be moved in Signer.sign()
    if signer.verifier.verify_NI(pedersen_NI):
        print("Pedersen commitment verified on the signer side. Signing...")
    
    w = signer.keyGen()
    A,e,s2 = signer.sign()
    print("Done signing..")
    #sign takes no additional argument since we already gave the verifier object (included the LHS = the actual Pedersen commitment to the signer)

    if verify_signature(A,e,s2+s1, w, generators, henerators[0], messages) :
        print ("Signature verified!")

    
    




class Signed:
    def __init__(self):
        self.A = 0
        self.e
        self.same


class SignatureProof(Proof):
    def __init__(self, blabla):
        """
        Instantiates a Signature Proof which is an enhanced version of AndProof allowing to access additional parameters
        """
        self.andp = build_pi5(blabla)


    def get_prover(self, secret_dict):
        andp = self.andp.get_prover(secret_dict)
        return SignatureProver(andp)

class SignatureProver(Prover):
    def __init__(self, andprover)
        self.andp = andprover

    def commit(self):
        return self.andp.commit()



        

"""A template for the proof of knowledge of a signature pi5 detailed on page 7 of the following paper : https://eprint.iacr.org/2008/136.pdf
It uses group pairings, DLRep and And Proofs."""

def precommit(generators, A)
"""
Generate LHS A1, A2 for the signature proof
"""
    r1 = generators[0].group.order().random()
    r2 = generators[0].group.order().random()
    a1 = generators[1]*r1+generators[2]*r2
    a2 = A+generators[2]*r1
    return [r1, r2], a1, a2





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
A1b = e*A1
g0, g1, g2 = generators[0], generators[1], generators[2]
dl1 = DLRepProof(A1, Secret("r1")*g1 + Secret("r2"*g2))
dl2 = DLRepProof(A1b, Secret("delta1")*g1 + Secret("delta2")*g2)

signature = AndProof(dl1, dl2)


gen_pairs = [gT.pair(generators[k], h0) for k in range(L+2)]

lhs = gT.pair(A2, w)/gen_pairs[0]
generators = [-gT.pair(A2, h0), gT.pair(generators[1], w), gen_pairs[1]]
generators.extend(gen_pairs[1:])

secret_dict = {"e":e, "r1":r[0], "delta1":delta[0], "s":s}
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
secret_names are the exponents (ordered) ie -e, r1, delta1, s, m_i as specified in the protocol
secret_dict binds the secret names to their value
"""

pairings_proof = DLRepProof(lhs, create_rhs(secret_names, generators))

return AndProof(signature, pairings_proof)
#The sigature proof is ready to be used, either with an interactive sigma protocol, 
# a NI proof or even a simulation (just specify dummy secrets for the proof building and then pass an empty dict to the prover)


def SignProof(A, e, s, messages):
    a1,a2,r = precommit(generators, A)