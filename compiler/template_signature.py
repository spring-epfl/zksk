from DLRep import * 
from Subproof import *
from CompositionProofs import *
from SigmaProtocol import *
from pairings import *
import pdb

class Signer:
    def __init__(self, generators, henerators):
        self.generators = generators
        self.henerators = henerators
        self.h0 = henerators[0]
        self.group = self.h0.group
        self.gamma = 0
        self.keyGen()
    
    def keyGen(self):
        self.gamma = self.h0.group.order().random()
        self.w = self.gamma*self.h0

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
        e = self.group.order().random()
        s2 = self.group.order().random()
        prod = self.generators[0]+s2*self.generators[1]+pedersen_product
        A = (self.gamma+e).mod_inverse(self.group.order())*prod
        return A,e,s2


def user_commit(messages, generators):
    """
    Prepare a pedersen commitment for the correct construction of the sequence to be signed.
    Returns a non-interactive proof as well as a verifier object able to verify the said proof.
    """
    #Test the generator length to see if we were passed g0 (power 1)
    if len(generators)==len(messages)+2:
        generators = generators[1:]
    s1 = generators[0].group.order().random()
    #define secret names as s' m1 m2 ...mL
    names = ["s'"] + ["m"+str(i+1) for i in range(len(messages))] 
    secrets = [s1] + messages

    pedersen_proof = DLRepProof(create_lhs(generators, secrets), create_rhs(names, generators))
    pedersen_prover = pedersen_proof.get_prover(dict(zip(names, secrets)))
    return pedersen_prover.get_NI_proof(encoding=enc_GXpt), pedersen_proof.get_verifier(), s1

def verify_signature(A,e,s, w, generators, h0, messages):
    product = generators[0] + create_lhs(generators[1:], [s]+messages)
    return A.pair(w+e*h0) == product.pair(h0)
    
def sign_and_verify(messages, signer:Signer):
    """
    Wrapper method which given a set of generators and messages, performs the whole protocol from the key generation to the signature verification.
    """
    generators, h0 = signer.generators, signer.h0
    pedersen_NI, signer.verifier, s1 = user_commit(messages, generators)

    #verification is done on the signer side. can be moved in Signer.sign()
    if signer.verifier.verify_NI(*pedersen_NI, encoding=enc_GXpt):
        print("Pedersen commitment verified on the signer side. Signing...")
    
    w = signer.w
    A,e,s2 = signer.sign()
    print("Done signing..")
    s = s1+s2
    #sign takes no additional argument since we already gave the verifier object (included the LHS = the actual Pedersen commitment to the signer)

    if verify_signature(A,e,s, w, generators, h0, messages) :
        print ("Signature verified!")
        return True
    return False

class SignatureProof(Proof):
    """
    Proof of knowledge of a (A,e,s) signature over a set of messages.
    """
    def __init__(self, signer:Signer):
        """
        Instantiates a Signature Proof which is an enhanced version of AndProof allowing to access additional parameters
        """
        #preprocess all is needed for the signature PK
        self.generators = signer.generators
        self.h0 = signer.h0
        self.w = signer.w



    def get_prover(self, secret_dict, A):
        prov = SignatureProver(None)
        A1,A2 = prov.precommit(self.generators, A)

        self.andproof = build_pi5(A1, A2)

        andprover = self.andproof.get_prover(secret_dict)
        prov.__init__(andprover)
        return prov
    
    def get_verifier(self):
        return SignatureVerifier(self.andproof.get_verifier())


    def build_pi5(self, A1, A2):
        """
        A template for the proof of knowledge of a signature pi5 detailed on page 7 of the following paper : https://eprint.iacr.org/2008/136.pdf
        It uses group pairings, DLRep and And Proofs.
        public info should be : 
            - w (public key), 
            - h0 (base of the public key), 
            - generators (of length len(m)+2)

        """
        gT = self.h0.gtgroup
        L = len(self.generators)-2
        g0, g1, g2 = self.generators[0], self.generators[1], self.generators[2]
        dl1 = DLRepProof(A1, Secret("r1")*g1 + Secret("r2"*g2))
        dl2 = DLRepProof(gT.infinite(), Secret("delta1")*g1 + Secret("delta2")*g2 + Secret("e")*(-A1))

        signature = AndProof(dl1, dl2)


        gen_pairs = [gT.pair(self.generators[k], self.h0) for k in range(L+2)]

        lhs = gT.pair(A2, w)-gen_pairs[0]
        generators = [-gT.pair(A2, self.h0), gT.pair(self.generators[1], w), gen_pairs[1]]
        generators.extend(gen_pairs[1:])

        self.secret_names = ["e", "r1", "delta1", "s"]
        """
        Notice we replace -e*g by e*(-g) so the system recognizes e as reoccuring secret through subproofs
        """
        for k in range(L):
            self.secret_names.append("m"+str(k+1))
        """
        
        gen_pairs is an array of the form epair(gi, h0)
        generators is the list of elements to multiply i.e all pairings
        secret_names are the exponents (ordered) ie -e, r1, delta1, s, m_i as specified in the protocol
        """

        pairings_proof = DLRepProof(lhs, create_rhs(secret_names, generators))

        return AndProof(signature, pairings_proof)
    #The sigature proof is ready to be used, either with an interactive sigma protocol, 
    # a NI proof or even a simulation (just specify dummy secrets for the proof building and then pass an empty dict to the prover)



class SignatureProver(AndProofProver):
    """TODO: fix. does it inherit from AndProofProver or is it a wrapper?
    """
    def __init__(self, andprover):
        if andprover is None:
            return
        self.andp = andprover
        self.secret_values = andprover.secret_values

    def precommit(generators, A):
        """
        Generate LHS A1, A2 for the signature proof
        """
        self.r1 = generators[0].group.order().random()
        self.r2 = generators[0].group.order().random()
        a1 = generators[1]*r1+generators[2]*r2
        a2 = A+generators[2]*r1
        return a1, a2


class SignatureVerifier(AndProofVerifier):
    pass