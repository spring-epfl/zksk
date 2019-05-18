from primitives.DLRep import * 
from Subproof import *
from CompositionProofs import *
from SigmaProtocol import *
from BilinearPairings import *
import pdb
import random, string

RD_LENGTH = 30

class Signature:
    def __init__(self, A, e, s):
        self.A = A
        self.e = e
        self.s = s

class SignatureCreator:
    def __init__(self, pk):
        self.generators = pk.generators
        self.h0 = pk.h0
        self.pk = pk
        self.s1 = None

    def commit(self, messages, zkp=False):
        """
        Prepare a pedersen commitment for the correct construction of the sequence to be signed.
        Returns a non-interactive proof as well as a verifier object able to verify the said proof.
        """
        to_sign= create_rhs(self.generators[2:len(messages)+2], messages)
        
        self.s1 = self.generators[0].group.order().random()
        cmessages = self.s1*self.generators[1]+ to_sign
        if not zkp:
            return cmessages

        #define secret names as s' m1 m2 ...mL
        names = ["s'"] + ["m"+str(i+1) for i in range(len(messages))] 
        secrets = [self.s1] + messages

        pedersen_proof = DLRepProof(cmessages, to_sign)
        pedersen_prover = pedersen_proof.get_prover(dict(zip(names, secrets)))
        return cmessages, pedersen_prover.get_NI_proof(encoding=enc_GXpt) 


    def obtain_signature(self, presignature):
        """
        State is the part of the signature which is on the user side
        """
        A, e, s = presignature.A, presignature.e, presignature.s + self.s1
        return Signature(A,e,s)



class KeyPair:
    def __init__(self, bilinearpair, length):
        """
        length should be an upperbound on the number of messages
        """

        self.generators = []
        self.henerators = []
        g = bilinearpair.G1.generator()
        h = bilinearpair.G2.generator()
        order = bilinearpair.G1.order()
        for i in range(length+2):
            randWord = ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(RD_LENGTH))
            self.generators.append(bilinearpair.G1.hash_to_point(randWord.encode("UTF-8")))
        self.henerators.append(bilinearpair.G2.generator())

        self.sk = SecretKey(order.random(), self)
        self.pk = PublicKey(self.sk.gamma*self.henerators[0], self.generators, self.henerators)
        self.sk.pk = self.pk

class PublicKey:
    def __init__(self, w, generators, henerators):
        self.w = w
        self.generators = generators
        self.henerators = henerators
        self.h0 = self.henerators[0]

    def verify_signature(self, signature, messages):
        generators =self.generators[:len(messages)+1]
        product = generators[0] + create_lhs(generators[1:], [signature.s]+messages)
        return signature.A.pair(self.w+signature.e*self.h0) == product.pair(self.h0)



class SecretKey:
    def __init__(self, value, keypair):
        self.generators = keypair.generators
        self.henerators = keypair.henerators
        self.h0 = self.henerators[0]
        self.group = self.h0.group
        self.gamma = value

    def sign(self, cmessages):
        """
        Signs a committed message Cm ie returns A,e,s such that A = (g0 + s*g1 + Cm) * 1/e+gamma
        >>> G = BilinearGroupPair()
        >>> gens = [2,3,4]*G.G1.generator()
        >>> hens = [2,3,4]*G.G2.generator()
        >>> pk, sk = gen_keys(gens, hens)

        >>> A,e,s2 = s.sign()
        >>> (e + s.gamma)*A == self.verifier.lhs
        True
        """
        pedersen_product = cmessages
        e = self.group.order().random()
        s2 = self.group.order().random()
        prod = self.generators[0]+s2*self.generators[1]+pedersen_product
        A = (self.gamma+e).mod_inverse(self.group.order())*prod
        return Signature(A,e,s2)

def verify_proof(self, NIproof, lhs, generators):
    """
    Prototypes a ZK proof for the Pedersen commitment to messages and uses it to
    verify the non-interactive proof passed as argument.
    """
    secret_names = ["s1"] + ["m"+str(i+1)for i in range (len(generators)-2)]
    proof = DLRepProof(lhs, create_rhs(secret_names, generators[1:]))
    return proof.get_verifier().verify_NI(*NIproof, encoding=enc_GXpt)



class SignatureProof(Proof):
    """
    Proof of knowledge of a (A,e,s) signature over a set of messages.
    """
    def __init__(self, pk, sk):
        """
        Instantiates a Signature Proof which is an enhanced version of AndProof allowing to access additional parameters
        """
        #preprocess all is needed for the signature PK
        self.generators = pk.generators
        self.h0 = pk.h0
        self.w = pk.w


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