from primitives.DLRep import * 
from Subproof import *
from CompositionProofs import *
from SigmaProtocol import *
from BilinearPairings import *
import pdb
import random, string

RD_LENGTH = 30
DEFAULT_SIGALIASES = ["r1_", "r2_", "delta1_", "delta2_"]

def generate_signature_aliases():
    nb1, nb2 = chal_randbits(), chal_randbits()
    return DEFAULT_SIGALIASES[0]+nb1.hex(), DEFAULT_SIGALIASES[1]+nb2.hex(), DEFAULT_SIGALIASES[2]+nb1.hex(), DEFAULT_SIGALIASES[3]+nb2.hex()

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
        Returns a non-interactive proof if zkp parameter is set to true.
        """
        to_sign= create_lhs(self.generators[2:len(messages)+2], messages)
        
        self.s1 = self.generators[0].group.order().random()
        lhs = self.s1*self.generators[1]+ to_sign
        if not zkp:
            return lhs

        #define secret names as s' m1 m2 ...mL
        names = ["s'"] + ["m"+str(i+1) for i in range(len(messages))] 
        secrets = [self.s1] + messages
        rhs = create_rhs(names, self.generators[1:])

        pedersen_proof = DLRepProof(lhs, rhs)
        pedersen_prover = pedersen_proof.get_prover(dict(zip(names, secrets)))
        return lhs, pedersen_prover.get_NI_proof(encoding=enc_GXpt) 


    def obtain_signature(self, presignature):
        """
        S1 is the part of the signature blinding factor which is on the user side
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
        generators =self.generators[:len(messages)+2]
        product = generators[0] + create_lhs(generators[1:], [signature.s]+messages)
        return signature.A.pair(self.w+signature.e*self.h0) == product.pair(self.h0)



class SecretKey:
    def __init__(self, value, keypair):
        self.generators = keypair.generators
        self.henerators = keypair.henerators
        self.h0 = self.henerators[0]
        self.group = self.h0.group
        self.gamma = value

    def sign(self, lhs):
        """
        Signs a committed message Cm ie returns A,e,s such that A = (g0 + s*g1 + Cm) * 1/e+gamma
        """
        pedersen_product = lhs
        e = self.group.order().random()
        s2 = self.group.order().random()
        prod = self.generators[0]+s2*self.generators[1]+pedersen_product
        A = (self.gamma+e).mod_inverse(self.group.order())*prod
        return Signature(A,e,s2)

def verify_blinding(NIproof, lhs, generators, nb_messages):
    """
    Prototypes a ZK proof for the Pedersen commitment to messages and uses it to
    verify the non-interactive proof passed as argument.
    """
    generators = generators[1:nb_messages+2]
    secret_names = ["s'"] + ["m"+str(i+1)for i in range (len(generators))]
    proof = DLRepProof(lhs, create_rhs(secret_names, generators))
    return proof.get_verifier().verify_NI(*NIproof, encoding=enc_GXpt)



class SignatureProof(Proof):
    """
    Proof of knowledge of a (A,e,s) signature over a set of messages.
    """
    def __init__(self, signature, secret_names, pk):
        """
        Instantiates a Signature Proof which is an enhanced version of AndProof allowing to access additional parameters
        secret_names should be the alias for signature.e, the alias for signature.s, and the aliases for the messages.
        """
        self.generators = pk.generators[:len(secret_names)+2]
        self.h0 = pk.h0
        self.w = pk.w
        self.aliases = generate_signature_aliases()
        self.signature = signature
        self.secret_names = secret_names


    def build_constructed_proof(self, A1, A2):
        """
        A template for the proof of knowledge of a signature pi5 detailed on page 7 of the following paper : https://eprint.iacr.org/2008/136.pdf
        It uses group pairings, DLRep and And Proofs.
        public info should be : 
            - w (public key), 
            - h0 (base of the public key), 
            - generators (of length len(m)+2)

        """
        rhs = create_rhs(self.aliases + self.secret_names)
        gT = self.h0.gtgroup
        g0, g1, g2 = self.generators[0], self.generators[1], self.generators[2]
        dl1 = DLRepProof(A1, Secret(self.aliases[0])*g1 + Secret(self.aliases[1]*g2))
        dl2 = DLRepProof(gT.infinite(), Secret(self.aliases[2])*g1 + Secret(self.aliases[3])*g2 + Secret(self.secret_names[0])*(-A1))

        signature = AndProof(dl1, dl2)

        gen_pairs = [g.pair(self.h0) for g in self.generators]
        self.pair_lhs = A2.pair(self.w)-gen_pairs[0]
        generators = [-(A2.pair(self.h0)), self.generators[2].pair(w), gen_pairs[2]]
        generators.extend(gen_pairs[2:])

        # Build secret names [e, r1, delta1, s, m_i]
        new_secret_names = self.secret_names[:1] + [self.aliases[0], self.aliases[2]] + self.secret_names[1:]
        pairings_proof = DLRepProof(self.pair_lhs, create_rhs(secret_names, generators))
        
        self.constructed_proof =  AndProof(signature, pairings_proof)

    def get_prover(self, secret_values):
        if self.simulate:
            secret_values={}
        return SignatureProver(self, secret_values)

    def get_proof_id(self):
        return ["SignatureProof", self.generators, self.A1, self.A2, self.pair_lhs]

        

class SignatureProver(Prover):
    def __init__(self, proof, secret_values):
        self.generators = proof.generators 
        self.proof = proof
        self.secret_names = proof.secret_names
        self.aliases = proof.aliases
        self.secret_values = secret_values

    def commit(self, randomizers_dict = None):
        """
        Triggers the inside prover commit. Transfers the randomizer dict coming from above.
        """
        if self.blinder is None:
            raise Exception("Please precommit before commiting, else proofs lack parameters")
        return self.constructed_prover.commit(randomizers_dict)


    def precommit(self):

        r1, r2 = self.generators[0].group.order.random(), self.generators[0].group.order.random()
        delta1, delta2 = r1*self.signature.e, r2*self.signature.e
        A1 = r1*self.generators[1]+ r2*self.generators[2]
        A2 = r1*self.generators[2]+self.signature.A
        self.precommitment = [A1, A2]
        self.constructed_proof = self.proof.build_constructed_proof(self.precommitment)
        self.constructed_dict = dict(zip(self.constructed_proof.secret_names, [new_secrets]))
        if self.proof.binding:
            self.constructed_dict.update(self.secret_values)
        self.constructed_prover = self.constructed_proof.get_prover(self.constructed_dict)
        return self.precommitment

    def compute_response(self, challenge):
        self.challenge = challenge
        self.constructed_prover.challenge=  challenge
        self.response = self.constructed_prover.compute_response(challenge)
        return self.response




class SignatureVerifier(AndProofVerifier):
    pass
