"""
see https://www.cypherpunks.ca/~iang/pubs/blacronym-wpes.pdf
"""
from SigmaProtocol import *
from CompositionProofs import *
from DLRep import *
from Subproof import *
import pdb
DEFAULT_ALIASES = ("alpha_", "beta_")

def generate_aliases():
    nb1, nb2 = chal_randbits(), chal_randbits()
    return DEFAULT_ALIASES[0]+nb1.hex(), DEFAULT_ALIASES[1]+nb2.hex()

class DLRepNotEqualProof(Proof):
    def __init__(self, valid_tuple, invalid_tuple, secret_names):
        """
        Takes (H0,h0), (H1,h1), ["x"] such that H0 = x*h0 and H1 != x*h1.
        All arguments should be iterable.
        """
        if len(valid_tuple) != 2 or len(invalid_tuple) != 2:
            raise Exception("Wrong parameters for DLRepNotEqualProof")
        self.aliases = generate_aliases()
        self.lhs = [valid_tuple[0], invalid_tuple[0]]
        self.generators = [valid_tuple[1], invalid_tuple[1]]
        self.secret_names = secret_names
        self.simulate = False
        
    def update(self, precommitment):
        return self.build_and(precommitment)

    def get_prover(self, secret_values):
        if self.simulate:
            secret_values={}
        return DLRepNotEqualProver(self, secret_values)

    def get_verifier(self):
        return DLRepNotEqualVerifier(self)

    def build_and(self, precommitment):
        """Builds the AndProof associated to a DLRepNotEqualProof.
        """
        precommitment = [self.generators[0].group.infinite()] + precommitment
        p = []
        for i in range(len(precommitment)):
            p.append(DLRepProof(precommitment[i], create_rhs(self.aliases, [self.generators[i], self.lhs[i]])))
        
        self.constructed_proof = AndProof(*p)
        self.constructed_proof.precommitment = precommitment
        return self.constructed_proof

    
    def get_proof_id(self):
        return ["DLRepNotEqualProof", self.lhs, self.generators, self.constructed_proof.precommitment]

    def recompute_commitment(self, challenge, responses):
        """
        Recomputes the commitment. Appends the precommitment for consistency in the equality check.
        The precommitment is truncated since we artificially added the infinity point before storing
        it in the constructed internal proof.
        """
        if not self.check_unity():
            """
            This will make any upper equality test to reject the proof
            """
            return None
        return self.constructed_proof.precommitment[1:], self.constructed_proof.recompute_commitment(challenge, responses)

    def check_unity(self):
        for el in self.constructed_proof.precommitment[1:]:
            if el == self.generators[0].group.infinite():
                return False
        return True

class DLRepNotEqualProver(Prover):
    def __init__(self, proof, secret_values):
        self.lhs = proof.lhs
        self.generators = proof.generators #h0,h1
        self.proof = proof
        self.grouporder = self.generators[0].group.order()
        self.secret_names = proof.secret_names
        self.aliases = proof.aliases
        self.secret_values = secret_values

    def commit(self, randomizers_dict = None):
        """
        Triggers the inside prover commit. Drops the randomizer dict which was drawn for the "official" 
        secret name which we never use plain
        """
        return self.precommit(), self.constructed_prover.commit()


    def precommit(self):
        cur_secret = self.secret_values[self.secret_names[0]]
        order = self.generators[0].group.order()
        self.blinder = order.random()
        new_secrets = (cur_secret*self.blinder % self.grouporder, -self.blinder)
        C = self.blinder*(cur_secret*self.generators[1] - self.lhs[1])
        self.constructed_proof = self.proof.update([C])
        self.constructed_dict = dict(zip(self.constructed_proof.secret_names, new_secrets))
        self.constructed_prover = self.constructed_proof.get_prover(self.constructed_dict)
        return [C]

    def compute_response(self, challenge):
        self.challenge = challenge
        self.constructed_prover.challenge=  challenge
        self.response = self.constructed_prover.compute_response(challenge)
        return self.response

    def get_NI_proof(self, message ='', encoding=None):
        return (self.constructed_proof.precommitment, self.constructed_prover.get_NI_proof())




class DLRepNotEqualVerifier(Verifier):
    def __init__(self, proof):
        self.proof =proof
        self.lhs = proof.lhs
        self.generators = proof.generators
        self.secret_names = proof.secret_names
        self.aliases = proof.aliases

    def process_precommitment(self, precommitment):
        self.constructed_proof = self.proof.update(precommitment)
        self.constructed_verifier = self.constructed_proof.get_verifier()

    def send_challenge(self, com):
        precom, self.commitment = com[0], com
        self.process_precommitment(precom)
        self.challenge = self.constructed_verifier.send_challenge(com[1])
        return self.challenge

    def verify_NI(self, challenge, response, precommitment, message='', encoding=None):
        return self.check_unity() and self.constructed_verifier.verify_NI(challenge, response, message, encoding)

    def check_unity(self):
        for el in self.constructed_proof.precommitment[1:]:
            if el == self.generators[0].group.infinite():
                return False
        return True
