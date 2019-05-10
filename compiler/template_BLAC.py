"""
see https://www.cypherpunks.ca/~iang/pubs/blacronym-wpes.pdf
"""
from SigmaProtocol import *
from CompositionProofs import *
from DLRep import *
from Subproof import *
import pdb
DEFAULT_ALIASES = ("alpha", "beta")


class DLRepNotEqualProof(Proof):
    def __init__(self):
        """TODO: find an interface and parse lhs and generators
        """
        self.aliases = DEFAULT_ALIASES


    def initialize(self, lhs_array, generators, secret_names):
        self.lhs = lhs_array
        self.generators = generators
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
        #pdb.set_trace()
        for i in range(len(precommitment)):
            p.append(DLRepProof(precommitment[i], create_rhs(self.aliases, [self.generators[i], self.lhs[i]])))
        
        self.constructed_proof = AndProof(*p)
        self.constructed_proof.precommitment = precommitment
        return self.constructed_proof

    
    def get_proof_id(self):
        return ["DLRepNotEqualProof", self.lhs, self.generators, self.constructed_proof.precommitment]

    def recompute_commitment(self, challenge, responses):
        return self.constructed_proof.recompute_commitment(challenge, responses)


class DLRepNotEqualProver(Prover):
    def __init__(self, proof, secret_values):
        self.lhs = proof.lhs
        self.generators = proof.generators #h0,h1
        self.proof = proof
        self.grouporder = self.generators[0].group.order()
        self.aliases = proof.aliases
        self.secret_names = proof.secret_names
        self.secret_values = secret_values

    def commit(self, randomizers_dict = None):
        return self.precommit(), self.constructed_prover.commit(randomizers_dict)

    def precommit(self):
        cur_secret = self.secret_values[self.secret_names[0]]#x
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
        precom, self.commitment = com[0], com[1]
        self.process_precommitment(precom)
        self.challenge = self.constructed_verifier.send_challenge(com)
        return self.challenge


    def verify(self, response, commitment=None,
            challenge=None):
        if commitment:
            self.commitment = commitment
        self.response = response
        return self.check_unity() and self.constructed_verifier.verify(response, self.commitment, challenge)

    def verify_NI(self, challenge, response, precommitment, message='', encoding=None):
        return self.check_unity() and self.constructed_verifier.verify_NI(challenge, response, message, encoding)

    def check_unity(self):
        for el in self.constructed_proof.precommitment[1:]:
            if el == self.generators[0].group.infinite():
                return False
        return True