"""
see https://www.cypherpunks.ca/~iang/pubs/blacronym-wpes.pdf
"""
from SigmaProtocol import *
from CompositionProofs import *
from DLRep import *
from Subproof import *
import pdb
DEFAULT_ALIASES = ("alpha", "beta")

class InequalityProver(Prover):
    def __init__(self, proof, secret_values):
        self.lhs = proof.lhs
        self.generators = proof.generators #h0,h1
        self.proof = proof
        self.grouporder = self.generators[0].group.order()
        self.aliases = proof.aliases
        self.secret_names = proof.secret_names
        self.secret_values = secret_values

    def commit(self, randomizers_dict = None):
        return self.precommit(), self.embedded_prover.commit(randomizers_dict)

    def precommit(self):
        cur_secret = self.secret_values[self.secret_names[0]]#x
        order = self.generators[0].group.order()
        self.blinder = order.random()
        new_secrets = (cur_secret*self.blinder % self.grouporder, -self.blinder)
        C = self.blinder*(cur_secret*self.generators[1] - self.lhs[1])
        self.embedded_proof = self.proof.update([C])
        self.embedded_dict = dict(zip(self.embedded_proof.secret_names, new_secrets))
        self.embedded_prover = self.embedded_proof.get_prover(self.embedded_dict)
        return [C]

    def get_NI_proof(self, message ='', encoding=None):
        return (self.embedded_proof.precommitment, *super().get_NI_proof())



        

class InequalityProof(Proof):
    def __init__(self, *kwargs):
        """TODO: find an interface and parse lhs and generators
        """
        super().__init__(*kwargs)
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
        return InequalityProver(self, secret_values)

    def get_verifier(self):
        return InequalityVerifier(self)

    def build_and(self, precommitment):
        """Builds the AndProof associated to a InequalityProof.
        """
        precommitment = [self.generators[0].group.infinite()] + precommitment
        p = []
        #pdb.set_trace()
        for i in range(len(precommitment)):
            p.append(DLRepProof(precommitment[i], create_rhs(self.aliases, [self.generators[i], self.lhs[i]])))
        
        self.embedded_proof = AndProof(*p)
        self.embedded_proof.precommitment = precommitment
        return self.embedded_proof

    
    def get_proof_id(self):
        return ["InequalityProof", self.lhs, self.generators, self.embedded_proof.precommitment]

    def recompute_commitment(self, challenge, responses):
        return self.embedded_proof.recompute_commitment(challenge, responses)




class InequalityVerifier(Verifier):
    def __init__(self, proof):
        self.proof =proof
        self.lhs = proof.lhs
        self.generators = proof.generators
        self.secret_names = proof.secret_names
        self.aliases = proof.aliases

    def process_precommitment(self, precommitment):
        self.embedded_proof = self.proof.update(precommitment, new_aliases)
        self.embedded_verifier = self.embedded_proof.get_verifier()

    def send_challenge(self, com):
        precom, self.commitment = com[0], com[1]
        self.process_precommitment(precom)
        self.challenge = self.embedded_verifier.send_challenge(com)
        return self.challenge


    def verify(self, response, commitment=None,
            challenge=None):
        self.response = response
        
        return self.check_unity() and self.embedded_verifier.verify(responses, commitment, challenge)

    def verify_NI(self, challenge, response, precommitment, message='', encoding=None):
        return self.check_unity() and super().verify_NI(challenge, response, message, encoding)

    def check_unity(self):
        for el in self.embedded_proof.precommitment[1:]:
            if el == self.generators.group.infinite():
                return False
        return True
