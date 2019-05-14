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
    def __init__(self, valid_tuple, invalid_tuple, secret_names, binding=False):
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
        self.binding = binding
        
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
        if self.binding:
            p.append(DLRepProof(self.lhs[0], Secret(self.secret_names[0])*self.generators[0]))
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
        self.blinder = None

    def commit(self, randomizers_dict = None):
        """
        Triggers the inside prover commit. Transfers the randomizer dict coming from above, which will be
        used if the binding of the proof is set True.
        """
        if self.blinder is not None:
            #We have already built our constructed proof. Only commit.
            return self.precommitment, self.constructed_prover.commit(randomizers_dict)
        return self.precommit(), self.constructed_prover.commit(randomizers_dict)


    def precommit(self):
        cur_secret = self.secret_values[self.secret_names[0]]
        self.blinder = self.grouporder.random()
        new_secrets = (cur_secret*self.blinder % self.grouporder, -self.blinder)
        self.precommitment = [self.blinder*(cur_secret*self.generators[1] - self.lhs[1])]
        self.constructed_proof = self.proof.update(self.precommitment)
        self.constructed_dict = dict(zip(self.constructed_proof.secret_names, new_secrets))
        if self.proof.binding:
            self.constructed_dict.update(self.secret_values)
        self.constructed_prover = self.constructed_proof.get_prover(self.constructed_dict)
        return self.precommitment

    def compute_response(self, challenge):
        self.challenge = challenge
        self.constructed_prover.challenge=  challenge
        self.response = self.constructed_prover.compute_response(challenge)
        return self.response

    def get_NI_proof(self, message ='', encoding=None):
        precommitment = self.precommit()
        return (*self.constructed_prover.get_NI_proof(), precommitment)




class DLRepNotEqualVerifier(Verifier):
    """ A wrapper for an AndVerifier such that the proof can be initialized without the full information.
    The check_responses_consistency method is not overriden there since secrets are always different.
    """
    def __init__(self, proof):
        self.proof =proof
        self.lhs = proof.lhs
        self.generators = proof.generators
        self.secret_names = proof.secret_names
        self.aliases = proof.aliases

    def process_precommitment(self, commitment):
        if len(commitment)>1:
            #commitment is (precommitment, actual_commitment)
            self.constructed_proof = self.proof.update(commitment[0])
        elif len(commitment) ==1 :
            # commitment is only a precommitment
            self.constructed_proof = self.proof.update(commitment)
        self.constructed_verifier = self.constructed_proof.get_verifier()

    def send_challenge(self, com):
        self.commitment = com
        self.process_precommitment(com)
        self.challenge = self.constructed_verifier.send_challenge(com[1])

        return self.challenge

    def verify_NI(self, challenge, response, precommitment, message='', encoding=None):
        self.process_precommitment(precommitment)
        return self.check_unity() and self.constructed_verifier.verify_NI(challenge, response, message = message, encoding=encoding)

    def check_unity(self):
        for el in self.constructed_proof.precommitment[1:]:
            if el == self.generators[0].group.infinite():
                return False
        return True

    def check_responses_consistency(self, response, response_dict):
        return self.constructed_verifier.check_responses_consistency(response, response_dict)
