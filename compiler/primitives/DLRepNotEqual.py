"""
see https://www.cypherpunks.ca/~iang/pubs/blacronym-wpes.pdf
"""
from Abstractions import *
from CompositionProofs import *
from primitives.DLRep import *
import pdb

DEFAULT_ALIASES = ("alpha_", "beta_")


def generate_DLRNE_aliases():
    nb1, nb2 = chal_randbits(), chal_randbits()
    return DEFAULT_ALIASES[0] + nb1.hex(), DEFAULT_ALIASES[1] + nb2.hex()


class DLRepNotEqualProof(Proof):
    def __init__(self, valid_tuple, invalid_tuple, secret_names, binding=False):
        """
        Takes (H0,h0), (H1,h1), ["x"] such that H0 = x*h0 and H1 != x*h1.
        All these arguments should be iterable.
        """
        if len(valid_tuple) != 2 or len(invalid_tuple) != 2:
            raise Exception("Wrong parameters for DLRepNotEqualProof")
        self.aliases = generate_DLRNE_aliases()
        self.lhs = [valid_tuple[0], invalid_tuple[0]]
        self.generators = [valid_tuple[1], invalid_tuple[1]]
        self.secret_names = secret_names
        self.simulate = False
        self.binding = binding
        self.constructed_proof = None

    def get_prover(self, secret_values={}):
        if self.simulate:
            secret_values = {}
        return DLRepNotEqualProver(self, secret_values)

    def get_verifier(self):
        return DLRepNotEqualVerifier(self)

    def build_constructed_proof(self, precommitment):
        """Builds the AndProof associated to a DLRepNotEqualProof.
        """
        new_lhs = [self.generators[0].group.infinite()] + precommitment
        p = []
        for i in range(len(new_lhs)):
            p.append(
                DLRepProof(
                    new_lhs[i],
                    create_rhs(self.aliases, [self.generators[i], self.lhs[i]]),
                )
            )
        if self.binding:
            p.append(
                DLRepProof(
                    self.lhs[0], Secret(self.secret_names[0]) * self.generators[0]
                )
            )
        self.constructed_proof = AndProof(*p)
        self.constructed_proof.lhs = new_lhs 
        return self.constructed_proof

    def get_proof_id(self):
        st = [
            "DLRepNotEqualProof",
            self.constructed_proof.generators,
            self.constructed_proof.lhs,
        ]
        if self.binding:
            st.append(self.constructed_proof.subproofs[2].get_proof_id())
        return st

    def recompute_commitment(self, challenge, responses):
        """
        Recomputes the commitment. 
        """
        return self.constructed_proof.recompute_commitment(challenge, responses)

    def get_simulator(self):
        return DLRepNotEqualProver(self, {})


class DLRepNotEqualProver(Prover):
    def __init__(self, proof, secret_values):
        self.proof = proof
        self.secret_values = secret_values

    def commit(self, randomizers_dict=None):
        """
        Triggers the inside prover commit. Transfers the randomizer dict coming from above, which will be
        used if the binding of the proof is set True.
        """
        if self.proof.constructed_proof is None:
            raise Exception(
                "Please precommit before commiting, else proofs lack parameters"
            )
        return self.constructed_prover.commit(randomizers_dict)

    def precommit(self):
        cur_secret = self.secret_values[self.proof.secret_names[0]]
        self.blinder = self.proof.generators[0].group.order().random()
        new_secrets = (
            cur_secret * self.blinder % self.proof.generators[0].group.order(),
            -self.blinder % self.proof.generators[0].group.order(),
        )
        self.precommitment = [
            self.blinder * (cur_secret * self.proof.generators[1] - self.proof.lhs[1])
        ]
        self.proof.build_constructed_proof(self.precommitment)
        self.constructed_dict = dict(zip(self.proof.aliases, new_secrets))
        if self.proof.binding:
            self.constructed_dict.update(self.secret_values)
        self.constructed_prover = self.proof.constructed_proof.get_prover(
            self.constructed_dict
        )
        return self.precommitment

    def compute_response(self, challenge):
        self.challenge = challenge
        self.constructed_prover.challenge = challenge
        self.response = self.constructed_prover.compute_response(challenge)
        return self.response

    def simulate_proof(self, responses_dict=None, challenge=None):
        group = self.proof.generators[0].group
        lhs = [group.order().random()* group.generator()]
        self.proof.build_constructed_proof(lhs)
        self.constructed_prover = self.proof.constructed_proof.get_prover()
        tr = self.constructed_prover.simulate_proof(responses_dict, challenge)
        tr.precommitment = lhs
        return tr


class DLRepNotEqualVerifier(Verifier):
    """ A wrapper for an AndVerifier such that the proof can be initialized without the full information.
    """

    def __init__(self, proof):
        self.proof = proof

    def process_precommitment(self, precommitment):
        self.proof.build_constructed_proof(precommitment)
        self.constructed_verifier = self.proof.constructed_proof.get_verifier()

    def send_challenge(self, com):
        self.commitment = com
        self.challenge = self.constructed_verifier.send_challenge(com)

        return self.challenge

    def check_adequate_lhs(self):
        for el in self.proof.constructed_proof.lhs[1:]:
            if el == self.proof.generators[0].group.infinite():
                return False
        return True

    def check_responses_consistency(self, response, response_dict):
        return self.constructed_verifier.check_responses_consistency(
            response, response_dict
        )
