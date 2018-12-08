from SigmaProtocol import *
from petlib.bn import Bn


class AndProofCommitment:
    def __init__(self, commitment1, commitment2):
        self.commitment1 = commitment1
        self.commitment2 = commitment2

    def __eq__(self, other):
        return (self.commitment1==other.commitment1) and (self.commitment2 == other.commitment2)

AndProofChallenge = Bn

class AndProofResponse:
    def __init__(self, response1, response2):
        self.response1 = response1
        self.response2 = response2


class AndProofProver(Prover):
    def __init__(self, prover1, prover2):
        self.prover1 = prover1
        self.prover2 = prover2

        #A hack
        self.proof1 = prover1
        self.proof2 = prover2

        self.generators = AndProof.get_generators(self)
        self.secret_names = AndProof.get_secret_names(self)

        self.set_simulate = False

    def get_randomizers(self) -> dict:  #Creates a dictionary of randomizers by querying the subproofs dicts and merging them
        random_vals = self.prover1.get_randomizers().copy()
        random_vals.update(self.prover2.get_randomizers().copy())
        return random_vals

    def commit(self, randomizers_dict=None) -> AndProofCommitment:
        if randomizers_dict is None:
            randomizers_dict = self.get_randomizers()
        self.commitment =  AndProofCommitment(
            self.prover1.commit(randomizers_dict=randomizers_dict),
            self.prover2.commit(randomizers_dict=randomizers_dict))
        return self.commitment
        
    def compute_response(self, challenge: AndProofChallenge
                        ) -> AndProofResponse:  #r = secret*challenge + k
        return AndProofResponse(
            self.prover1.compute_response(challenge),
            self.prover2.compute_response(challenge))

    def simulate_proof(self, responses_dict = None, challenge = None):
        if responses_dict is None:
            responses_dict = self.get_randomizers() 
        if challenge is None:
            challenge = chal_128bits()
        self.recompute_commitment = AndProof.recompute_commitment


        com1, __, resp1 = self.prover1.simulate_proof(responses_dict, challenge)
        com2, __, resp2 = self.prover2.simulate_proof(responses_dict, challenge)
        commitment = AndProofCommitment(com1, com2)
        resp = AndProofResponse(resp1, resp2)
        return commitment, challenge, resp
        
        


class AndProofVerifier(Verifier):
    def __init__(self, verifier1, verifier2):
        self.verifier1 = verifier1
        self.verifier2 = verifier2
       
        #A hack
        self.proof1 = verifier1
        self.proof2 = verifier2
        
        self.generators = AndProof.get_generators(self)
        self.secret_names = AndProof.get_secret_names(self)

        self.recompute_commitment = AndProof.recompute_commitment
        


class Proof:
    def __and__(self, other):
        return AndProof(self, other)

    def get_prover(self, secrets_dict):
        pass

    def get_verifier(self):
        pass

    def recompute_commitment(self):
        pass


class AndProof(Proof):
    def __init__(self, proof1, proof2):
        self.proof1 = proof1
        self.proof2 = proof2

        self.generators = self.get_generators()
        self.secret_names = self.get_secret_names()
        check_groups(self.secret_names, self.generators)
    
    def get_secret_names(self):
        secrets = self.proof1.secret_names.copy()
        secrets.extend(self.proof2.secret_names.copy())
        return secrets

    def get_generators(self):
        generators = self.proof1.generators.copy()
        generators.extend(self.proof2.generators.copy())
        return generators

    def recompute_commitment(self, challenge, andresp : AndProofResponse):
        c1 = self.proof1.recompute_commitment(self.proof1, challenge, andresp.response1)
        c2 = self.proof2.recompute_commitment(self.proof2, challenge, andresp.response2)
        return AndProofCommitment(c1, c2)

    def get_prover(self, secrets_dict):
        def sub_proof_prover(sub_proof):
            keys = set(sub_proof.secret_names.copy())
            secrets_for_prover = []
            for s_name in secrets_dict:
                if s_name in keys:
                    secrets_for_prover.append((s_name, secrets_dict[s_name]))
            return sub_proof.get_prover(dict(secrets_for_prover))

        prover1 = sub_proof_prover(self.proof1)
        prover2 = sub_proof_prover(self.proof2)
        return AndProofProver(prover1, prover2)

    def get_verifier(self):
        return AndProofVerifier(self.proof1.get_verifier(),
                                self.proof2.get_verifier())

    def get_simulator(self):
        return AndProofProver(self.proof1.get_simulator(), self.proof2.get_simulator())


