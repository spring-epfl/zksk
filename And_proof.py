from SigmaProtocol import *
from petlib.bn import Bn


AndProofCommitment = list
AndProofResponse = list
AndProofChallenge = Bn


class AndProofProver(Prover):
    """
    """
    def __init__(self, subprovers):
        self.subs = subprovers.copy()

        self.generators = get_generators(subprovers)
        self.secret_names = get_secret_names(subprovers)


    def get_randomizers(self) -> dict:  #Creates a dictionary of randomizers by querying the subproofs dicts and merging them
        random_vals = {}
        {random_vals.update(subp.get_randomizers().copy()) for subp in self.subs}
        return random_vals

    def commit(self, randomizers_dict=None) -> AndProofCommitment:
        if randomizers_dict is None:
            randomizers_dict = self.get_randomizers()
        self.commitment =  []
        for subp in self.subs:
            self.commitment.append(subp.commit(randomizers_dict = randomizers_dict))
        return self.commitment
        
    def compute_response(self, challenge: AndProofChallenge
                        ) -> AndProofResponse:  #r = secret*challenge + k
        return [subp.compute_response(challenge) for subp in self.subs]

    def simulate_proof(self, responses_dict = None, challenge = None):
        if responses_dict is None:
            responses_dict = self.get_randomizers() 
        if challenge is None:
            challenge = chal_128bits()
        com = []
        resp = []
        for subp in self.subs:
            com1, __, resp1 = subp.simulate_proof(responses_dict, challenge)
            com.append(com1)
            resp.append(resp1)
        return commitment, challenge, resp
        
        


class AndProofVerifier(Verifier):
    def __init__(self, subverifiers):
        self.subs = subverifiers.copy()
        
        self.generators = get_generators(subverifiers)
        self.secret_names = get_generators(subverifiers)

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
    def __init__(self, *subproofs):
        """The AndProof(subproof_list = None, *subproofs = None) can take an arbitrary number of proofs. 
        Arguments can also be lists of proofs, but not lists of lists."""
        if not subproofs:
            raise Exception('AndProof needs arguments !')
        list_subproofs = []
        for el in subproofs:
            if isinstance(el, list):
                list_subproofs.extend(el)
            else:
                list_subproofs.append(el)

        self.subproofs = list_subproofs

        self.generators = get_generators(self.subproofs)
        self.secret_names = get_secret_names(self.subproofs)
        self.simulate = False
        check_groups(self.secret_names, self.generators)
    
    def recompute_commitment(self, challenge, andresp : AndProofResponse):
        """This function allows to retrieve the commitment generically. For this purpose 
        the names of the sub-objects of AndVerifier and AndProver should be the same.
        """
        comm = []
        for i in range(len(self.subs)):
            cur_proof = self.subs[i]
            comm.append(cur_proof.recompute_commitment(cur_proof, challenge, andresp[i]))
        return comm

    def get_prover(self, secrets_dict):
        def sub_proof_prover(sub_proof):
            keys = set(sub_proof.secret_names.copy())
            secrets_for_prover = []
            for s_name in secrets_dict:
                if s_name in keys:
                    secrets_for_prover.append((s_name, secrets_dict[s_name]))
            return sub_proof.get_prover(dict(secrets_for_prover))

        return AndProofProver([sub_proof_prover(subproof) for subproof in self.subproofs])

    def get_verifier(self):
        return AndProofVerifier([subp.get_verifier() for subp in self.subproofs])

    def get_simulator(self):
        return [subp.get_simulator() for subp in self.subproofs]

    def set_simulate(self):
        self.simulate = True

