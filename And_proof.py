from SigmaProtocol import *
from petlib.bn import Bn


AndProofCommitment = list
AndProofResponse = list
AndProofChallenge = Bn


class AndProofProver(Prover):
    """:param subprovers: instances of Prover"""
    def __init__(self, subprovers):
        self.subs = subprovers.copy()

        self.generators = get_generators(subprovers)
        self.secret_names = get_secret_names(subprovers)


    def get_randomizers(self) -> dict: 
        """Creates a dictionary of randomizers by querying the subproofs dicts and merging them"""
        random_vals = {}
        {random_vals.update(subp.get_randomizers().copy()) for subp in self.subs}
        return random_vals

    def commit(self, randomizers_dict=None) -> AndProofCommitment:
        """:return: a AndProofCommitment instance from the commitments of the subproofs encapsulated by this and-proof"""
        if randomizers_dict is None:
            randomizers_dict = self.get_randomizers()
        self.commitment =  []
        for subp in self.subs:
            self.commitment.append(subp.commit(randomizers_dict = randomizers_dict))
        return self.commitment
        
    def compute_response(self, challenge: AndProofChallenge
                        ) -> AndProofResponse:  
        """:return: the list (of type AndProofResponse) containing the subproofs responses"""#r = secret*challenge + k
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
        return com, challenge, resp
        
        


class AndProofVerifier(Verifier):
    def __init__(self, subverifiers):
        """
        :param subverifiers: instances of subtypes of Verifier
        """

        self.subs = subverifiers.copy()
        
        self.generators = get_generators(subverifiers)
        self.secret_names = get_secret_names(subverifiers)

        self.recompute_commitment = AndProof.recompute_commitment
        


class Proof:
    """an abstraction of a sigma protocol proof"""
    def __and__(self, other):
        """
        :return: an AndProof from this proof and the other proof using the infix '&' operator
        """
        return AndProof(self, other)

    def __or__(self, other):
        """
        :return: an OrProof from this proof and the other proof using the infix '|' operator
        """
        return OrProof(self, other)

    def get_prover(self, secrets_dict):
        """
        :param: secrets_dict: a mapping from secret names to secret values
        :return: an instance of Prover"""
        pass

    def get_verifier(self):
        """:return: an instance of Verifier"""
        pass

    def recompute_commitment(self, challenge, response):
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
        self.check_or_flaw()

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
        if self.simulate == True or secrets_dict == {}:
            print('Can only simulate')
            return get_simulator()
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
        """ Returns an empty prover which can only simulate (via simulate_proof)
        """
        arr = [subp.get_simulator() for subp in self.subproofs]
        return AndProofProver(arr)

    def set_simulate(self):
        self.simulate = True
        
    def check_or_flaw(self, forbidden_secrets= []): #TODO : test this when OrProof is finished
        """ Checks for appearance of the following scheme : And(Or, x) where at least one secret is shared between x and Or.
            Raises an error if finds any."""
        for subp in self.subproofs:
            if "Or" in subp.__class__.__name__ :
                if any(x in subp.secret_names for x in forbidden_secrets):
                    raise Exception("Or flaw detected. Aborting. Try to flatten the proof to  \
                        avoid shared secrets inside and outside an Or")
                for other_sub in self.subproofs:
                    if any(set(subp.secret_names)&set(other_sub.secret_names)):
                        raise Exception("Or flaw detected. Aborting. Try to flatten the proof to  \
                        avoid shared secrets inside and outside an Or")
            elif "And" in subp.__class__.__name__ :
                fb  = subp.secret_names.copy()
                forbidden_secrets.extend(fb)
                subp.check_or_flaw(forbidden_secrets)
