#!/usr/bin/python3
from SigmaProtocol import *
from DLRep import *


class OrProver(Prover): # This prover is built on two subprovers, max one of them is a simulator

    def __init__(self, subprovers):
        self.subs = subprovers.copy()

        self.generators = get_generators(subprovers)
        self.secret_names = get_secret_names(subprovers)


    def find_legit_prover(self):
        for subprover in self.subs:
            is self.subs


    def get_randomizers(self) -> dict:  #Creates a dictionary of randomizers by querying the subproofs dicts and merging them
        random_vals = {}
        {random_vals.update(subp.get_randomizers().copy()) for subp in self.subs}
        return random_vals

    def commit(self, randomizers_dict=None):
        if randomizers_dict is None:
            randomizers_dict = self.get_randomizers()
        

    def computeResponse(self, challenge1):
        return (self.p1.computeResponse(challenge1), self.response2)


class OrVerifier(Verifier):
    def __init__(self, or_verifier1: Verifier, or_verifier2: Verifier):
        self.or_verifier1 = or_verifier1
        self.or_verifier2 = or_verifier2

    def sendChallenge(self, commitment1, public_info1):
        return self.or_verifier1.sendChallenge(commitment1, public_info1)

    def verify(self, commitment, challenge, response, public_info):
        commitment1, commitment2 = commitment
        challenge1, challenge2 = challenge
        response1, response2 = response
        (public_info1, public_info2) = public_info
        #in the book there is c = c1 XOR c2 but why do that since c is computed as c = c1 XOR c2 by the prover?
        return self.or_verifier1.verify(
            commitment1, challenge1,
            response1, public_info1) and self.or_verifier2.verify(
                commitment2, challenge2, response2, public_info2)


class OrProof:  
    def __init__(self, *subproofs):
        if not subproofs:
            raise Exception('OrProof needs arguments !')
        list_subproofs = []
        for el in subproofs:
            if isinstance(el, list):
                list_subproofs.extend(el)
            else:
                list_subproofs.append(el)

        self.subproofs = list_subproofs

        self.generators = get_generators(self.subproofs)  #For consistency
        self.secret_names = get_secret_names(self.subproofs)
        self.simulate = False
        check_groups(self.secret_names, self.generators) # For now we consider the same constraints as in the And Proof

    def get_secret_names(self):
        secrets = self.proof1.get_secret_names()
        secrets.extend(self.proof2.get_secret_names())
        return secrets

    def get_generators(self):
        generators = self.proof1.generators.copy()
        generators.extend(self.proof2.generators.copy())
        return generators

    def get_prover(self, secrets_dict):
    """Gets an OrProver which contains a list of the N subProvers, N-1 of which will be simulators.
    """
        def sub_proof_prover(sub_proof):
            keys = set(sub_proof.get_secret_names())
            secrets_for_prover = []
            for s_name in secrets_dict:
                if s_name in keys:
                    secrets_for_prover.append((s_name, secrets_dict[s_name]))
            return sub_proof.get_prover(dict(secrets_for_prover))
        
        for subp in self.s
        

    def get_verifier(self):
        return OrVerifier(self.proof1.get_verifier(),
                                self.proof2.get_verifier())

    def set_simulate(self):
        self.simulate = True


