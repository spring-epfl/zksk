#!/usr/bin/python3
from SigmaProtocol import *
from DLRep import *

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


class OrProver(Prover): # This prover is built on two subprovers, max one of them is a simulator
    def __init__(self, p1: Prover, p2: Prover): 
        self.prover1 = prover1
        self.prover2 = prover2

    def find_legit_prover(self):


    def get_randomizers(self) -> dict:  #Creates a dictionary of randomizers by querying the subproofs dicts and merging them
        random_vals = self.prover1.get_randomizers().copy()
        random_vals.update(self.prover2.get_randomizers().copy())
        return random_vals 

    def commit(self, randomizers_dict=None):
        if randomizers_dict is None:
            randomizers_dict = self.get_randomizers()
        if 

    def computeResponse(self, challenge1):
        return (self.p1.computeResponse(challenge1), self.response2)


class OrProof:
        def __init__(self, proof1, proof2):
        self.proof1 = proof1
        self.proof2 = proof2

        self.group_generators = self.get_generators()  #For consistency
        self.secret_names = self.get_secret_names()
        check_groups(self.secret_names, self.group_generators) # For now we consider the same constraints as in the And Proof

    def get_secret_names(self):
        secrets = self.proof1.get_secret_names()
        secrets.extend(self.proof2.get_secret_names())
        return secrets

    def get_generators(self):
        generators = self.proof1.group_generators.copy()
        generators.extend(self.proof2.group_generators.copy())
        return generators

    def get_prover(self, secrets_dict):
        indicator = 0
        def sub_proof_prover(sub_proof):
            keys = set(sub_proof.get_secret_names())
            secrets_for_prover = []
            for s_name in secrets_dict:
                if s_name in keys:
                    secrets_for_prover.append((s_name, secrets_dict[s_name]))
            return sub_proof.get_prover(dict(secrets_for_prover))
        try:
            prover1 = sub_proof_prover(self.proof1)
        except:         #Ugly for now, should check which error is raised
            indicator +=1
            prover1 = self.proof1.get_simulator()
        try :
            prover2 = sub_proof_prover(self.proof2)
        except: 
            indicator +=1
            prover2 = self.proof2.get_simulator()
        if indicator>1:
            raise Exception("The secrets do not match with any of the Or Proof primitives")
        return OrProver(prover1, prover2)

    def get_verifier(self):
        return OrVerifier(self.proof1.get_verifier(),
                                self.proof2.get_verifier())


