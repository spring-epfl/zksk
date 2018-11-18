from SigmaProtocol import *
from petlib.bn import Bn
from collections import defaultdict


class AndProofCommitment:
    def __init__(self, commitment1, commitment2):
        self.commitment1 = commitment1
        self.commitment2 = commitment2

AndProofChallenge = Bn

class AndProofResponse:
    def __init__(self, response1, response2):
        self.response1 = response1
        self.response2 = response2


class AndProofProver(Prover):
    def __init__(self, prover1, prover2):
        self.prover1 = prover1
        self.prover2 = prover2

    def get_randomizers(self) -> dict:
        random_vals = self.prover1.get_randomizers().copy()
        random_vals.update(self.prover2.get_randomizers().copy())
        return random_vals

    def commit(self, randomizers_dict=None) -> AndProofCommitment:
        if randomizers_dict is None:
            randomizers_dict = self.get_randomizers()
        return AndProofCommitment(
            self.prover1.commit(randomizers_dict=randomizers_dict),
            self.prover2.commit(randomizers_dict=randomizers_dict))

    def computeResponse(self, challenge: AndProofChallenge
                        ) -> AndProofResponse:  #r = secret*challenge + k
        return AndProofResponse(
            self.prover1.computeResponse(challenge),
            self.prover2.computeResponse(challenge))

class AndProofVerifier:
    def __init__(self, verifier1, verifier2):
        self.verifier1 = verifier1
        self.verifier2 = verifier2

    def sendChallenge(self,
                      commitment: AndProofCommitment) -> AndProofChallenge:
        self.commitment = commitment
        self.and_challenge = self.verifier1.sendChallenge(commitment.commitment1)
        return self.and_challenge

    def verify(self, responses: AndProofResponse, commitment: AndProofCommitment = None, challenge: AndProofChallenge = None):
        if challenge is None:
            challenge = self.and_challenge
        if commitment is None:
            commitment = self.commitment
        
        return self.verifier1.verify(
            responses.response1, commitment = commitment.commitment1, challenge = challenge ) and self.verifier2.verify(responses.response2, commitment=commitment.commitment2, challenge= challenge)


class AndProof:
    def __init__(self, proof1, proof2):
        self.proof1 = proof1
        self.proof2 = proof2

        self.group_generators = self.get_generators()  #For consistency
        self.secret_names = self.get_secret_names()
        check_groups(self.secret_names, self.group_generators)

    def get_secret_names(self):
        secrets = self.proof1.get_secret_names().copy()
        secrets.extend(self.proof2.get_secret_names().copy())
        return secrets

    def get_generators(self):
        generators = self.proof1.group_generators.copy()
        generators.extend(self.proof2.group_generators.copy())
        return generators

    def getProver(self, secrets_dict):
        def sub_proof_prover(sub_proof):
            keys = set(sub_proof.get_secret_names())
            secrets_for_prover = []
            for s_name in secrets_dict:
                if s_name in keys:
                    secrets_for_prover.append((s_name, secrets_dict[s_name]))
            return sub_proof.getProver(dict(secrets_for_prover))

        prover1 = sub_proof_prover(self.proof1)
        prover2 = sub_proof_prover(self.proof2)
        return AndProofProver(prover1, prover2)

    def getVerifier(self):
        return AndProofVerifier(self.proof1.getVerifier(),
                                self.proof2.getVerifier())


def check_groups(
        list_of_secret_names, list_of_generators
):  #checks that if two secrets are the same, the generators they expand live in the same group
    # takes a merged list of secrets names and a merged list of generators.

    # We map the unique secrets to the indices where they appear
    mydict = defaultdict(list)
    for idx, word in enumerate(list_of_secret_names):
        mydict[word].append(idx)

    # Now we use this dictionary to check all the generators related to a particular secret live in the same group
    for word, gen_idx in mydict.items(
    ):  #word is the key, gen_idx is the value = a list of indices
        ref_group = list_of_generators[gen_idx[0]].group

        for index in gen_idx:
            if list_of_generators[index].group != ref_group:
                raise Exception(
                    "A shared secret has generators from different groups : secret",
                    word)

    return True
