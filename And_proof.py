from SigmaProtocol import *
from collections import defaultdict


class AndProofCommitment:
    def __init__(self, commitment1, commitment2):
        self.commitment1 = commitment1
        self.commitment2 = commitment2


class AndProofChallenge:
    def __init__(self, challenge1, challenge2):
        self.challenge1 = challenge1
        self.challenge2 = challenge2


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
        if randomizers_dict == None:
            randomizers_dict = self.get_randomizers()
        return AndProofCommitment(
            self.prover1.commit(randomizers_dict=randomizers_dict),
            self.prover2.commit(randomizers_dict=randomizers_dict))

    def computeResponse(self, challenges: AndProofChallenge
                        ) -> AndProofResponse:  #r = secret*challenge + k
        return AndProofResponse(
            self.prover1.computeResponse(challenges.challenge1),
            self.prover2.computeResponse(challenges.challenge2))

    def sendResponse(self, challenges: AndProofChallenge) -> AndProofResponse:
        return self.computeResponse(challenges)


class AndProofVerifier:
    def __init__(self, verifier1, verifier2):
        self.verifier1 = verifier1
        self.verifier2 = verifier2

    def sendChallenge(self,
                      commitment: AndProofCommitment) -> AndProofChallenge:
        return AndProofChallenge(
            self.verifier1.sendChallenge(commitment.commitment1),
            self.verifier2.sendChallenge(commitment.commitment2))

    def verify(self, responses: AndProofResponse):
        return self.verifier1.verify(
            responses.response1) and self.verifier2.verify(responses.response2)


class AndProof:
    def __init__(self, proof1, proof2):
        self.proof1 = proof1
        self.proof2 = proof2

    def get_secret_names(self):
        secrets = self.proof1.get_secret_names().copy()
        secrets.extend(self.proof2.get_secret_names().copy())
        return secrets 
        

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
        list_of_list_of_secret_names, list_of_generators_list
):  #checks that if two secrets are the same, the generators they expand live in the same group
    # takes a list of all secret_aliases lists (one for each subproof), a list of all generators lists(one for each subproof),
    # looks for the matching secrets. Checks the corresponding generators groups.
    #
    # MERGE the lists and then :
    # use a dict 'mydict' with secret names as keys, and with list of indices as values.
    # and then for each key (unique secret name) check all its g[idx for idx in mydict[word]] are ==

    # First concatenate all the secret aliases lists in one and all the generators list in one. Notice they match exactly because they are ordered.
    secret_names_list = [
        item for sublist in list_of_list_of_secret_names for item in sublist
    ]
    generators_list = [
        item for sublist in list_of_generators_list for item in sublist
    ]

    # Now we map the unique secrets to the indices where they appear
    mydict = defaultdict(list)
    for idx, word in enumerate(secret_names_list):
        mydict(word).append(idx)

    # Now we use this dictionary to check all the generators related to a particular secret live in the same group
    for word, gen in mydict.items():
        ref_group = gen[0].group
        for generator in gen:
            if generator.group != ref_group:
                raise Exception(
                    "A shared secret has generators from different groups : secret",
                    word)

    return True
