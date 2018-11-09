import SigmaProtocol
from collections import Counter


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

    def commit(self) -> AndProofCommitment: #TODO : compute the randomizers for all unique secrets
        return AndProofCommitment(self.prover1.commit(), self.prover2.commit())

    def computeResponse(
        self, challenges: AndProofChallenge
    ) -> AndProofResponse:  # r = secret*challenge + k
        return AndProofResponse(
            self.prover1.computeResponse(challenges.challenge1),
            self.prover2.computeResponse(challenges.challenge2),
        )

    def sendResponse(self, challenges: AndProofChallenge) -> AndProofResponse:
        return self.computeResponse(challenges)


class AndProofVerifier:
    def __init__(self, verifier1, verifier2):
        self.verifier1 = verifier1
        self.verifier2 = verifier2

    def sendChallenge(self, commitment: AndProofCommitment) -> AndProofChallenge:
        return AndProofChallenge(
            self.verifier1.sendChallenge(commitment.commitment1),
            self.verifier2.sendChallenge(commitment.commitment2),
        )

    def verify(self, responses: AndProofResponse):
        return self.verifier1.verify(responses.response1) and self.verifier2.verify(
            responses.response2
        )


class AndProof:
    def __init__(self, proof1, proof2):
        self.proof1 = proof1
        self.proof2 = proof2

    def getProver(self, secrets_dict):
        def sub_proof_prover(sub_proof):
            keys = set(sub_proof.secrets_names)
            secrets_for_prover = []
            for s_name in secrets_dict:
                if s_name in keys:
                    secrets_for_prover.append((s_name, secrets_dict[s_name]))
            return sub_proof.getProver(dict(secrets_for_prover))

        prover1 = sub_proof_prover(self.proof1)
        prover2 = sub_proof_prover(self.proof2)
        return AndProofProver(prover1, prover2)

    def getVerifier(self):
        return AndProofVerifier(self.proof1.getVerifier(), self.proof2.getVerifier())

def check_groups(list_of_secret_names, list_of_generators_list) #checks that if two secrets are the same, the generators they expand live in the same group
                                        # takes a list of all secret_aliases lists (for each subproof) and looks for the matching secrets. Checks the corresponding generators groups.
                                        #
                                        # MERGE the two lists and then :
                                        #Use a Counter 
                                        # use a dict 'mydict' with same keys as Counter, but with list of indices as values. fill it in the counter loop with mydict[word].append(idx)
                                        # and then for each key (unique secret name) check all its g[idx for idx in mydict[word]] are ==

    cnt = Counter()
    for word, idx in enumerate(['red', 'blue', 'red', 'green', 'blue', 'blue']):
        cnt[word] += 1
    cnt
#Counter({'blue': 3, 'red': 2, 'green': 1})