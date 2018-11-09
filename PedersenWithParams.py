# TODO : remove camelCase

import random, string
from collections import namedtuple
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from SigmaProtocol import *
from hashlib import sha256
import binascii


class PedersenProver(Prover):
    def commit(self):
        tab_g = self.generators
        public_info = self.public_info
        G = tab_g[0].group
        self.group_order = G.order()  # Will be useful for all the protocol
        self.ks = []
        for i in range(len(tab_g)):  # we build a N-commitment
            self.ks.append(
                self.group_order.random()
            )  # To be replaced by a call to randomizers() so shared secrets also share a randomizer
        commits = [a * b for a, b in zip(self.ks, tab_g)]

        # We build the commitment doing the product g1^k1 g2^k2...
        sum = G.infinite()
        for com in commits:
            sum = sum + com

        print("\ncommitment = ", sum, "\npublic_info = ", public_info)
        return sum

    def computeResponse(
            self, challenge
    ):  # r = secret*challenge + k. At this point the k[] array contains the correct randomizers for the matching secrets
        resps = [  # (1) OR k is a dict with secret names as keys and randomizers as values ?
            (self.secrets_values[self.secrets_names[i]].mod_mul(
                challenge, self.group_order)).
            mod_add(
                self.ks[i],
                self.
                group_order,  # If (1) replace by self.ks[self.secrets_names[i]]
            ) for i in range(len(self.ks))
        ]
        print("\n responses : ", resps)
        return resps

    def sendResponse(self, challenge):
        response = self.computeResponse(
            challenge
        )  # could create a private non defined method called compute response in an interface Prover
        return response

    def simulate_proof(self, challenge, response):  # TODO : correct this
        G = self.generators[0].group
        commmitment = (
            G.infinite()
        )  # We will choose all but 1 commitment elements at random
        for idx in len(
                self.params.tab_g):  # We compute the commitment so it matches
            commitment += response[i] * self.params.tab_g[idx]
        commitment += (-challenge) * public_info

        return commitment, challenge, response


class PedersenVerifier(Verifier):
    def sendChallenge(self, commitment):
        tab_g = self.generators
        self.commitment = commitment

        # Computing the challenge
        conc = self.public_info.export()
        conc += (gen.export()
                 for gen in tab_g)  # We concatenate all the public info

        myhash = sha256(conc).digest()
        self.challenge = Bn.from_hex(binascii.hexlify(myhash).decode())
        print("\nchallenge is ", self.challenge)
        # raise Exception('stop hammertime')
        return self.challenge

    def verify(self, response, commitment=None, challenge=None):

        # These two parameters exist so we can also inject commitments and challenges and verify simulations
        if commitment == None:
            commitment = self.commitment
        if challenge == None:
            challenge = self.challenge

        tab_g = self.generators
        y = self.public_info
        r = self.commitment

        left_arr = [a * b for a, b in zip(response, tab_g)]  # g1^s1, g2^s2...

        leftside = tab_g[0].group.infinite()
        for el in left_arr:  # We sum all these guys
            leftside += el

            # rightSide = y^c+r = y^c+g1^k1+g2^k2
            # (generalization of rightSide = challenge*y + r in Schnorr)
        rightside = challenge * y + commitment

        return rightside.pt_eq(leftside)  # If the result


def randomword(length):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


class PedersenProof:
    def __init__(self, generators, secrets_names, public_info):

        # len of the list of aliases and list of generators (params of __init__) must match exactly
        if not isinstance(generators, list) or len(generators) == 0:
            raise Exception("We need a non-empty list of generators")

        if not isinstance(secrets_names, list) or len(secrets_names) == 0:
            raise Exception("We need a non-empty list of secrets names")

        if len(secrets_names) != len(generators):
            raise Exception(
                "secrets_names and generators must be of the same length")

            # We check the consistency of the generators
        test_group = tab_g[0].group
        for g in tab_g:
            if g.group != test_group:
                raise Exception(
                    "All generators should come from the same group")

        self.group_generators = generators
        self.secrets_names = secrets_names
        self.public_info = public_info

    def getProver(self, secrets_dict):
        # Sanity check over the secrets : consistent type and number of unique secrets
        if len(set(self.secrets_names)) != len(secrets_dict):
            raise Exception("We expect as many secrets as different aliases")
        if type(secrets_dict) != type(dict([])):
            raise Exception("secrets_dict should be a dictionary")

            # We check that the aliases match with the keys of the dictionary
        secrets_names_set = set(self.secrets_names)
        secrets_keys = set(secrets_dict.keys())
        diff1 = secrets_keys.difference(secrets_names_set)
        diff2 = secrets_names_set.difference(secrets_keys)
        if len(diff1) > 0 or len(diff2) > 0:
            raise Exception(
                "secrets do not match: these secrets should be checked {0} {1}"
                .format(diff1, diff2))

        return PedersenProver(self.generators, self.secret_names, secrets_dict,
                              self.public_info)

    def getVerifier(self):
        return PedersenVerifier(self.group_generators, self.secrets_names,
                                self.public_info)


if __name__ == "__main__":
    N = 5
    G = EcGroup(713)
    tab_g = []
    tab_g.append(G.generator())
    for i in range(1, N):
        randWord = randomword(30).encode("UTF-8")
        tab_g.append(G.hash_to_point(randWord))
    o = G.order()
    secrets = []
    for i in range(len(tab_g)):  # we build N secrets
        secrets.append(
            o.random()
        )  # peggy wishes to prove she knows the discrete logarithm equal to this value

    powers = [a * b for a, b in zip(secrets, tab_g)
              ]  # The Ys of which we will prove logarithm knowledge
    public_info = G.infinite()
    for y in powers:
        public_info += y

    secrets_aliases = ["x1", "x2", "x3", "x4", "x5"]
    pedersen_proof = PedersenProof(tab_g, secrets_aliases, public_info)
    Ped_prover = pedersen_proof.getProver(secrets)
    Ped_verifier = pedersen_proof.getVerifier()

    pedersen_protocol = SigmaProtocol(Ped_verifier, Ped_prover)
    pedersen_protocol.run()
