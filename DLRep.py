# TODO : remove camelCase

import pdb
import random, string
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from SigmaProtocol import *
from hashlib import sha256
import binascii


class DLRepProver(Prover):
    def get_randomizers(self) -> dict:
        output = {}
        for idx, sec in enumerate(self.secret_names): #This overwrites if shared secrets but allows to access the appropriate group order
            key = sec
            to_append = self.generators[idx].group.order().random()
            output.update({key: to_append})
        return output

    def commit(self, randomizers_dict=None):
        tab_g = self.generators
        G = tab_g[0].group
        self.group_order = G.order()  # Will be useful for all the protocol

        if randomizers_dict == None:  # If we are not provided a randomizer dict from above, we compute it
            secret_to_random_value = self.get_randomizers()
        else:
            secret_to_random_value = randomizers_dict

        self.ks = [secret_to_random_value[sec] for sec in self.secret_names]
        commits = [a * b for a, b in zip(self.ks, tab_g)]

        # We build the commitment doing the product g1^k1 g2^k2...
        sum_ = G.infinite()
        for com in commits:
            sum_ = sum_ + com

        print("\ncommitment = ", sum_, "\npublic_info = ", self.public_info)
        return sum_

    def compute_response(
            self, challenge
    ):  # r = secret*challenge + k. At this point the k[] array contains the correct randomizers for the matching secrets
        resps = [  # (1) OR k is a dict with secret names as keys and randomizers as values ?
            (self.secret_values[self.secret_names[i]].mod_mul(
                challenge, self.group_order)).
            mod_add(
                self.ks[i],
                self.
                group_order,  # If (1) replace by self.ks[self.secret_names[i]]
            ) for i in range(len(self.ks))
        ]
        print("\n responses : ", resps)
        return resps

    def get_NI_proof(
            self, message=''
    ):  # Non-interactive proof. Takes a string message. Challenge is hash of (public_info, commitment, message)
        tab_g = self.generators
        commitment = self.commit()
        message = message.encode()

        # Computing the challenge
        conc = self.public_info.export()
        conc += commitment.export()
        conc += message
        myhash = sha256(conc).digest()
        challenge = Bn.from_hex(binascii.hexlify(myhash).decode())
        responses = self.compute_response(challenge)
        return (challenge, responses)

    def simulate_proof(self): 
        G = self.generators[0].group
        challenge = G.order().random()
        new_dict = self.get_randomizers() 
        response = [new_dict[m] for m in self.secret_names] #random responses, the same for shared secrets
        commitment = (
            G.infinite()
        )  
        commitment += raise_powers(self.generators, response)
        commitment += (-challenge) * self.public_info

        return commitment, challenge, response


def randomword(length):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))

def raise_powers(tab_g, response):
    left_arr = [a * b for a, b in zip(response, tab_g)]  # g1^s1, g2^s2...
    leftside = tab_g[0].group.infinite()
    for el in left_arr:
        leftside += el
    return leftside

class DLRepVerifier(Verifier):
    def send_challenge(self, commitment):
        self.commitment = commitment
        
        twoTo128 = Bn.from_binary(bytes.fromhex("1" + "0" * 31))
        self.challenge = twoTo128.random()
        print("\nchallenge is ", self.challenge)

        return self.challenge

    def verify(
            self, response, commitment=None,
            challenge=None):  #Can verify simulations with optional arguments

        if commitment is None:
            commitment = self.commitment
        if challenge is None:
            challenge = self.challenge

        tab_g = self.generators
        y = self.public_info

        left_arr = [a * b for a, b in zip(response, tab_g)]  # g1^s1, g2^s2...
        leftside = raise_powers(self.generators, response)
        rightside = challenge * y + commitment

        return rightside.pt_eq(leftside)  # If the result

    def verify_NI(self, challenge, response, message=''):
        message = message.encode()
        tab_g = self.generators
        y = self.public_info
        r_guess = -challenge * y + raise_powers(self.generators, 
            response
        )  #We retrieve the commitment using the verification identity

        conc = self.public_info.export()
        conc += r_guess.export()
        conc += message
        myhash = sha256(conc).digest()
        return challenge == Bn.from_hex(binascii.hexlify(myhash).decode())


class DLRepProof:

    #len of secretDict and generators param of __init__ must match exactly
    def __init__(self, generators, secret_names, public_info):
        if not isinstance(generators, list):  # we have a single generator
            raise Exception("generators must be a list of generators values")

        if isinstance(generators, list) and len(generators) == 0:
            raise Exception(
                "A list of generators must be of length at least one.")

        if not isinstance(secret_names, list):
            raise Exception("secret_names must be a list of secrets names")

        if len(secret_names) != len(generators):
            raise Exception(
                "secret_names and generators must be of the same length")

        # Check all the generators live in the same group
        test_group = generators[0].group
        for g in generators:
            if g.group != test_group:
                raise Exception(
                    "All generators should come from the same group")

        self.group_generators = generators
        self.secret_names = secret_names
        self.public_info = public_info

    def get_secret_names(self):
        return self.secret_names.copy()

    def get_prover(self, secrets_dict):
        if len(set(self.secret_names)) != len(secrets_dict):
            raise Exception("We expect as many secrets as different aliases")

        if not isinstance(secrets_dict, dict):
            raise Exception("secrets_dict should be a dictionary")

        # Check that the secret names and the keys of the secret values actually match. Could be simplified since it only matters that all names are in dict
        secret_names_set = set(self.secret_names)
        secrets_keys = set(secrets_dict.keys())
        diff1 = secrets_keys.difference(secret_names_set)
        diff2 = secret_names_set.difference(secrets_keys)

        if len(diff1) > 0 or len(diff2) > 0:
            raise Exception(
                "secrets do not match: those secrets should be checked {0} {1}"
                .format(diff1, diff2))

        # We check everything is indeed a BigNumber, else we cast it
        for name, sec in secrets_dict.items():
            if not isinstance(sec, Bn):
                secrets_dict[name] = Bn.from_decimal(str(sec))

        return DLRepProver(self.group_generators, self.secret_names,
                              secrets_dict, self.public_info)
        
    def get_simulator(self):
        return DLRepProver(self.group_generators, self.secret_names, {}, self.public_info)
        

    def get_verifier(self):
        return DLRepVerifier(self.group_generators, self.secret_names,
                                self.public_info)


if __name__ == "__main__":  #A legit run in which we build the public info from random variables and pass everything to the process
    N = 5
    G = EcGroup(713)
    tab_g = []
    tab_g.append(G.generator())
    for i in range(1, N):
        randWord = randomword(30).encode("UTF-8")
        tab_g.append(G.hash_to_point(randWord))
    o = G.order()
    secrets_aliases = ["x1", "x2", "x3", "x4", "x5"]
    secrets_values = dict()
    secret_tab = [
    ]  #This array is only useful to compute the public info because zip doesn't take dicts. #spaghetti
    for wurd in secrets_aliases:  # we build N secrets
        secrets_values[wurd] = o.random()
        secret_tab.append(secrets_values[wurd])
    # peggy wishes to prove she knows the discrete logarithm equal to this value

    powers = [a * b for a, b in zip(secret_tab, tab_g)
              ]  # The Ys of which we will prove logarithm knowledge
    public_info = G.infinite()
    for y in powers:
        public_info += y

    dl_proof = DLRepProof(tab_g, secrets_aliases, public_info)
    dl_prover = dl_proof.get_prover(secrets_values)
    dl_verifier = dl_proof.get_verifier()

    dl_protocol = SigmaProtocol(dl_verifier, dl_prover)
    dl_protocol.run()