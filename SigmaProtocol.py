import random, string
from collections import namedtuple
from petlib.ec import EcGroup
from petlib.bn import Bn
import binascii
import pdb
from hashlib import sha256
from collections import defaultdict
import pytest


class SigmaProtocol:
    def __init__(self, verifierClass, proverClass):
        self.verifierClass = verifierClass
        self.proverClass = proverClass

    def setup(self):
        pass

    def verify(
            self
    ) -> bool:  # a method used to chain SigmaProtocols verifications
        victor = self.verifierClass
        peggy = self.proverClass

        (commitment) = peggy.commit()
        challenge = victor.send_challenge(commitment)
        response = peggy.compute_response(challenge)
        return victor.verify(response)

    def run(self):
        if self.verify():
            print("Verified for {0}".format(self.__class__.__name__))
            return True
        else:
            print("Not verified for {0}".format(self.__class__.__name__))
            return False


class Prover:  # The Prover class is built on an array of generators, an array of secrets'IDs, a dict of these secrets, and public info
    def __init__(self, generators, secret_names, secret_values, public_info):
        self.generators = generators
        self.secret_names = secret_names
        self.secret_values = secret_values
        self.public_info = public_info

        self.set_simulate = False

    def commit(self, randomizers_dict=None):
        pass

    def compute_response(self, challenge):
        pass

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
        


class Verifier:  # The Verifier class is built on an array of generators, an array of secrets'IDs and public info
    def __init__(self, generators, secret_names, public_info):
        self.generators = generators
        self.secret_names = secret_names
        self.public_info = public_info

    def send_challenge(self, commitment):
        self.commitment = commitment
        self.challenge = chal_128bits()
        print("\nchallenge is ", self.challenge)

        return self.challenge
    
    def verify(
            self, response, commitment=None,
            challenge=None):  #Can verify simulations with optional arguments

        if commitment is None:
            commitment = self.commitment
        if challenge is None:
            challenge = self.challenge
        
        return (commitment == self.recompute_commitment(self, challenge, response) )

    def verify_NI(self, challenge, response, message=''):
        message = message.encode()
        tab_g = self.generators
        y = self.public_info
        #r_guess = recompute_commitment  #We retrieve the commitment using the verification identity
        r_guess = tab_g[0].group.order().random() #for compilation
        conc = self.public_info.export()
        conc += r_guess.export()
        conc += message
        myhash = sha256(conc).digest()
        return challenge == Bn.from_hex(binascii.hexlify(myhash).decode())


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

def chal_128bits():
    twoTo128 = Bn.from_binary(bytes.fromhex("1" + "0" * 31))
    return twoTo128.random()