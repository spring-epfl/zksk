import random, string
from collections import namedtuple
from petlib.ec import EcGroup
import pdb
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

    def commit(self, randomizers_dict=None):
        pass

    def compute_response(self, challenge):
        pass

    def get_NI_proof(message):
        pass


class Verifier:  # The Verifier class is built on an array of generators, an array of secrets'IDs and public info
    def __init__(self, generators, secret_names, public_info):
        self.generators = generators
        self.secret_names = secret_names
        self.public_info = public_info

    def send_challenge(self, commitment):
        pass

    def verify(self, response, commitment=None, challenge=None):
        pass

    def verify_NI(self, challenge, response, message):
        pass


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
