import random, string
from collections import namedtuple
from petlib.ec import EcGroup
import pdb
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
