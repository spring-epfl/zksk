import random, string, attr
from collections import namedtuple
from petlib.ec import EcGroup
import pdb
import pytest

# SetupOutputParams = namedtuple("SetupOutputParams", "tab_g secrets")
Params = attr.make_class("Params", ["public_info", "tab_g", "secrets"])

# @attr.s
# class Params:
# 	g_tab = attr.ib(factory=list)
# 	secrets = attr.ib(factory=list)


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
        challenge = victor.sendChallenge(commitment)
        response = peggy.computeResponse(challenge)
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

    def computeResponse(self, challenge):
        pass
    
    def get_NI_proof():
        pass


class Verifier:  # The Verifier class is built on an array of generators, an array of secrets'IDs and public info
    def __init__(self, generators, secret_names, public_info):
        self.generators = generators
        self.secret_names = secret_names
        self.public_info = public_info

    def sendChallenge(self, commitment):
        pass

    def verify(self, response, commitment=None, challenge=None):
        pass

    def verify_NI(self, challenge, response):
        pass
