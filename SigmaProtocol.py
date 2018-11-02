import random, string, attr
from collections import namedtuple 
from petlib.ec import EcGroup
import pytest

#SetupOutputParams = namedtuple("SetupOutputParams", "tab_g secrets")
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
		
	def run(self): 
		params, params_verif = self.setup()
		victor = self.verifierClass(params_verif)
		peggy = self.proverClass(params)

		commitment = peggy.commit()
		challenge = victor.sendChallenge(commitment)	
		response = peggy.computeResponse(challenge)
		return victor.verify(response)



class Prover: #The Prover class is built on an array of generators and an array of secrets
	def __init__(self, params):
		self.params = params

	def commit(self):
		pass
	def computeResponse(self, challenge):
		pass
	def simulate(self, challenge, response):
		pass

class Verifier: #The Verifier class is built on an array of generators
	def __init__(self, params_verif):
		self.params = params_verif

	def sendChallenge(self, commitment):
		pass	
	def verify(self, response, commitment, challenge):
		pass



