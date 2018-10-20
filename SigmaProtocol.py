import random, string, attr
from collections import namedtuple 
from petlib.ec import EcGroup

#SetupOutputParams = namedtuple("SetupOutputParams", "tab_g secrets")
Params = attr.make_class("Params", ["tab_g", "secrets"])
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
		params = self.setup()
		victor = self.verifierClass(params.tab_g)
		peggy = self.proverClass(params)

		commitment, publicInfo = peggy.commit()
		challenge = victor.sendChallenge(commitment, publicInfo)	
		response = peggy.computeResponse(challenge)
		victor.verify(response)



class Prover: #The Prover class is built on an array of generators and an array of secrets
	def __init__(self, params):
		self.params = params

	def commit(self):
		pass
	def computeResponse(self, challenge):
		pass

class Verifier: #The Verifier class is built on an array of generators
	def __init__(self, generators):
		self.tab_g = generators

	def sendChallenge(self, commitment, publicInfo):
		pass	
	def verify(self, response):
		pass



