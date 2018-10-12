import random, string
from collections import namedtuple 
from petlib.ec import EcGroup

SetupOutputParams = namedtuple("SetupOutputParams", "G g1 g2 o")
class SigmaProtocol:
	def __init__(self, verifierClass, proverClass):
		self.verifierClass = verifierClass
		self.proverClass = proverClass

	def setup(self):
		pass

	def run(self): 
		params = self.setup()

		victor = self.verifierClass(params)
		peggy = self.proverClass(params)

		commitment, publicInfo = peggy.commit()
		challenge = victor.sendChallenge(commitment, publicInfo)	
		response = peggy.computeResponse(challenge)
		victor.verify(response)

class Prover:
	def __init__(self, params):
		self.params = params

	def commit(self):
		pass
	def computeResponse(self, challenge):
		pass

class Verifier:
	def __init__(self, params):
		self.params = params

	def sendChallenge(self, commitment, publicInfo):
		pass	
	def verify(self, response):
		pass



