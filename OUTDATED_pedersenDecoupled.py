import random, string
from collections import namedtuple 
from petlib.ec import EcGroup
from SigmaProtocol import Prover, Verifier, SigmaProtocol, RandomlySimulatableProver

SetupOutputParams = namedtuple("SetupOutputParams", "G g1 g2 o")

class PedersenProver(RandomlySimulatableProver):
	def __init__(self, params):
		self.params = params
		self.secret1 = params.o.random() # peggy wishes to prove she knows the discrete logarithm equal to this value
		self.secret2 = params.o.random()

	def commit(self):
		G, g1, g2, o, = self.params
		self.k1 = o.random()
		self.k2 = o.random()
		# one could create an array ks and secrets to generalize this algorithm. 
		# with |array of ks| = 1 and |array of secrets| = 1 we would obtain the schnorr zkp
		commitment = (self.k1 * g1, self.k2 * g2) 
		public_info = (self.secret1 * g1, self.secret2 * g2)
		return (commitment, public_info)

	def computeResponse(self, challenge):
		return (self.k1 + challenge * self.secret1, self.k2 + challenge * self.secret2)

	def generateRandomChallenge(self):
		return self.params.o.random()

	def generateRandomResponse(self):
		o = self.params.o
		return (o.random(), o.random())

	def simulate(self, challenge, response):
		s1, s2 = response
		G, g1, g2, o = self.params
		r1 = randomEcPoint(G)
		r2 = s1 * g1 + s2 * g2 + challenge * ((self.secret1 * g1 + self.secret2 * g2) - r1)
		return (challenge, response, (r1, r2))

	def sendResponse(self, challenge):
		response = self.computeResponse(challenge) #could create a private non defined method called compute response in an interface Prover
		return response

class PedersenVerifier(Verifier):
	def __init__(self, params):
		self.params = params

	def sendChallenge(self, commitment, public_info):
		self.commitment = commitment
		self.public_info = public_info	
		self.challenge = self.params.o.random()
		return self.challenge
					
	def verify(self, commitment, challenge, response, public_info): 
		G, g1, g2, o = self.params
		(y1, y2) = public_info 
		(r1, r2) = commitment
		leftSide = (response[0] * g1) + (response[1] * g2)
		rightSide = (challenge * y1 + r1) + (challenge * y2 + r2)
		return leftSide == rightSide

def randomEcPoint(ecGroup: EcGroup):
	return ecGroup.hash_to_point(randomword(30).encode("UTF-8"))

def randomword(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))

class PedersenProtocol(SigmaProtocol):
	def setup(self):
                G = EcGroup(713)
                g1 = G.generator()
                g2 = randomEcPoint(G) # a second generator for G
                o = G.order()
                return SetupOutputParams(G, g1, g2, o)


