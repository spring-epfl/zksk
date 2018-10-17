import random, string
from collections import namedtuple 
from petlib.ec import EcGroup
from SigmaProtocol import Prover, Verifier, SigmaProtocol

SetupOutputParams = namedtuple("SetupOutputParams", "G g_tab o")

class PedersenProver(Prover):
	def __init__(self, params):
		self.params = params
		self.secret1 = params.o.random() # peggy wishes to prove she knows the discrete logarithm equal to this value
		self.secret2 = params.o.random()

	def commit(self):
		G, g_tab, o = self.params
		self.k1 = o.random()
		self.k2 = o.random()
		# one could create an array ks and secrets to generalize this algorithm. 
		# with |array of ks| = 1 and |array of secrets| = 1 we would obtain the schnorr zkp
		commitment = 
		#(self.k1 * g1, self.k2 * g2) 
		publicInfo = (self.secret1 * g1, self.secret2 * g2)
		return commitment, publicInfo

	def computeResponse(self, challenge):
		return (self.k1 + challenge * self.secret1, self.k2 + challenge * self.secret2)

	def sendResponse(self, challenge):
		response = self.computeResponse(challenge) #could create a private non defined method called compute response in an interface Prover
		return response

class PedersenVerifier(Verifier):
	def __init__(self, params):
		self.params = params

	def sendChallenge(self, commitment, publicInfo):
		self.commitment = commitment
		self.publicInfo = publicInfo	
		self.challenge = self.params.o.random()
		return self.challenge
					
	def verify(self, response):
		G, g_tab, o = self.params
		(y1, y2) = self.publicInfo 
		(r1, r2) = self.commitment
		leftSide = (response[0] * g1) + (response[1] * g2)
		rightSide = (self.challenge * y1 + r1) + (self.challenge * y2 + r2)
		if leftSide == rightSide:
			print("Verified")
		else:
			print("Not verified")

def randomword(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

class PedersenProtocol(SigmaProtocol):
	def __init__(self, verifierClass, proverClass, N)
		#super().__init__
		self.nbases = N

	def setup(self):
			N = self.nbases
			if (N <1):
				return 1
			G = EcGroup(713)
			g_tab = []
			g_tab.append(G.generator())
			for i in range (1,N):
				randWord = randomword(30).encode("UTF-8")
				g_tab.append(G.hash_to_point(randWord)) # a second generator for G
			o = G.order()
			return SetupOutputParams(G, g_tab, o)



N= 4
pedersenProtocol = PedersenProtocol(PedersenVerifier, PedersenProver, N)
pedersenProtocol.run()
