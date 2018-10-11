import random, string
from collections import namedtuple 
from petlib.ec import EcGroup

class Prover:
	def __init__(self, params):
		self.params = params
		self.secret1 = params.o.random() # peggy wishes to prove she knows the discrete logarithm equal to this value
		self.secret2 = params.o.random()

	# we see that Prover and Verifier have both a well defined set of interfaces
	# to communicate with each other
	def setVerifier(self, verifier):
		self.verifier = verifier

	def commit(self):
		G, g1, g2, o, = self.params
		self.k1 = o.random()
		self.k2 = o.random()
		# one could create an array ks and secrets to generalize this algorithm. 
		# with |array of ks| = 1 and |array of secrets| = 1 we would obtain the schnorr zkp
		commitment = (self.k1 * g1, self.k2 * g2) 
		publicInfo = (self.secret1 * g1, self.secret2 * g2)
		self.verifier.sendChallenge(commitment, publicInfo)

	def computeResponse(self, challenge):
		return (self.k1 + challenge * self.secret1, self.k2 + challenge * self.secret2)

	def sendResponse(self, challenge):
		response = self.computeResponse(challenge) #could create a private non defined method called compute response in an interface Prover
		self.verifier.verify(response)

class Verifier:
	def __init__(self, params):
		self.params = params
	def setProver(self, prover):
		self.prover = prover

	def sendChallenge(self, commitment, publicInfo):
		self.commitment = commitment
		self.publicInfo = publicInfo	
		self.challenge = self.params.o.random()
		self.prover.sendResponse(self.challenge)	
					
	def verify(self, response):
		G, g1, g2, o = self.params
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



SetupOutputParams = namedtuple("SetupOutputParams", "G g1 g2 o")

def setup():
	G = EcGroup(713)
	g1 = G.generator()
	randWord = randomword(30).encode("UTF-8")
	g2 = G.hash_to_point(randWord) # a second generator for G
	o = G.order()
	return SetupOutputParams(G, g1, g2, o)

params = setup()

victor = Verifier(params)
peggy = Prover(params)

victor.setProver(peggy)
peggy.setVerifier(victor)

peggy.commit()
