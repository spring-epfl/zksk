#TODO : perform the computation of resps (l35) mod o to save time
#TODO : remove G from parameters, useless
import random, string
from collections import namedtuple 
from petlib.ec import EcGroup
from SigmaProtocol import Prover, Verifier, SigmaProtocol

SetupOutputParams = namedtuple("SetupOutputParams", "G g_tab o")

class PedersenProver(Prover):
	def __init__(self, params):
		self.params = params

	def commit(self):
		print('\ncommiting')
		G, g_tab, o = self.params
		self.ks = []
		for i in range(len(g_tab)): #we build a N-commitments
			self.ks.append(o.random())
		# one could create an array ks and secrets to generalize this algorithm. 
		# with |array of ks| = 1 and |array of secrets| = 1 we would obtain the schnorr zkp
		commitment = (a*b for a,b in zip(self.ks, g_tab))
		commitment = tuple(commitment)
		publicInfo = (a*b for a,b in zip (self.secrets, g_tab))
		publicInfo = tuple(publicInfo)
		print ('\ncommitment = ', commitment, '\npublicInfo = ', publicInfo)
		return commitment, publicInfo

	def computeResponse(self, challenge):
		wchal = [challenge*x for x in self.secrets]
		resps = [self.ks[i]+wchal[i] for i in range(len(self.ks))]
		print('\n responses : ', resps)
		return resps

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
		print('\nchallenge is ', self.challenge)
		return self.challenge
					
	def verify(self, response):
		G, g_tab, o = self.params
		y = self.publicInfo 
		r = self.commitment

		
		leftSide =  [a*b for a,b in zip(response, g_tab)]
		sumleft = leftSide[0] #Ugly but simpler than converting 0 in Bn
		for i in range(2,len(leftSide)):
			sumleft+= leftSide[i]
		#leftSide = (response[0] * g1) + (response[1] * g2) ...

		#rightSide = (challenge * y1 + r1) + (challenge*y2+r2) ...
		# (generalization of rightSide = challenge*y + r in Schnorr)
		rightSide = [self.challenge*yelem + relem for yelem, relem in zip(y, r)]
		sumright = rightSide[0] #Ugly but simpler than converting 0 in Bn
		for i in range(2,len(rightSide)):
			sumright+= rightSide[i]

		if sumright == sumleft: #If the result
			print("Verified")
		else:
			print("Not verified")

def randomword(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

class PedersenProtocol(SigmaProtocol):
	def __init__(self, verifierClass, proverClass, N):
		super().__init__(verifierClass, proverClass)
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

			self.secrets = []
			for i in range(len(g_tab)): #we build N secrets
				self.secrets.append(params.o.random())# peggy wishes to prove she knows the discrete logarithm equal to this value
		
			return SetupOutputParams(g_tab, o, self.secrets)



N= 6
pedersenProtocol = PedersenProtocol(PedersenVerifier, PedersenProver, N)
pedersenProtocol.run()
