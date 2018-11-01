#TODO : remove camelCase

import random, string
from collections import namedtuple 
from petlib.ec import EcGroup
from petlib.bn import Bn
from SigmaProtocol import *


class PedersenProver(Prover):
	def commit(self):
		tab_g= self.params.tab_g
		public_info = self.params.public_info
		
		self.group_order = tab_g[0].group.order()
		self.ks = []
		for i in range(len(tab_g)): #we build a N-commitments
			self.ks.append(self.group_order.random())
		# one could create an array ks and secrets to generalize this algorithm. 
		# with |array of ks| = 1 and |array of secrets| = 1 we would obtain the schnorr zkp
		commitment = [a*b for a,b in zip(self.ks, tab_g)]
		
		print ('\ncommitment = ', commitment, '\npublic_info = ', public_info)
		return commitment #Do we return public info here or is it already accessible to the Verifier?

	def computeResponse(self, challenge): #r = secret*challenge + k 
		resps = [(self.params.secrets[i].mod_mul(challenge,self.group_order)).mod_add(self.ks[i],self.group_order) for i in range(len(self.ks))]
		print('\n responses : ', resps)
		return resps

	def sendResponse(self, challenge):
		response = self.computeResponse(challenge) #could create a private non defined method called compute response in an interface Prover
		return response

class PedersenVerifier(Verifier):

	def sendChallenge(self, commitment):
		tab_g = self.params.tab_g
		self.o = tab_g[0].group.order()
		self.commitment = commitment
		self.challenge = self.o.random()
		print('\nchallenge is ', self.challenge)
		return self.challenge
					
	def verify(self, response):
		tab_g = self.params.tab_g
		y = self.params.public_info 
		r = self.commitment
		G = tab_g[0].group

		
		leftSide =  [a*b for a,b in zip(response, tab_g)]
		
		sumleft = G.infinite()
		#sumleft = leftSide[0] #Ugly but simpler than converting 0 in Bn
		for i in range(len(leftSide)):
			sumleft+= leftSide[i]
		#leftSide = (response[0] * g1) + (response[1] * g2) ...

		#rightSide = (challenge * y1 + r1) + (challenge*y2+r2) ...
		# (generalization of rightSide = challenge*y + r in Schnorr)
		rightSide = [self.challenge*yelem + relem for yelem, relem in zip(y, r)]
		sumright = G.infinite()
	    #sumright = rightSide[0] #Ugly but simpler than converting 0 in Bn
		for i in range(len(rightSide)):
			sumright+= rightSide[i]

		return sumright == sumleft #If the result

def randomword(length):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(length))

class PedersenProtocol(SigmaProtocol):
	def __init__(self, verifierClass, proverClass, public_info, tab_g, secrets):
		super().__init__(verifierClass, proverClass)
		if len(tab_g) != len(secrets):
			raise Exception('One secret = one generator, one voice one hope one real decision...')
		self.params = Params(public_info, tab_g, secrets)

		test_group = tab_g[0].group
		for g in tab_g:
			if g.group != test_group:
				raise Exception('All generators should come from the same group')

	def setup(self): #for compatibility with the SigmaProtocol class
			params_verif = Params(self.params.public_info, self.params.tab_g, None) #we build a custom parameter object without the secrets 
			return self.params, params_verif
	

class PedersenProof: 

	#len of secretDict and generators param of __init__ must match exactly or secrets_names must be exactly of size 1 and and then every generator uses the same secret.
	def __init__(self, generators, secrets_names):
		if type(generators) != type(dict([])): # we have a single generator
			raise Exception("generators must be a map from generator name to its values")

		if type(generators) == type(dict([])) and len(generators) == 0:
			raise Exception("A dictionnary of generators must be of length at least one.")
		
		if type(secrets_names) != type(list()):
			raise Exception("secrets_names must be a list of secrets names")

		if len(secrets_names) != len(generators) and len(secrets_names) != 1:
			raise Exception("secrets_names and generators must be of the same length if length of secret names is not one (secret shared by all generators)")

		if len(secrets_names) != len(generators) and len(secrets_names) == 1:
			secrets_names = [secrets_names[0] for i in range(len(generators))]	
			
		if len(secrets_names) == 0:
			raise Exception("create some entries in this array of secrets' names. ")


		self.group_generators = generators
		self.secrets_names = secrets_names

	def getProver(self, secrets_dict): 
		if (type(secrets_dict) != type(dict([]))):
			raise Exception("secrets_dict should be a dictionnary")

		secrets_names_set = set(self.secrets_names)
		secrets_keys = set(secrets_dict.keys())
		diff1 = secrets_keys.difference(secrets_names_set)
		diff2 = secrets_names_set.difference(secrets_keys)
		if len(diff1) > 0 or len(diff2) > 0:
			raise Exception("secrets do not match: those secrets should be checked {0} {1}".format(diff1, diff2))

		secrets_arr = []
		for name in self.secrets_names:
			secrets_arr.append(secrets_dict[name])
			
		gen_values = list(self.group_generators.values())
		public_info = [a*g_val for a, g_val in zip (secrets_arr, gen_values)] #The Ys of which we will prove logarithm knowledge
		self.group_generators.values()
		self.pedersen_protocol = PedersenProtocol(PedersenVerifier, PedersenProver, public_info, gen_values, secrets_arr)
		params, params_verif = self.pedersen_protocol.setup()
		self.params = params
		self.params_verif = params_verif

		return PedersenProver(self.params)

	def getVerifier(self):
		return PedersenVerifier(self.params_verif)

 
if __name__ == "__main__":
	N = 5
	G = EcGroup(713)
	tab_g = []
	tab_g.append(G.generator())
	for i in range (1,N):
		randWord = randomword(30).encode("UTF-8")
		tab_g.append(G.hash_to_point(randWord)) 
	o = G.order()
	secrets = []
	for i in range(len(tab_g)): #we build N secrets
		secrets.append(o.random())# peggy wishes to prove she knows the discrete logarithm equal to this value


	public_info = [a*b for a,b in zip (secrets, tab_g)] #The Ys of which we will prove logarithm knowledge

	pedersen_protocol = PedersenProtocol(PedersenVerifier, PedersenProver, public_info, tab_g, secrets)
	pedersen_protocol.run()


