#TODO : remove camelCase

import random, string
from collections import namedtuple 
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from SigmaProtocol import *
from hashlib import sha256
import binascii


class PedersenProver(Prover):
	def commit(self):
		tab_g= self.params.tab_g
		public_info = self.params.public_info
		G = tab_g[0].group
		o = G.order()
		self.ks = []
		for i in range(len(tab_g)): #we build a N-commitments
			self.ks.append(self.group_order.random())
		# one could create an array ks and secrets to generalize this algorithm. 
		# with |array of ks| = 1 and |array of secrets| = 1 we would obtain the schnorr zkp
		commits = [a*b for a,b in zip(self.ks, tab_g)]
		
        #We build the commitment doing the product g1^k1 g2^k2...
		sum = G.infinite()
		for com in commits:
			sum = sum+com
		
		print ('\ncommitment = ', sum, '\npublic_info = ', public_info)
		return sum 
        
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
		self.challenge = self.o.random() #Replace by a hash of generators + public info
		#self.challenge = sha256((public_info+tab_g[0]).export()).digest()
		#self.challenge = binascii.hexlify(self.challenge)
		print('\nchallenge is ', self.challenge)
		#raise Exception('stop hammertime')
		return self.challenge
					
	def verify(self, response, commitment=None, challenge=None):

        #These two parameters exist so we can also inject commitments and challenges and verify simulations
		if commitment == None :
			commitment = self.commitment
		if challenge == None:
			challenge = self.challenge
        
		tab_g = self.params.tab_g
		y = self.params.public_info 
		r = self.commitment
		G = tab_g[0].group

		
		left_arr =  [a*b for a,b in zip(response, tab_g)]
		
		leftside = G.infinite()
		for el in left_arr:
			leftside+= el
		#left_arr= (response[0] * g1) + (response[1] * g2) ...

		#rightSide = y^c+r = y^c+g1^k1+g2^k2
		# (generalization of rightSide = challenge*y + r in Schnorr)
		rightside = challenge*y+ commitment

		return sumright == sumleft #If the result

def randomword(length):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(length))


class AndProofCommitment:
	def __init__(self, commitment1, commitment2):
		self.commitment1 = commitment1
		self.commitment2 = commitment2

class AndProofChallenge:
	def __init__(self, challenge1, challenge2):
		self.challenge1 = challenge1
		self.challenge2 = challenge2
class AndProofResponse:
	def __init__(self, response1, response2):
		self.response1 = response1
		self.response2 = response2


class AndProofProver(Prover):
	def __init__(self, prover1, prover2):
		self.prover1 = prover1 
		self.prover2 = prover2 

	def commit(self) -> AndProofCommitment:
		return AndProofCommitment(self.prover1.commit(), self.prover2.commit())

	def computeResponse(self, challenges: AndProofChallenge) -> AndProofResponse: #r = secret*challenge + k 
		return AndProofResponse(self.prover1.computeResponse(challenges.challenge1), self.prover2.computeResponse(challenges.challenge2))

	def sendResponse(self, challenges: AndProofChallenge) -> AndProofResponse:
		return self.computeResponse(challenges) 

class AndProofVerifier:
	def __init__(self, verifier1, verifier2):
		self.verifier1 = verifier1
		self.verifier2 = verifier2

	def sendChallenge(self, commitment: AndProofCommitment) -> AndProofChallenge:
		return AndProofChallenge(self.verifier1.sendChallenge(commitment.commitment1), self.verifier2.sendChallenge(commitment.commitment2))

	def verify(self, responses: AndProofResponse):
		return self.verifier1.verify(responses.response1) and self.verifier2.verify(responses.response2)



class AndProof:
	def __init__(self, proof1, proof2):
		self.proof1 = proof1
		self.proof2 = proof2	
	
	def getProver(self, secrets_dict):
		def sub_proof_prover(sub_proof):
			keys = set(sub_proof.secrets_names)
			secrets_for_prover = []
			for s_name in secrets_dict:	
				if s_name in keys:
					secrets_for_prover.append((s_name, secrets_dict[s_name]))
			return sub_proof.getProver(dict(secrets_for_prover))

		prover1 = sub_proof_prover(self.proof1)
		prover2 = sub_proof_prover(self.proof2)
		return AndProofProver(prover1, prover2)

	def getVerifier(self):
		return AndProofVerifier(self.proof1.getVerifier(), self.proof2.getVerifier())
				
	

class PedersenProof: 
	def __init__(self, generators, secrets_names, public_info):

		#len of the list of aliases and list of generators (params of __init__) must match exactly 
		if not isinstance(generators, list) or len(generators) == 0:
			raise Exception("We need a non-empty list of generators")
		
		if if not isinstance(secrets_names, list) or len(secrets_names) == 0:
			raise Exception("We need a non-empty list of secrets names")

		if len(secrets_names) != len(generators):
			raise Exception("secrets_names and generators must be of the same length")

		#We check the consistency of the generators
		test_group = tab_g[0].group
		for g in tab_g:
			if g.group != test_group:
				raise Exception('All generators should come from the same group')
			
		self.group_generators = generators
		self.secrets_names = secrets_names
		self.public_info = public_info

	def getProver(self, secrets_dict): 
		#Sanity check over the secrets : consistent type and number of unique secrets
		if len(set(self.secrets_names))!= len(secrets_dict):
			raise Exception("We expect as many secrets as different aliases")
		if (type(secrets_dict) != type(dict([]))):
			raise Exception("secrets_dict should be a dictionary")

		#We check that the aliases match with the keys of the dictionary
		secrets_names_set = set(self.secrets_names)
		secrets_keys = set(secrets_dict.keys())
		diff1 = secrets_keys.difference(secrets_names_set) 
		diff2 = secrets_names_set.difference(secrets_keys)
		if len(diff1) > 0 or len(diff2) > 0:
			raise Exception("secrets do not match: those secrets should be checked {0} {1}".format(diff1, diff2))

		return PedersenProver(self.generators, self.secret_names, secrets_dict, self.public_info)

	def getVerifier(self):
		return PedersenVerifier(self.group_generators, self.secrets_names, self.public_info)


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


	powers = [a*b for a,b in zip (secrets, tab_g)] #The Ys of which we will prove logarithm knowledge
	public_info = G.infinite()
	for y in powers:
		public_info += y

	secrets_aliases = ["x1", "x2", "x3", "x4", "x5"]
	pedersen_proof = PedersenProof(tab_g, secrets_aliases, public_info)
	Ped_prover = pedersen_proof.getProver(secrets)
	Ped_verifier = pedersen_proof.getVerifier()

	pedersen_protocol = SigmaProtocol(Ped_verifier, Ped_prover)
	pedersen_protocol.run()


