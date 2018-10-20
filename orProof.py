#!/usr/bin/python3
from SigmaProtocol import SigmaProtocol, Prover, Verifier, SimulatableProver
from pedersenDecoupled import PedersenProver, PedersenProtocol, PedersenVerifier

	
class OrVerifier:
	def __init__(self, or_verifier1: Verifier, or_verifier2: Verifier, params):
		self.params = params
		self.or_verifier1 = or_verifier1(params[0])
		self.or_verifier2 = or_verifier2(params[1])

	def sendChallenge(self, commitment1, public_info1):
		return self.or_verifier1.sendChallenge(commitment1, public_info1)
	
	def verify(self, commitment, challenge, response, public_info):
		commitment1, commitment2 = commitment
		challenge1, challenge2 = challenge
		response1, response2 = response
		(public_info1, public_info2) = public_info
		#in the book there is c = c1 XOR c2 but why do that since c is computed as c = c1 XOR c2 by the prover?
		return self.or_verifier1.verify(commitment1, challenge1, response1, public_info1) and self.or_verifier2.verify(commitment2, challenge2, response2, public_info2)

class OrProver(Prover):
	def __init__(self, p1: Prover, p2: SimulatableProver, params):
		self.params = params
		self.p1 = p1(params[0]) 
		self.p2 = p2(params[1])

	def commit(self):
		(commitment1, public_info1) = self.p1.commit()

		print("In orProof commit commitment1 {0}\n, public_info1 {1}\n".format(commitment1, public_info1))
		(commitment_to_trash, public_info2) = self.p2.commit()
		(challenge2, response2, commitment2) = self.p2.randomlySimulate()
		print("in orProof commit challenge2{0}\n response2{1}, commitment2{2}".format(challenge2, response2, commitment2))
		self.challenge2 = challenge2
		self.response2 = response2
		return ((commitment1, public_info1), (commitment2, public_info2, challenge2))

	def computeResponse(self, challenge1): 
		return (self.p1.computeResponse(challenge1), self.response2)
		

class OrProtocol(SigmaProtocol):
	def __init__(self, verifier_class_creator, prover_class_creator, protocol1: SigmaProtocol, protocol2: SigmaProtocol):
		super().__init__(verifier_class_creator, prover_class_creator)
		self.protocol1 = protocol1
		self.protocol2 = protocol2

	def verify(self) -> bool:
		params = self.setup()
		victor = self.verifierClass(params)
		peggy = self.proverClass(params)
		((commitment1, public_info1), (commitment2, public_info2, challenge2)) = peggy.commit()
		challenge1 = victor.sendChallenge(commitment1, public_info1)
		(response1, response2) = peggy.computeResponse(challenge1)
		return victor.verify((commitment1, commitment2), (challenge1, challenge2), (response1, response2), (public_info1, public_info2))

		
	def setup(self):
		return (self.protocol1.setup(), self.protocol2.setup())



def or_prover_creator(params):
	return OrProver(PedersenProver, PedersenProver, params) #need to send parameters to the pedersen provers (maybe different parameters)
def or_verifier_creator(params):
	return OrVerifier(PedersenVerifier, PedersenVerifier, params) 
def create_pedersen_protocol():
	return PedersenProtocol(PedersenVerifier, PedersenProver) 

or_proof_protocol = OrProtocol(or_verifier_creator, or_prover_creator, create_pedersen_protocol(), create_pedersen_protocol())

or_proof_protocol.run()
