from PedersenWithParams import *
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
# If due to petlib you have a weird configuration of the python interpreter, you can run this like:
# python -m pytest unit_tests.py
# with "python" being the path or alias to the path of your python interpreter that has access to petlib utilities


def test_one_secret_per_generator(): 
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

	assert pedersen_protocol.verify()


#can be used to create ec points from hexa
def translate(hexa, group):
		return EcPt.from_binary(bytes(bytearray.fromhex(hexa)), G)

def test_one_generator_one_secret():
	G = EcGroup(713)
	gen = G.generator()
	pp = PedersenProof({"g1": gen}, ["x1"])
	prover = pp.getProver({"x1": 1})
	commitments = prover.commit()

	
	assert len(commitments) == 1

def get_generators(nb_wanted, start_index = 0):
	G = EcGroup(713)
	tab_g = []
	tab_g.append(("g"+str(start_index), G.generator()))
	for i in range (1,nb_wanted):
		randWord = randomword(30).encode("UTF-8")
		generator_name = "g" + str(i + start_index)
		tab_g.append((generator_name, G.hash_to_point(randWord)))
	return dict(tab_g)


def test_generators_sharing_a_secret():
	N = 10
	generators_dict = get_generators(N)
	pp = PedersenProof(generators_dict, ["x1"])
	prover = pp.getProver({"x1": 1})
	assert type(prover) == PedersenProver
	commitments = prover.commit()
	
	assert len(commitments) == len(generators_dict) and len(generators_dict) == N

def test_get_many_different_provers():
	N = 10
	generators_dict = get_generators(N)
	prefix = "secret_"
	pp = PedersenProof(generators_dict, [prefix+str(i) for i in range(N)])

	prover = pp.getProver(dict([(prefix + str(i), i) for i in range(N)]))
	commitments = prover.commit()
	assert len(commitments) == N

def test_and_proofs():
	n1 = 3
	n2 = 4
	generators_dict1 = get_generators(n1)
	generators_dict2 = get_generators(n2, start_index = n1)
	pp1 = PedersenProof(generators_dict1, ["x0", "x1", "x2"])
	pp2 = PedersenProof(generators_dict2, ["x0", "x3", "x4", "x5"]) #one shared secret x0
	and_proof = AndProof(pp1, pp2)
	and_prover = and_proof.getProver({"x0": 1, "x1": 2, "x2": 5, "x3": 100, "x4": 43, "x5": 10})
	and_verifier = and_proof.getVerifier()

	commitment = and_prover.commit()
	challenge = and_verifier.sendChallenge(commitment)
	response = and_prover.computeResponse(challenge)
	assert and_verifier.verify(response)



	

