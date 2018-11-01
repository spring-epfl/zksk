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

def get_generators(nb_wanted):
	G = EcGroup(713)
	tab_g = []
	tab_g.append(("g0", G.generator()))
	for i in range (1,nb_wanted):
		randWord = randomword(30).encode("UTF-8")
		generator_name = "g" + str(i)
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
