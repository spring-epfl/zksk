from DLRep import *
from And_proof import AndProof
from Subproof import PublicInfo, Sec

N = 5
G = EcGroup(713)
tab_g = []
tab_g.append(G.generator())
for i in range(1, N):
    randWord = randomword(30).encode("UTF-8")
    tab_g.append(G.hash_to_point(randWord))
o = G.order()
secrets_aliases = ["x1", "x2", "x3", "x4", "x5"]
secrets_values = dict()
secret_tab = [
]  #This array is only useful to compute the public info because zip doesn't take dicts. #spaghetti
for wurd in secrets_aliases:  # we build N secrets
    secrets_values[wurd] = o.random()
    secret_tab.append(secrets_values[wurd])
    # peggy wishes to prove she knows the discrete logarithm equal to this value

powers = [a * b for a, b in zip(secret_tab, tab_g)
          ]  # The Ys of which we will prove logarithm knowledge
public_info = G.infinite()
for y in powers:
    public_info += y


def test_dlrep_true():  # Legit run
    pedersen_true = DLRepProof(tab_g, secrets_aliases, public_info)
    true_prover = pedersen_true.get_prover(secrets_values)
    true_verifier = pedersen_true.get_verifier()
    proof = SigmaProtocol(true_verifier, true_prover)
    assert proof.run() == True


def test_dlrep_wrong_public(
):  # We use generators and secrets from previous run but random public info
    randWord = randomword(30).encode("UTF-8")
    public_wrong = G.hash_to_point(randWord)
    pedersen_public_wrong = DLRepProof(tab_g, secrets_aliases, public_wrong)
    wrongprover = pedersen_public_wrong.get_prover(secrets_values)
    wrongverifier = pedersen_public_wrong.get_verifier()
    wrongpub = SigmaProtocol(wrongverifier, wrongprover)
    assert wrongpub.run() == False


def test_dlrep_NI():  #We request a non_inte_ractive proof from the prover
    niproof = DLRepProof(tab_g, secrets_aliases, public_info)
    niprover = niproof.get_prover(secrets_values)
    niverif = niproof.get_verifier()
    chal, resp = niprover.get_NI_proof("mymessage")
    assert niverif.verify_NI(chal, resp, "mymessage") == True


def test_dlrep_wrongNI():  #We request a non_inte_ractive proof from the prover
    niproof = DLRepProof(tab_g, secrets_aliases, public_info)
    niprover = niproof.get_prover(secrets_values)
    niverif = niproof.get_verifier()
    chal, resp = niprover.get_NI_proof("mymessage")
    resp[1] = tab_g[0].group.order().random()
    assert niverif.verify_NI(chal, resp, "mymessage") == False

def test_dlrep_simulation():
    ped_proof = DLRepProof(tab_g, secrets_aliases, public_info)
    sim_prover = ped_proof.get_simulator()
    sim_verif = ped_proof.get_verifier()
    (com, chal, resp) = sim_prover.simulate_proof()
    assert sim_verif.verify(resp, com, chal) == True


def test_diff_groups_dlrep():
    tab_g[2] = EcGroup(706).generator()
    with pytest.raises(
            Exception
    ):  # An exception should be raised due to different groups coexisting in a DLRepProof
        niproof = DLRepProof(tab_g, secrets_aliases, public_info)


# can be used to create ec points from hexa
def translate(hexa, group):
    return EcPt.from_binary(bytes(bytearray.fromhex(hexa)), G)


def test_one_generator_one_secret():
    G = EcGroup(713)
    gen = G.generator()
    pp = DLRepProof([gen], ["x1"], [gen])
    prover = pp.get_prover({"x1": 1})
    commitments = prover.commit()


def get_generators(nb_wanted, start_index=0):  #What is start_index?
    G = EcGroup(713)
    tab_g = []
    tab_g.append(G.generator())
    for i in range(1, nb_wanted):
        randWord = randomword(30).encode("UTF-8")
        tab_g.append(G.hash_to_point(randWord))
    return tab_g


def test_generators_sharing_a_secret():
    N = 10
    generators = get_generators(N)
    unique_secret = 4
    public_info = create_public_info(generators, [4 for g in generators])
    pp = DLRepProof(
        generators,
        ["x1", "x1", "x1", "x1", "x1", "x1", "x1", "x1", "x1", "x1"],
        public_info)
    prover = pp.get_prover({"x1": unique_secret})
    assert type(prover) == DLRepProver
    commitment = prover.commit()
    assert isinstance(commitment, EcPt)


def create_public_info(generators, secrets):
    sum_ = generators[0].group.infinite()
    for i in range(len(generators)):
        sum_ = sum_ + secrets[i] * generators[i]
    return sum_


def test_get_many_different_provers():
    N = 10
    generators = get_generators(N)
    prefix = "secret_"
    secrets_names = [prefix + str(i) for i in range(N)]
    secrets_vals = range(N)
    secr_dict = dict(zip(secrets_names, secrets_vals))
    pp = DLRepProof(generators, secrets_names,
                       create_public_info(generators, secrets_vals))
    prover = pp.get_prover(secr_dict)
    commitment = prover.commit()
    assert isinstance(commitment, EcPt)


def test_same_random_in_commitment():
    g = get_generators(1)[0]
    gens = [g, g, g]

    pub_info = create_public_info(gens, [100, 100, 100])

    pp = DLRepProof(gens, ["x1", "x1", "x1"], pub_info)
    prover = pp.get_prover({"x1": 100})
    commitments = prover.commit()


def setup_and_proofs():
    n1 = 3
    n2 = 4
    generators1 = get_generators(n1)
    generators2 = get_generators(n2, start_index=n1)

    secrets_dict = dict([("x0", 1), ("x1", 2), ("x2", 5), ("x3", 100),
                         ("x4", 43), ("x5", 10)])

    sum_1 = create_public_info(
        generators1,
        [secrets_dict["x0"], secrets_dict["x1"], secrets_dict["x2"]])
    secrets_2 = [secrets_dict["x0"]]
    for i in range(3, 6):
        secrets_2.append(secrets_dict["x" + str(i)])

    sum_2 = create_public_info(generators2, secrets_2)
    pp1 = DLRepProof(generators1, ["x0", "x1", "x2"], sum_1)

    pp2 = DLRepProof(generators2, ["x0", "x3", "x4", "x5"],
                        sum_2)  #one shared secret x0
    return pp1, pp2, secrets_dict


def test_wrong_and_proofs():  # An alien EcPt is inserted in the generators
    n1 = 3
    n2 = 1
    generators1 = get_generators(n1)
    generators2 = get_generators(n2)
    generators2[0] = EcGroup(706).generator()

    secrets_dict = dict([("x0", 1), ("x1", 2), ("x2", 5), ("x3", 100),
                         ("x4", 43), ("x5", 10)])
    sum_1 = create_public_info(
        generators1,
        [secrets_dict["x0"], secrets_dict["x1"], secrets_dict["x2"]])

    secrets_2 = [secrets_dict["x0"]]

    sum_2 = create_public_info(generators2, secrets_2)
    pp1 = DLRepProof(generators1, ["x0", "x1", "x2"], sum_1)
    pp2 = DLRepProof(generators2, ["x0"], sum_2)
    with pytest.raises(
            Exception
    ):  #An exception should be raised because of a shared secrets linked to two different groups
        and_proof = AndProof(pp1, pp2)


def assert_verify_proof(verifier, prover):
    commitment = prover.commit()
    challenge = verifier.send_challenge(commitment)
    response = prover.compute_response(challenge)
    assert verifier.verify(response)


def test_and_proofs():
    pp1, pp2, secrets_dict = setup_and_proofs()
    and_proof = AndProof(pp1, pp2)
    and_prover = and_proof.get_prover(secrets_dict)
    and_verifier = and_proof.get_verifier()

    assert_verify_proof(and_verifier, and_prover)


def test_compose_and_proofs():
    pp1, pp2, secrets_dict = setup_and_proofs()
    pp3 = AndProof(pp1, pp2)
    pp4 = AndProof(AndProof(pp1, pp2), pp1)
    prover = pp4.get_prover(secrets_dict)
    verifier = pp4.get_verifier()

    assert_verify_proof(verifier, prover)


def test_compose_and_proofs2():
    pp1, pp2, secrets_dict = setup_and_proofs()
    pp3 = AndProof(pp1, pp2)
    p = AndProof(AndProof(pp1, AndProof(pp3, AndProof(pp1, pp2))), pp2)
    prover = p.get_prover(secrets_dict)
    verifier = p.get_verifier()
    assert_verify_proof(verifier, prover)

class Infix:
    def __init__(self, function):
        self.function = function
    def __ror__(self, other):
        return Infix(lambda x, self=self, other=other: self.function(other, x))
    def __or__(self, other):
        return self.function(other)
    def __rlshift__(self, other):
        return Infix(lambda x, self=self, other=other: self.function(other, x))
    def __rshift__(self, other):
        return self.function(other)
    def __call__(self, value1, value2):
        return self.function(value1, value2)


def test_infix_and():
    pp1, pp2, secrets_dict = setup_and_proofs()
    _and_ = Infix(lambda proof1, proof2: AndProof(pp1, pp2))
    and_proof = pp1      |_and_|     pp2       |_and_| pp1
    prover = and_proof.get_prover(secrets_dict)
    verifier = and_proof.get_verifier()
    assert_verify_proof(verifier, prover)

def test_and_operator():
    pp1, pp2, secrets_dict = setup_and_proofs() 
    and_proof = pp1 & pp2 & pp1
    prover = and_proof.get_prover(secrets_dict)
    verifier = and_proof.get_verifier()
    assert_verify_proof(verifier, prover)


def test_DLRep_parser_proof_fails():
    g = EcGroup().generator()
    g1 = 2 * g
    g2 = 5 * g
    x1 = 10
    x2 = 15
    proof = PublicInfo(g) == Sec("x1") * g1 + Sec("x2") * g2
    prover = proof.get_prover({"x1": x1, "x2": x2})
    verifier = proof.get_verifier()
    with pytest.raises(
            Exception
    ):
        assert_verify_proof(verifier, prover)

def test_DLRep_parser_proof_succeeds():
    g = EcGroup().generator()
    g1 = 2 * g
    g2 = 5 * g
    x1 = 10
    x2 = 15
    proof = PublicInfo(x1 * g1 + x2 * g2) == Sec("x1") * g1 + Sec("x2") * g2
    prover = proof.get_prover({"x1": x1, "x2": x2})
    verifier = proof.get_verifier()
    assert_verify_proof(verifier, prover)

def test_DLRep_parser_with_and_proof():
    g = EcGroup().generator()
    g1 = 2 * g
    g2 = 5 * g
    g3 = 10 * g
    x1 = 10
    x2 = 15
    x3 = 35
    proof = (PublicInfo(x1 * g1 + x2 * g2) == Sec("x1") * g1 + Sec("x2") * g2) & (PublicInfo(x2 * g1 + x3 * g3) == Sec("x2") * g1 + Sec("x3") * g3)
    

    
