

import os, sys

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_code_path = os.path.join(root_dir, "compiler")
sys.path.append(src_code_path)

from DLRep import *
from Subproof import *
from CompositionProofs import *
from pairings import *
from template_signature import *
from template_BLAC import *
import pytest

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
lhs = G.infinite()
for y in powers:
    lhs += y


def create_rhs(secrets_names, generators):
    return reduce(lambda x1, x2: x1 + x2, map(lambda t: Secret(t[0]) * t[1], zip(secrets_names, generators)))

rhs1 = create_rhs(secrets_aliases, tab_g)

def test_dlrep_true():  # Legit run
    pedersen_true = DLRepProof(lhs, rhs1)
    true_prover = pedersen_true.get_prover(secrets_values)
    true_verifier = pedersen_true.get_verifier()
    proof = SigmaProtocol(true_verifier, true_prover)
    assert proof.run() == True



def test_dlrep_wrong_public(
):  # We use generators and secrets from previous run but random public info
    randWord = randomword(30).encode("UTF-8")
    public_wrong = G.hash_to_point(randWord)
    pedersen_public_wrong = DLRepProof(public_wrong, rhs1)
    wrongprover = pedersen_public_wrong.get_prover(secrets_values)
    wrongverifier = pedersen_public_wrong.get_verifier()
    wrongpub = SigmaProtocol(wrongverifier, wrongprover)
    assert wrongpub.run() == False


def test_dlrep_NI():  #We request a non_inte_ractive proof from the prover
    niproof = DLRepProof(lhs, rhs1)
    niprover = niproof.get_prover(secrets_values)
    niverif = niproof.get_verifier()
    chal, resp = niprover.get_NI_proof("mymessage")
    assert niverif.verify_NI(chal, resp, "mymessage") == True


def test_dlrep_wrongNI():  #We request a non_inte_ractive proof from the prover
    niproof = DLRepProof(lhs, rhs1)
    niprover = niproof.get_prover(secrets_values)
    niverif = niproof.get_verifier()
    chal, resp = niprover.get_NI_proof("mymessage")
    resp[1] = tab_g[0].group.order().random()
    assert niverif.verify_NI(chal, resp, "mymessage") == False

def test_dlrep_simulation():
    ped_proof = DLRepProof(lhs, rhs1)
    sim_prover = ped_proof.get_simulator()
    sim_verif = ped_proof.get_verifier()
    (com, chal, resp) = sim_prover.simulate_proof()
    assert sim_verif.verify(resp, com, chal) == True


def test_diff_groups_dlrep():
    tab_g1 = tab_g.copy()
    tab_g1[2] = EcGroup(706).generator()
    with pytest.raises(
            Exception
    ):  # An exception should be raised due to different groups coexisting in a DLRepProof
        niproof = DLRepProof(tab_g1, secrets_aliases, lhs)


# can be used to create ec points from hexa
def translate(hexa, group):
    return EcPt.from_binary(bytes(bytearray.fromhex(hexa)), G)


def test_one_generator_one_secret():
    G = EcGroup(713)
    gen = G.generator()
    pp = DLRepProof([gen], Secret("x1") * gen)
    prover = pp.get_prover({"x1": 1})
    commitments = prover.commit()


def get_generators(nb_wanted, start_index =0):  #What is start_index?
    G = EcGroup(713)
    tab_g1 = []
    tab_g1.append(G.generator())
    for i in range(1, nb_wanted):
        randWord = randomword(30).encode("UTF-8")
        tab_g1.append(G.hash_to_point(randWord))
    return tab_g1


def test_generators_sharing_a_secret():
    N = 10
    generators = get_generators(N)
    unique_secret = 4
    lhs = create_lhs(generators, [4 for g in generators])

    def get_rhs(i):
        return Secret("x1") * generators[i]

    rhs = get_rhs(0)
    for i in range(1,N):
        rhs += get_rhs(i)

    pp = DLRepProof(
        lhs,
        rhs
        )
    prover = pp.get_prover({"x1": unique_secret})
    assert type(prover) == DLRepProver
    commitment = prover.commit()
    assert isinstance(commitment, EcPt)



def test_get_many_different_provers():
    N = 10
    generators = get_generators(N)
    prefix = "secret_"
    secrets_names = [prefix + str(i) for i in range(N)]
    secrets_vals = range(N)
    secr_dict = dict(zip(secrets_names, secrets_vals))
    pp = DLRepProof(create_lhs(generators, secrets_vals), create_rhs(secrets_names, generators))
    prover = pp.get_prover(secr_dict)
    commitment = prover.commit()
    assert isinstance(commitment, EcPt)


def test_same_random_in_commitment():
    g = get_generators(1)[0]
    gens = [g, g, g]

    pub_info = create_lhs(gens, [100, 100, 100])

    pp = DLRepProof(pub_info, create_rhs(["x1", "x1", "x1"], gens))
    prover = pp.get_prover({"x1": 100})
    commitments = prover.commit()


def setup_and_proofs():
    n1 = 3
    n2 = 4
    generators1 = get_generators(n1)
    generators2 = get_generators(n2, start_index=n1)

    secrets_dict = dict([("x0", 1), ("x1", 2), ("x2", 5), ("x3", 100),
                         ("x4", 43), ("x5", 10)])

    sum_1 = create_lhs(
        generators1,
        [secrets_dict["x0"], secrets_dict["x1"], secrets_dict["x2"]])
    secrets_2 = [secrets_dict["x0"]]
    for i in range(3, 6):
        secrets_2.append(secrets_dict["x" + str(i)])

    sum_2 = create_lhs(generators2, secrets_2)
    pp1 = DLRepProof(sum_1, create_rhs(["x0", "x1", "x2"], generators1))

    pp2 = DLRepProof(sum_2, create_rhs(["x0", "x3", "x4", "x5"], generators2)
                        )  #one shared secret x0
    return pp1, pp2, secrets_dict


def test_wrong_and_proofs():  # An alien EcPt is inserted in the generators
    n1 = 3
    n2 = 1
    generators1 = get_generators(n1)
    generators2 = get_generators(n2)
    generators2[0] = EcGroup(706).generator()

    secrets_dict = dict([("x0", 1), ("x1", 2), ("x2", 5), ("x3", 100),
                         ("x4", 43), ("x5", 10)])
    sum_1 = create_lhs(
        generators1,
        [secrets_dict["x0"], secrets_dict["x1"], secrets_dict["x2"]])

    secrets_2 = [secrets_dict["x0"]]

    sum_2 = create_lhs(generators2, secrets_2)
    pp1 = DLRepProof(sum_1, create_rhs(["x0", "x1", "x2"], generators1))
    pp2 = DLRepProof(sum_2, create_rhs(["x0"], generators2))
    with pytest.raises(
            Exception
    ):  #An exception should be raised because of a shared secrets linked to two different groups
        and_proof = AndProof(pp1, pp2)


def assert_verify_proof(verifier, prover):
    commitment = prover.commit()
    challenge = verifier.send_challenge(commitment)
    response = prover.compute_response(challenge)
    v = verifier.verify(response)
    assert (v == True)


def test_and_proofs():
    pp1, pp2, secrets_dict = setup_and_proofs()
    and_proof = AndProof(pp1, pp2)
    and_prover = and_proof.get_prover(secrets_dict)
    and_verifier = and_proof.get_verifier()

    assert_verify_proof(and_verifier, and_prover)


def test_wrong_and_proofs():
    pp1, pp2, secrets_dict = setup_and_proofs()
    and_proof = AndProof(pp1, pp2)
    sec = secrets_dict.copy()
    sec["x0"] = G.order().random()
    and_prover = and_proof.get_prover(sec)
    and_verifier = and_proof.get_verifier()

    commitment = and_prover.commit()
    challenge = and_verifier.send_challenge(commitment)
    response = and_prover.compute_response(challenge)
    v = and_verifier.verify(response)
    assert (v == False)

def test_3_and_proofs():
    pp1, pp2, secrets_dict = setup_and_proofs()
    and_proof = AndProof([pp1, pp2, pp2], pp1, pp1, [pp1, pp2])
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

def test_simulate_andproof():
    subproof1 = DLRepProof(lhs, create_rhs(secrets_aliases, tab_g))
    subproof2 = DLRepProof(lhs, create_rhs(secrets_aliases, tab_g))
    andp = AndProof(subproof1, subproof2)
    andv = andp.get_verifier()
    andsim = andp.get_simulator()
    com, ch, resp = andsim.simulate_proof()
    assert andv.verify(resp, com, ch) == True

def test_and_NI():
    p1, p2, secrets = setup_and_proofs()
    niproof = AndProof(p1, p2)
    andprov = niproof.get_prover(secrets)
    and_verifier = niproof.get_verifier()

    message = 'toto'
    chall, resp = andprov.get_NI_proof(message)
    assert and_verifier.verify_NI(chall, resp, message) == True


def test_wrong_and_NI():
    p1, p2, secrets = setup_and_proofs()
    niproof = AndProof(p1, p2)
    wrongs = secrets.copy()
    wrongs["x0"] = G.order().random()
    andprov = niproof.get_prover(wrongs)
    and_verifier = niproof.get_verifier()

    message = 'toto'
    chall, resp = andprov.get_NI_proof(message)
    assert and_verifier.verify_NI(chall, resp, message) == False


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
    proof = DLRepProof(g, Secret("x1") * g1 + Secret("x2") * g2)
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
    proof = DLRepProof(x1 * g1 + x2 * g2, Secret("x1") * g1 + Secret("x2") * g2)
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
    proof = DLRepProof(x1 * g1 + x2 * g2, Secret("x1") * g1 + Secret("x2") * g2) & DLRepProof(x2 * g1 + x3 * g3, Secret("x2") * g1 + Secret("x3") * g3)
    prover = proof.get_prover({"x1": x1, "x2": x2, "x3": x3})
    verifier = proof.get_verifier()
    assert_verify_proof(verifier, prover)

def test_DLRep_right_hand_side_eval():
    g = EcGroup().generator()
    g1 = 2 * g
    g2 = 5 * g
    g3 = 10 * g
    x1 = 10
    x2 = 15
    x3 = 35

    rhs = Secret("x1", value = x1) * g1 + Secret("x2", value = x2) * g2
    expected_lhs = x1 * g1 + x2 * g2
    assert rhs.eval() == expected_lhs

def test_DLRep_right_hand_side_eval():
    g = EcGroup().generator()
    g1 = 2 * g
    g2 = 5 * g
    g3 = 10 * g
    x1 = 10
    x2 = 15
    x3 = 35

    rhs = Secret("x1") * g1 + Secret("x2", value = x2) * g2
    with pytest.raises(
            Exception
    ):  #An exception should be raised because of a shared secrets linked to two different groups
        rhs.eval()

def test_or_proof_simple():
    pp1, pp2, secrets = setup_and_proofs()
    orproof = OrProof(pp1, pp2, pp1, pp2, pp1, pp2)
    prov = orproof.get_prover(secrets)
    verif = orproof.get_verifier()
    com = prov.commit()
    chal =verif.send_challenge(com)
    resp = prov.compute_response(chal)
    # Here we see that some responses have an identical first element
    # The only one with a different first element is the non simulated one
    assert verif.verify(resp)

def test_and_or_proof():
    pp1, pp2, secrets = setup_and_proofs()
    g1 = 7*pp1.generators[0]
    g2 = 8*pp1.generators[0]
    pp0 = DLRepProof(7 * g1 + 18 * g2, Secret("xb") * g1 + Secret("xa") * g2)
    secrets["xb"]=7
    secrets["xa"]=18
    orproof= OrProof(pp1, pp2)
    andp = AndProof(orproof, pp0)
    prov = andp.get_prover(secrets)
    ver = andp.get_verifier()
    com = prov.commit()
    chal = ver.send_challenge(com)
    resp = prov.compute_response(chal)
    assert ver.verify(resp)

def test_or_and_proof():
    pp1, pp2, secrets = setup_and_proofs()
    andp = AndProof(pp1, pp2)

    g1 = 7*pp1.generators[0]
    g2 = 8*pp1.generators[0]
    pp0 = DLRepProof(7 * g1 + 18 * g2, Secret("xb") * g1 + Secret("xa") * g2)
    secrets["xa"]=7
    secrets["xc"]=18
    orproof = OrProof(pp0, andp)
    prov = orproof.get_prover(secrets)
    ver = orproof.get_verifier()
    com = prov.commit()
    chal = ver.send_challenge(com)
    resp = prov.compute_response(chal)
    assert ver.verify(resp)

def test_or_or():
    pp1, pp2, secrets = setup_and_proofs()
    first_or = OrProof(pp1, pp2)
    g1 = 7*pp1.generators[0]
    g2 = 8*pp1.generators[0]
    pp0 = DLRepProof(7 * g1 + 18 * g2, Secret("xb") * g1 + Secret("xa") * g2)
    secrets["xa"]=7
    secrets["xc"]=18
    orproof = OrProof(pp0, first_or)
    prov = orproof.get_prover(secrets)
    ver = orproof.get_verifier()
    com = prov.commit()
    chal = ver.send_challenge(com)
    resp = prov.compute_response(chal)
    assert ver.verify(resp)

def test_or_sim():
    pp1, pp2, secrets = setup_and_proofs()
    first_or = OrProof(pp1, pp2)
    sim = first_or.get_simulator()
    ver = first_or.get_verifier()
    com, chal, resp = sim.simulate_proof()
    assert ver.verify(resp, com, chal)

def verify_proof(proof, secrets):
    prov = proof.get_prover(secrets)
    verif = proof.get_verifier()
    com = prov.commit()
    chal =verif.send_challenge(com)
    resp = prov.compute_response(chal)
    assert verif.verify(resp)

def test_multiple_or_proof():
    pp1, pp2, secrets = setup_and_proofs()
    g = EcGroup().generator()
    x10 = 13
    secrets.update({"x10": x10})
    orproof = OrProof(pp1, OrProof(pp2, DLRepProof(x10 * g, Secret("x10") * g)))
    verify_proof(orproof, secrets)

def test_multiple_or_proof_2():
    pp1, pp2, secrets = setup_and_proofs()
    g = EcGroup().generator()
    x10 = 13
    secrets.update({"x10": x10})
    orp1 = OrProof(pp2, pp1)
    orp2 = OrProof(pp1, DLRepProof(x10 * g, Secret("x10") * g))
    orproof = OrProof(orp1, pp2, orp2)
    verify_proof(orproof, secrets)

def test_or_proof_syntax():
    pp1, pp2, secrets = setup_and_proofs()
    orproof = pp1 | pp2
    verify_proof(orproof, secrets)


def test_multiple_or_proof_syntax():
    pp1, pp2, secrets = setup_and_proofs()
    g = EcGroup().generator()
    x10 = 13
    secrets.update({"x10": x10})
    orproof = pp1 | pp2 | DLRepProof(x10 * g, Secret("x10") * g)
    verify_proof(orproof, secrets)


def test_or_NI():
    p1, p2, secrets = setup_and_proofs()
    niproof = OrProof(p1, p2)
    orprov = niproof.get_prover(secrets)
    or_verifier = niproof.get_verifier()

    message = 'toto'
    chall, resp = orprov.get_NI_proof(message)
    assert or_verifier.verify_NI(chall, resp, message) == True


def test_wrong_or_NI():
    p1, p2, secrets = setup_and_proofs()
    niproof = OrProof(p1, p2)
    wrongs = secrets.copy()
    wrongs["x0"] = G.order().random()
    orprov = niproof.get_prover(wrongs)
    or_verifier = niproof.get_verifier()

    message = 'toto'
    chall, resp = orprov.get_NI_proof(message)
    assert or_verifier.verify_NI(chall, resp, message) == False


def test_malicious_and_proofs():
    x0=3
    x2=50
    x1 = 12
    xm = 51
    tab_g = get_generators(3)
    g1 = tab_g[0]
    g2 = tab_g[1]
    g3 = tab_g[2]
    secret_dict = {'x0': 3, 'x2': 50, 'x1': 12}
    mal_secret_dict = {'x0': 3, 'x2': 51}
    andp = AndProof(
        DLRepProof(x1 * g1 + x2 * g2,
                   Secret("x1") * g1 + Secret("x2") * g2),
        DLRepProof(x0 * g3 + xm * g2,
                   Secret("x0") * g1 + Secret("x2") * g2))

    prov = andp.get_prover(secret_dict)
    prov.subs[1].secret_values = mal_secret_dict
    verif = andp.get_verifier()

    com = prov.commit()
    chal = verif.send_challenge(com)
    resp = prov.compute_response(chal)
    with pytest.raises(Exception):
        v = verif.verify(resp)

def test_signature_setup():
    mG =BilinearGroupPair()
    g,h = mG.G1.generator(), mG.G2.generator()
    w = [mG.G1.order().random() for i in range(5)]
    generators = [g*k for k in w]
    henerators = [h*k for k in w]
    keypair = gen_keys(generators, henerators)
    messages = [Bn(30), Bn(31), Bn(32)]
    assert sign_and_verify(messages, keypair) and sign_and_verify(messages, keypair, zkp=True)


def test_BLAC():
    pr= DLRepNotEqualProof()
    G = EcGroup()
    g = G.generator()
    x = 3
    y = x*g
    y2 = 397474*g
    g2 = 1397*g
    pr.initialize([y, y2], [g, g2], "x")
    secret_dict = {"x":3}
    prov = pr.get_prover(secret_dict)
    commitment = prov.commit()
    ver = pr.get_verifier()
    chal = ver.send_challenge(commitment)
    resp = prov.compute_response(chal)
    assert ver.verify(resp)
