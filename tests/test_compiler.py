import os, sys

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_code_path = os.path.join(root_dir, "compiler")
sys.path.append(src_code_path)

from primitives.DLRep import *
from CompositionProofs import *
from BilinearPairings import *
from primitives.BBSplus import *
from primitives.DLRepNotEqual import *
from Abstractions import *
import pytest
import pdb


class SigmaProtocol:
    """
    an interface for sigma protocols.
    """

    def __init__(self, verifierClass, proverClass):
        self.verifierClass = verifierClass
        self.proverClass = proverClass

    def setup(self):
        pass

    def verify(self) -> bool:
        victor = self.verifierClass
        peggy = self.proverClass
        precommitment = peggy.precommit()
        victor.process_precommitment(precommitment)
        (commitment) = peggy.commit()
        challenge = victor.send_challenge(commitment)
        response = peggy.compute_response(challenge)
        return victor.verify(response)

    def run(self):
        if self.verify():
            print("Verified for {0}".format(self.__class__.__name__))
            return True
        else:
            print("Not verified for {0}".format(self.__class__.__name__))
            return False


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
secret_tab = []
# This array is only useful to compute the public info because zip doesn't take dicts. #spaghetti
for wurd in secrets_aliases:  # we build N secrets
    secrets_values[wurd] = o.random()
    secret_tab.append(secrets_values[wurd])
# peggy wishes to prove she knows the discrete logarithm equal to this value

lhs = G.wsum(secret_tab, tab_g)

rhs1 = create_rhs(secrets_aliases, tab_g)


def test_dlrep_true():
    # Legit run
    pedersen_true = DLRepProof(lhs, rhs1)
    true_prover = pedersen_true.get_prover(secrets_values)
    true_verifier = pedersen_true.get_verifier()
    proof = SigmaProtocol(true_verifier, true_prover)
    assert proof.run() == True


def test_dlrep_wrong_public():
    # We use generators and secrets from previous run but random public info
    randWord = randomword(30).encode("UTF-8")
    public_wrong = G.hash_to_point(randWord)
    pedersen_public_wrong = DLRepProof(public_wrong, rhs1)
    wrongprover = pedersen_public_wrong.get_prover(secrets_values)
    wrongverifier = pedersen_public_wrong.get_verifier()
    wrongpub = SigmaProtocol(wrongverifier, wrongprover)
    assert wrongpub.run() == False


def test_dlrep_NI():
    # We request a non_interactive proof from the prover
    niproof = DLRepProof(lhs, rhs1)
    tr = niproof.prove(secrets_values, message="mymessage")
    assert niproof.verify(tr, message="mymessage") == True


def test_dlrep_wrongNI():
    # We request a non_interactive proof from the prover
    niproof = DLRepProof(lhs, rhs1)
    tr = niproof.prove(secrets_values, message="mymessage")
    tr.responses[1] = tab_g[0].group.order().random()
    assert niproof.verify(tr, message="mymessage") == False


def test_dlrep_simulation():
    ped_proof = DLRepProof(lhs, rhs1)
    sim_prover = ped_proof.get_simulator()
    sim_verif = ped_proof.get_verifier()
    tr = sim_prover.simulate_proof()
    assert sim_verif.verify(tr) == True


def test_diff_groups_dlrep():
    tab_g1 = tab_g.copy()
    tab_g1[2] = EcGroup(706).generator()
    with pytest.raises(Exception):
        # An exception should be raised due to different groups coexisting in a DLRepProof
        niproof = DLRepProof(tab_g1, secrets_aliases, lhs)


def get_generators(nb_wanted, start_index=0):  # What is start_index?
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
    lhs = G.wsum([Bn(unique_secret) for g in generators], generators)

    def get_rhs(i):
        return Secret("x1") * generators[i]

    rhs = get_rhs(0)
    for i in range(1, N):
        rhs += get_rhs(i)

    pp = DLRepProof(lhs, rhs)
    prover = pp.get_prover({"x1": unique_secret})
    assert type(prover) == DLRepProver
    commitment = prover.commit()
    assert isinstance(commitment, EcPt)


def test_get_many_different_provers():
    N = 10
    generators = get_generators(N)
    prefix = "secret_"
    secrets_names = [prefix + str(i) for i in range(N)]
    secrets_vals = [Bn(i) for i in range(N)]
    secr_dict = dict(zip(secrets_names, secrets_vals))
    pp = DLRepProof(
        G.wsum(secrets_vals, generators), create_rhs(secrets_names, generators)
    )
    prover = pp.get_prover(secr_dict)
    commitment = prover.commit()
    assert isinstance(commitment, EcPt)


def test_same_random_in_commitment():
    g = get_generators(1)[0]
    gens = [g, g, g]

    pub_info = G.wsum([Bn(100), Bn(100), Bn(100)], gens)

    pp = DLRepProof(pub_info, create_rhs(["x1", "x1", "x1"], gens))
    prover = pp.get_prover({"x1": 100})
    commitments = prover.commit()


def setup_and_proofs():
    n1 = 3
    n2 = 4
    generators1 = get_generators(n1)
    generators2 = get_generators(n2, start_index=n1)

    secrets_dict = dict(
        [
            ("x0", Bn(1)),
            ("x1", Bn(2)),
            ("x2", Bn(5)),
            ("x3", Bn(100)),
            ("x4", Bn(43)),
            ("x5", Bn(10)),
        ]
    )

    sum_1 = G.wsum(
        [secrets_dict["x0"], secrets_dict["x1"], secrets_dict["x2"]], generators1
    )
    secrets_2 = [secrets_dict["x0"]]
    for i in range(3, 6):
        secrets_2.append(secrets_dict["x" + str(i)])

    sum_2 = G.wsum(secrets_2, generators2)
    pp1 = DLRepProof(sum_1, create_rhs(["x0", "x1", "x2"], generators1))

    pp2 = DLRepProof(sum_2, create_rhs(["x0", "x3", "x4", "x5"], generators2))
    return pp1, pp2, secrets_dict


def test_wrong_and_proofs():
    # An alien EcPt is inserted in the generators
    n1 = 3
    n2 = 1
    generators1 = get_generators(n1)
    generators2 = get_generators(n2)
    generators2[0] = EcGroup(706).generator()

    secrets_dict = dict(
        [
            ("x0", Bn(1)),
            ("x1", Bn(2)),
            ("x2", Bn(5)),
            ("x3", Bn(100)),
            ("x4", Bn(43)),
            ("x5", Bn(10)),
        ]
    )
    sum_1 = G.wsum(
        [secrets_dict["x0"], secrets_dict["x1"], secrets_dict["x2"]], generators1
    )

    secrets_2 = [secrets_dict["x0"]]

    sum_2 = G.wsum(secrets_2, generators2)
    pp1 = DLRepProof(sum_1, create_rhs(["x0", "x1", "x2"], generators1))
    pp2 = DLRepProof(sum_2, create_rhs(["x0"], generators2))
    with pytest.raises(Exception):
        # An exception should be raised because of a shared secrets linked to two different groups
        and_proof = AndProof(pp1, pp2)


def assert_verify_proof(verifier, prover):
    commitment = prover.commit()
    challenge = verifier.send_challenge(commitment)
    response = prover.compute_response(challenge)
    v = verifier.verify(response)
    assert v == True


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
    assert v == False


def test_3_and_proofs():
    pp1, pp2, secrets_dict = setup_and_proofs()
    and_proof = AndProof(pp1, pp2, pp2, pp1, pp1, pp1, pp2)
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
    tr = andsim.simulate_proof()
    assert andv.verify(tr) == True


def test_and_NI():
    p1, p2, secrets = setup_and_proofs()
    niproof = AndProof(p1, p2)
    message = "toto"
    tr = niproof.prove(secrets, message=message)
    assert niproof.verify(tr, message=message) == True


def test_wrong_and_NI():
    p1, p2, secrets = setup_and_proofs()
    niproof = AndProof(p1, p2)
    wrongs = secrets.copy()
    wrongs["x0"] = G.order().random()
    message = "toto"
    tr = niproof.prove(wrongs, message=message)
    assert niproof.verify(tr, message=message) == False


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
    with pytest.raises(Exception):
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
    proof = DLRepProof(
        x1 * g1 + x2 * g2, Secret("x1") * g1 + Secret("x2") * g2
    ) & DLRepProof(x2 * g1 + x3 * g3, Secret("x2") * g1 + Secret("x3") * g3)
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

    rhs = Secret("x1", value=x1) * g1 + Secret("x2", value=x2) * g2
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

    rhs = Secret("x1") * g1 + Secret("x2", value=x2) * g2
    with pytest.raises(
        Exception
    ):  # An exception should be raised because of a shared secrets linked to two different groups
        rhs.eval()


def test_or_proof_simple():
    pp1, pp2, secrets = setup_and_proofs()
    orproof = OrProof(pp1, pp2, pp1, pp2, pp1, pp2)
    prov = orproof.get_prover(secrets)
    verif = orproof.get_verifier()
    com = prov.commit()
    chal = verif.send_challenge(com)
    resp = prov.compute_response(chal)
    # Here we see that some responses have an identical first element
    # The only one with a different first element is the non simulated one
    assert verif.verify(resp)


def test_and_or_proof():
    pp1, pp2, secrets = setup_and_proofs()
    g1 = 7 * pp1.generators[0]
    g2 = 8 * pp1.generators[0]
    pp0 = DLRepProof(7 * g1 + 18 * g2, Secret("xb") * g1 + Secret("xa") * g2)
    secrets["xb"] = 7
    secrets["xa"] = 18
    orproof = OrProof(pp1, pp2)
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

    g1 = 7 * pp1.generators[0]
    g2 = 8 * pp1.generators[0]
    pp0 = DLRepProof(7 * g1 + 18 * g2, Secret("xb") * g1 + Secret("xa") * g2)
    secrets["xa"] = 7
    secrets["xc"] = 18
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
    g1 = 7 * pp1.generators[0]
    g2 = 8 * pp1.generators[0]
    pp0 = DLRepProof(7 * g1 + 18 * g2, Secret("xb") * g1 + Secret("xa") * g2)
    secrets["xa"] = 7
    secrets["xc"] = 18
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
    tr = sim.simulate_proof()
    assert ver.verify(tr)


def verify_proof(proof, secrets):
    prov = proof.get_prover(secrets)
    verif = proof.get_verifier()
    com = prov.commit()
    chal = verif.send_challenge(com)
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
    message = "toto"
    tr = niproof.prove(secrets, message=message)
    assert niproof.verify(tr, message=message) == True


def test_wrong_or_NI():
    p1, p2, secrets = setup_and_proofs()
    niproof = OrProof(p1, p2)
    wrongs = secrets.copy()
    wrongs["x0"] = G.order().random()

    message = "toto"
    tr = niproof.prove(wrongs, message=message)
    assert niproof.verify(tr, message=message) == False


def test_malicious_and_proofs():
    x0 = 3
    x2 = 50
    x1 = 12
    xm = 51
    tab_g = get_generators(3)
    g1 = tab_g[0]
    g2 = tab_g[1]
    g3 = tab_g[2]
    secret_dict = {"x0": 3, "x2": 50, "x1": 12}
    mal_secret_dict = {"x0": 3, "x2": 51}
    andp = AndProof(
        DLRepProof(x1 * g1 + x2 * g2, Secret("x1") * g1 + Secret("x2") * g2),
        DLRepProof(x0 * g3 + xm * g2, Secret("x0") * g1 + Secret("x2") * g2),
    )

    prov = andp.get_prover(secret_dict)
    prov.subs[1].secret_values = mal_secret_dict
    verif = andp.get_verifier()

    com = prov.commit()
    chal = verif.send_challenge(com)
    resp = prov.compute_response(chal)
    with pytest.raises(Exception):
        v = verif.verify(resp)


def test_BLAC():
    G = EcGroup()
    g = G.generator()
    x = 3
    y = x * g
    y2 = 397474 * g
    g2 = 1397 * g

    pr = DLRepNotEqualProof([y, g], [y2, g2], ["x"], binding=True)
    prv = DLRepNotEqualProof([y, g], [y2, g2], ["x"], binding=True)
    secret_dict = {"x": 3}
    prov = pr.get_prover(secret_dict)
    ver = prv.get_verifier()

    ver.process_precommitment(prov.precommit())
    commitment = prov.commit()
    chal = ver.send_challenge(commitment)

    resp = prov.compute_response(chal)
    assert ver.check_adequate_lhs() and ver.verify(resp)


def test_false_BLAC1():
    G = EcGroup()
    g = G.generator()
    x = 3
    y = x * g
    g2 = 1397 * g
    y2 = 3 * g2

    pr = DLRepNotEqualProof([y, g], [y2, g2], ["x"])
    prv = DLRepNotEqualProof([y, g], [y2, g2], ["x"])
    secret_dict = {"x": 3}
    prov = pr.get_prover(secret_dict)
    ver = prv.get_verifier()
    ver.process_precommitment(prov.precommit())
    commitment = prov.commit()
    chal = ver.send_challenge(commitment)
    resp = prov.compute_response(chal)
    assert not ver.verify(resp)


def test_and_BLAC():
    lhs_tab = [x * g for x, g in zip(secret_tab, tab_g)]
    pr1 = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=True,
    )
    pr2 = DLRepNotEqualProof(
        [lhs_tab[1], tab_g[1]], [lhs_tab[2], tab_g[2]], [secrets_aliases[1]]
    )
    andp = pr1 & pr2

    pr1v = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=True,
    )
    pr2v = DLRepNotEqualProof(
        [lhs_tab[1], tab_g[1]], [lhs_tab[2], tab_g[2]], [secrets_aliases[1]]
    )

    andpv = pr1v & pr2v
    prot = SigmaProtocol(andpv.get_verifier(), andp.get_prover(secrets_values))
    assert prot.run()


def test_not_and_BLAC():
    # Second subproof not correct since the two members have the same DL

    lhs_tab = [x * g for x, g in zip(secret_tab, tab_g)]
    y3 = secret_tab[1] * tab_g[3]
    pr1 = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=True,
    )
    pr2 = DLRepNotEqualProof(
        [lhs_tab[1], tab_g[1]], [y3, tab_g[3]], [secrets_aliases[1]]
    )

    andp = pr1 & pr2

    pr1v = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=True,
    )
    pr2v = DLRepNotEqualProof(
        [lhs_tab[1], tab_g[1]], [y3, tab_g[3]], [secrets_aliases[1]]
    )

    andpv = pr1v & pr2v
    prot = SigmaProtocol(andpv.get_verifier(), andp.get_prover(secrets_values))
    assert not prot.run()


def test_and_BLAC_binding1():
    lhs_tab = [x * g for x, g in zip(secret_tab, tab_g)]
    pr1 = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=True,
    )
    pr2 = DLRepProof(lhs_tab[0], Secret(secrets_aliases[0]) * tab_g[0])

    andp = pr1 & pr2
    pr1v = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=True,
    )
    pr2v = DLRepProof(lhs_tab[0], Secret(secrets_aliases[0]) * tab_g[0])

    andpv = pr1v & pr2v

    prot = SigmaProtocol(andpv.get_verifier(), andp.get_prover(secrets_values))
    assert prot.run()


def test_and_BLAC_not_binding():
    # Prove (H0 = h0*x, H1 != h1*x) , H2 = h2*x with same secret name x. should not be detected since binding=False by default.
    lhs_tab = [x * g for x, g in zip(secret_tab, tab_g)]
    y3 = secret_tab[2] * tab_g[3]

    pr1 = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]], [lhs_tab[1], tab_g[1]], [secrets_aliases[0]]
    )
    pr2 = DLRepProof(lhs_tab[2], Secret(secrets_aliases[0]) * tab_g[2])
    andp = pr1 & pr2

    pr1v = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]], [lhs_tab[1], tab_g[1]], [secrets_aliases[0]]
    )
    pr2v = DLRepProof(lhs_tab[2], Secret(secrets_aliases[0]) * tab_g[2])
    andpv = pr1v & pr2v

    prov = andp.get_prover(secrets_values)
    prov.subs[1].secret_values[secrets_aliases[0]] = secret_tab[2]

    prot = SigmaProtocol(andpv.get_verifier(), prov)
    assert prot.run()


def test_and_BLAC_binding2():
    # Prove (H0 = h0*x, H1 != h1*x) , H2 = h2*x with same secret name x. should be detected since binding=True.
    lhs_tab = [x * g for x, g in zip(secret_tab, tab_g)]
    y3 = secret_tab[2] * tab_g[3]

    pr1 = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=True,
    )
    pr2 = DLRepProof(lhs_tab[2], Secret(secrets_aliases[0]) * tab_g[2])
    andp = pr1 & pr2
    pr1v = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=True,
    )
    pr2v = DLRepProof(lhs_tab[2], Secret(secrets_aliases[0]) * tab_g[2])
    andpv = pr1v & pr2v

    prov = andp.get_prover(secrets_values)
    prov.subs[1].secret_values[secrets_aliases[0]] = secret_tab[2]

    ver = andpv.get_verifier()
    ver.process_precommitment(prov.precommit())
    com = prov.commit()
    chal = ver.send_challenge(com)
    resp = prov.compute_response(chal)
    with pytest.raises(Exception):
        ver.verify(resp)


def test_not_and_BLAC_binding():
    # Claim to use (H0 = h0*x, H1 != h1*x) , (H1 = h1*x, H3 != h3*x) with the same x. (not only cheating, a contradiction)
    # Should be detected since binding = True

    lhs_tab = [x * g for x, g in zip(secret_tab, tab_g)]
    y3 = secret_tab[2] * tab_g[3]

    pr1 = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=True,
    )
    pr2 = DLRepNotEqualProof(
        [lhs_tab[1], tab_g[1]], [y3, tab_g[3]], [secrets_aliases[0]], binding=True
    )
    andp = pr1 & pr2

    pr1v = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=True,
    )
    pr2v = DLRepNotEqualProof(
        [lhs_tab[1], tab_g[1]], [y3, tab_g[3]], [secrets_aliases[0]], binding=True
    )
    andpv = pr1v & pr2v

    prov = andp.get_prover(secrets_values)
    prov.subs[1].secret_values[secrets_aliases[0]] = secret_tab[1]

    prot = SigmaProtocol(andpv.get_verifier(), prov)
    with pytest.raises(Exception):
        prot.run()


def test_and_BLAC_binding3():
    # Claim to use (H0 = h0*x, H1 != h1*x) , (H1 = h1*x, H3 != h3*x) with the same x. (not only cheating, a contradiction)
    # Should be undetected since binding = False in at least one proof

    lhs_tab = [x * g for x, g in zip(secret_tab, tab_g)]
    y3 = secret_tab[2] * tab_g[3]

    pr1 = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=False,
    )
    pr2 = DLRepNotEqualProof(
        [lhs_tab[1], tab_g[1]], [y3, tab_g[3]], [secrets_aliases[0]], binding=True
    )
    andp = pr1 & pr2
    pr1v = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=False,
    )
    pr2v = DLRepNotEqualProof(
        [lhs_tab[1], tab_g[1]], [y3, tab_g[3]], [secrets_aliases[0]], binding=True
    )
    andpv = pr1v & pr2v

    prov = andp.get_prover(secrets_values)
    prov.subs[1].secret_values[secrets_aliases[0]] = secret_tab[1]

    prot = SigmaProtocol(andpv.get_verifier(), prov)
    assert prot.run()


def test_multi_and_BLAC_binding1():
    lhs_tab = [x * g for x, g in zip(secret_tab, tab_g)]
    pr1 = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=True,
    )
    pr2 = DLRepProof(lhs_tab[0], Secret(secrets_aliases[0]) * tab_g[0])

    pr3 = DLRepNotEqualProof(
        [lhs_tab[2], tab_g[2]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[2]],
        binding=True,
    )
    pr4 = DLRepNotEqualProof(
        [lhs_tab[1], tab_g[1]],
        [lhs_tab[3], tab_g[3]],
        [secrets_aliases[0]],
        binding=True,
    )

    andp = pr1 & pr2 & pr3 & pr4

    pr11 = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=True,
    )
    pr21 = DLRepProof(lhs_tab[0], Secret(secrets_aliases[0]) * tab_g[0])

    pr31 = DLRepNotEqualProof(
        [lhs_tab[2], tab_g[2]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[2]],
        binding=True,
    )
    pr41 = DLRepNotEqualProof(
        [lhs_tab[1], tab_g[1]],
        [lhs_tab[3], tab_g[3]],
        [secrets_aliases[0]],
        binding=True,
    )

    andp1 = pr11 & pr21 & pr31 & pr41

    prov = andp.get_prover(secrets_values)
    prov.subs[1].secret_values[secrets_aliases[0]] = secret_tab[1]

    prot = SigmaProtocol(andp1.get_verifier(), prov)
    with pytest.raises(Exception):
        prot.run()


def test_multi_and_BLAC_binding2():
    lhs_tab = [x * g for x, g in zip(secret_tab, tab_g)]
    pr1 = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=False,
    )
    pr2 = DLRepProof(lhs_tab[2], Secret(secrets_aliases[2]) * tab_g[2])

    pr3 = DLRepNotEqualProof(
        [lhs_tab[2], tab_g[2]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[2]],
        binding=True,
    )
    pr4 = DLRepNotEqualProof(
        [lhs_tab[1], tab_g[1]],
        [lhs_tab[3], tab_g[3]],
        [secrets_aliases[0]],
        binding=True,
    )

    andp = pr1 & pr2 & pr3 & pr4

    pr11 = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=False,
    )
    pr21 = DLRepProof(lhs_tab[2], Secret(secrets_aliases[2]) * tab_g[2])

    pr31 = DLRepNotEqualProof(
        [lhs_tab[2], tab_g[2]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[2]],
        binding=True,
    )
    pr41 = DLRepNotEqualProof(
        [lhs_tab[1], tab_g[1]],
        [lhs_tab[3], tab_g[3]],
        [secrets_aliases[0]],
        binding=True,
    )

    andp1 = pr11 & pr21 & pr31 & pr41
    prov = andp.get_prover(secrets_values)
    prov.subs[1].secret_values[secrets_aliases[0]] = secret_tab[1]

    prot = SigmaProtocol(andp1.get_verifier(), prov)
    assert prot.run()


def test_BLAC_NI():
    G = EcGroup()
    g = G.generator()
    x = 3
    y = x * g
    y2 = 397474 * g
    g2 = 1397 * g

    pr = DLRepNotEqualProof([y, g], [y2, g2], ["x"], binding=True)
    secret_dict = {"x": 3}
    nip = pr.prove(secret_dict)
    pr2 = DLRepNotEqualProof([y, g], [y2, g2], ["x"], binding=True)
    assert pr2.verify(nip)


def test_BLAC_NI2():
    lhs_tab = [x * g for x, g in zip(secret_tab, tab_g)]
    pr1 = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=True,
    )
    pr2 = DLRepProof(lhs_tab[0], Secret(secrets_aliases[0]) * tab_g[0])

    pr3 = DLRepNotEqualProof(
        [lhs_tab[2], tab_g[2]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[2]],
        binding=True,
    )

    andp = pr1 & pr2 & pr3

    pr11 = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=True,
    )
    pr21 = DLRepProof(lhs_tab[0], Secret(secrets_aliases[0]) * tab_g[0])

    pr31 = DLRepNotEqualProof(
        [lhs_tab[2], tab_g[2]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[2]],
        binding=True,
    )

    andp1 = pr11 & pr21 & pr31

    nip = andp.prove(secrets_values)
    assert andp1.verify(nip)


def test_sim_DLRNE():
    g = G.generator()
    x = 3
    y = x * g
    y2 = 397474 * g
    g2 = 1397 * g

    pr = DLRepNotEqualProof([y, g], [y2, g2], ["x"], binding=True)
    secret_dict = {"x": 3}
    prover = pr.get_prover()
    ver = pr.get_verifier()
    tr = prover.simulate_proof()
    assert ver.verify(tr)


def test_sim_multiDLRNE():

    lhs_tab = [x * g for x, g in zip(secret_tab, tab_g)]
    pr1 = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=False,
    )
    pr2 = DLRepProof(lhs_tab[2], Secret(secrets_aliases[2]) * tab_g[2])

    pr3 = DLRepNotEqualProof(
        [lhs_tab[2], tab_g[2]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[2]],
        binding=True,
    )
    pr4 = DLRepNotEqualProof(
        [lhs_tab[1], tab_g[1]],
        [lhs_tab[3], tab_g[3]],
        [secrets_aliases[0]],
        binding=True,
    )

    andp = pr1 & pr2 & pr3 & pr4
    prover = andp.get_prover()
    ver = andp.get_verifier()
    tr = prover.simulate_proof()
    assert ver.verify(tr)


def test_DLRNE_sim_binding():

    lhs_tab = [x * g for x, g in zip(secret_tab, tab_g)]
    y3 = secret_tab[2] * tab_g[3]

    pr1 = DLRepNotEqualProof(
        [lhs_tab[0], tab_g[0]],
        [lhs_tab[1], tab_g[1]],
        [secrets_aliases[0]],
        binding=True,
    )
    pr2 = DLRepNotEqualProof(
        [lhs_tab[1], tab_g[1]], [y3, tab_g[3]], [secrets_aliases[0]], binding=True
    )
    andp = pr1 & pr2
    prov = andp.get_prover()
    ver = andp.get_verifier()
    sim = prov.simulate_proof()
    assert ver.verify(sim)


def test_or_DLRNE():
    pass


def test_signature_setup():
    mG = BilinearGroupPair()
    keypair = KeyPair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]

    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    usr_commitment = creator.commit(messages, zkp=True)
    presignature = sk.sign(usr_commitment.commitment_message)
    signature = creator.obtain_signature(presignature)

    assert usr_commitment.verify_blinding(
        pk, len(messages)
    ) and signature.verify_signature(pk, messages)


def test_signature_proof():
    mG = BilinearGroupPair()
    keypair = KeyPair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]

    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.commitment_message)
    signature = creator.obtain_signature(presignature)
    secret_dict = {
        "e": signature.e,
        "s": signature.s,
        "m1": messages[0],
        "m2": messages[1],
        "m3": messages[2],
    }

    sigproof = SignatureProof(signature, ["e", "s", "m1", "m2", "m3"], pk)
    prov = sigproof.get_prover(secret_dict)
    sigproof1 = SignatureProof(signature, ["e", "s", "m1", "m2", "m3"], pk)
    ver = sigproof1.get_verifier()
    ver.process_precommitment(prov.precommit())
    comm = prov.commit()
    chal = ver.send_challenge(comm)
    resp = prov.compute_response(chal)
    assert ver.verify(resp)


def test_and_sig():
    mG = BilinearGroupPair()
    keypair = KeyPair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]

    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.commitment_message)
    signature = creator.obtain_signature(presignature)
    secret_dict = {
        "e": signature.e,
        "s": signature.s,
        "m1": messages[0],
        "m2": messages[1],
        "m3": messages[2],
    }
    sigproof = SignatureProof(signature, ["e", "s", "m1", "m2", "m3"], pk)

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature2 = sk.sign(lhs.commitment_message)
    signature2 = creator.obtain_signature(presignature2)
    secret_dict2 = {
        "e1": signature2.e,
        "s1": signature2.s,
        "m1": messages[0],
        "m2": messages[1],
        "m3": messages[2],
    }
    sigproof1 = SignatureProof(signature2, ["e1", "s1", "m1", "m2", "m3"], pk)

    secret_dict.update(secret_dict2)
    andp = sigproof & sigproof1
    prov = andp.get_prover(secret_dict)
    ver = andp.get_verifier()
    prot = SigmaProtocol(ver, prov)
    assert prot.run()


def test_signature_and_DLRNE():
    """
    Constructs a signature on a set of messages, and then pairs the proof of knowledge of this signature with
    a proof of non-equality of two DL, one of which is the blinding exponent 's' of the signature.
    """
    mG = BilinearGroupPair()
    keypair = KeyPair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]
    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.commitment_message)
    signature = creator.obtain_signature(presignature)
    secret_dict = {
        "e": signature.e,
        "s": signature.s,
        "m1": messages[0],
        "m2": messages[1],
        "m3": messages[2],
    }
    sigproof = SignatureProof(signature, ["e", "s", "m1", "m2", "m3"], pk)

    g1 = mG.G1.generator()
    pg1 = signature.s * g1
    pg2, g2 = mG.G1.order().random() * g1, mG.G1.order().random() * g1
    dneq = DLRepNotEqualProof((pg1, g1), (pg2, g2), ["s"], binding=True)
    sigproof1 = SignatureProof(signature, ["e", "s", "m1", "m2", "m3"], pk)
    dneq1 = DLRepNotEqualProof((pg1, g1), (pg2, g2), ["s"], binding=True)

    andp = sigproof & dneq
    andp1 = sigproof1 & dneq1
    prov = andp.get_prover(secret_dict)
    ver = andp1.get_verifier()
    ver.process_precommitment(prov.precommit())
    commitment = prov.commit()

    challenge = ver.send_challenge(commitment)
    responses = prov.compute_response(challenge)
    assert ver.verify(responses)


def test_wrong_signature_and_DLRNE():
    """
    We manually modify a secret in the DLRNE member, i.e we wrongfully claim to use the same "s" i the 
    signature and in the DLRNE.
    Should be detected and raise an Exception.
    """
    mG = BilinearGroupPair()
    keypair = KeyPair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]
    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.commitment_message)
    signature = creator.obtain_signature(presignature)
    secret_dict = {
        "e": signature.e,
        "s": signature.s,
        "m1": messages[0],
        "m2": messages[1],
        "m3": messages[2],
    }
    sigproof = SignatureProof(signature, ["e", "s", "m1", "m2", "m3"], pk)

    g1 = mG.G1.generator()
    pg1 = signature.s * g1
    pg2, g2 = mG.G1.order().random() * g1, mG.G1.order().random() * g1
    dneq = DLRepNotEqualProof((pg1, g1), (pg2, g2), ["s"], binding=True)
    sigproof1 = SignatureProof(signature, ["e", "s", "m1", "m2", "m3"], pk)
    dneq1 = DLRepNotEqualProof((pg1, g1), (pg2, g2), ["s"], binding=True)

    andp = sigproof & dneq
    andp1 = sigproof1 & dneq1
    prov = andp.get_prover(secret_dict)

    prov.subs[1].secret_values["s"] = signature.s + 1
    ver = andp1.get_verifier()
    ver.process_precommitment(prov.precommit())

    commitment = prov.commit()

    challenge = ver.send_challenge(commitment)
    responses = prov.compute_response(challenge)
    with pytest.raises(Exception):
        ver.verify(responses)


def test_wrong_signature_and_DLRNE():
    """
    We manually modify a secret in the DLRNE member, i.e we wrongfully claim to use the same "s" i the 
    signature and in the DLRNE.
    Should not be detected since bindings in the DLRNE are False.
    """
    mG = BilinearGroupPair()
    keypair = KeyPair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]
    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.commitment_message)
    signature = creator.obtain_signature(presignature)
    secret_dict = {
        "e": signature.e,
        "s": signature.s,
        "m1": messages[0],
        "m2": messages[1],
        "m3": messages[2],
    }
    sigproof = SignatureProof(signature, ["e", "s", "m1", "m2", "m3"], pk)

    g1 = mG.G1.generator()
    pg1 = signature.s * g1 + g1
    pg2, g2 = mG.G1.order().random() * g1, mG.G1.order().random() * g1
    dneq = DLRepNotEqualProof((pg1, g1), (pg2, g2), ["s"], binding=False)
    sigproof1 = SignatureProof(signature, ["e", "s", "m1", "m2", "m3"], pk)
    dneq1 = DLRepNotEqualProof((pg1, g1), (pg2, g2), ["s"], binding=False)

    andp = sigproof & dneq
    andp1 = sigproof1 & dneq1
    prov = andp.get_prover(secret_dict)

    prov.subs[1].secret_values["s"] = signature.s + 1
    ver = andp1.get_verifier()
    ver.process_precommitment(prov.precommit())
    commitment = prov.commit()

    challenge = ver.send_challenge(commitment)
    responses = prov.compute_response(challenge)
    assert ver.verify(responses)


def test_and_NI_sig():
    mG = BilinearGroupPair()
    keypair = KeyPair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]

    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.commitment_message)
    signature = creator.obtain_signature(presignature)
    secret_dict = {
        "e": signature.e,
        "s": signature.s,
        "m1": messages[0],
        "m2": messages[1],
        "m3": messages[2],
    }
    sigproof = SignatureProof(signature, ["e", "s", "m1", "m2", "m3"], pk)

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature2 = sk.sign(lhs.commitment_message)
    signature2 = creator.obtain_signature(presignature2)
    secret_dict2 = {
        "e1": signature2.e,
        "s1": signature2.s,
        "m1": messages[0],
        "m2": messages[1],
        "m3": messages[2],
    }
    sigproof1 = SignatureProof(signature2, ["e1", "s1", "m1", "m2", "m3"], pk)

    secret_dict.update(secret_dict2)
    andp = sigproof & sigproof1
    nip = andp.prove(secret_dict, encoding=enc_GXpt)
    assert andp.verify(nip, encoding=enc_GXpt)
