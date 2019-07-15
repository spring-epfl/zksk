import random

import pytest

from petlib.bn import Bn
from petlib.ec import EcGroup

from zksk import DLRep, Secret
from zksk.exceptions import InvalidExpression, InvalidSecretsError, ValidationError, GroupMismatchError
from zksk.composition import AndProofStmt, OrProofStmt
from zksk.expr import wsum_secrets
from zksk.utils import make_generators


@pytest.fixture
def params(group):
    n1 = 3
    n2 = 4
    generators1 = make_generators(n1)
    generators2 = make_generators(n2)
    x0 = Secret()
    x1 = Secret()
    x2 = Secret()
    x3 = Secret()
    x4 = Secret()
    x5 = Secret()
    secrets = [x0, x1, x2, x3, x4, x5]
    secrets_dict = dict(
        [
            (x0, Bn(1)),
            (x1, Bn(2)),
            (x2, Bn(5)),
            (x3, Bn(100)),
            (x4, Bn(43)),
            (x5, Bn(10)),
        ]
    )

    sum_1 = group.wsum(
        [secrets_dict[x0], secrets_dict[x1], secrets_dict[x2]], generators1
    )
    secrets_2 = [secrets_dict[x0]]
    for i in range(3, 6):
        secrets_2.append(secrets_dict[secrets[i]])

    sum_2 = group.wsum(secrets_2, generators2)
    p1 = DLRep(sum_1, wsum_secrets([x0, x1, x2], generators1))

    p2 = DLRep(sum_2, wsum_secrets([x0, x3, x4, x5], generators2))
    return p1, p2, secrets_dict


def verify(verifier, prover):
    commitment = prover.commit()
    challenge = verifier.send_challenge(commitment)
    response = prover.compute_response(challenge)
    return verifier.verify(response)


def verify_proof(proof, secrets):
    prov = proof.get_prover(secrets)
    verif = proof.get_verifier()
    com = prov.commit()
    chal = verif.send_challenge(com)
    resp = prov.compute_response(chal)
    return verif.verify(resp)


def test_and_proof_same_environment(params):
    p1, p2, secrets_dict = params
    and_proof = AndProofStmt(p1, p2)

    prover = and_proof.get_prover(secrets_dict)
    verifier = and_proof.get_verifier()
    assert verify(verifier, prover)


def test_and_proof_different_environments(params):
    x, y = Secret(), Secret()
    p1, p2, secrets_dict = params
    and_proof = AndProofStmt(p1, p2)
    prover = and_proof.get_prover(secrets_dict)
    verifier = and_proof.get_verifier()
    assert verify(verifier, prover)


def test_and_proof_partially_defined_secrets():
    generators = make_generators(2)
    x = Secret(value=4)
    x2 = Secret()
    p1 = DLRep(4 * generators[0], x * generators[0])
    p2 = DLRep(3 * generators[1], x2 * generators[1])
    andp = p1 & p2
    tr = andp.prove({x2: 3})
    assert andp.verify(tr)


def test_and_proof_fails_when_bases_belong_to_different_groups(group):
    """
    An alien EcPt is inserted in the generators
    """
    g1 = group.generator()
    other_group = EcGroup(706)
    assert group != other_group
    g2 = other_group.generator()

    x = Secret(value=Bn(42))
    y1 = group.wsum([x.value], [g1])
    y2 = other_group.wsum([x.value], [g2])

    p1 = DLRep(y1, wsum_secrets([x], [g1]))
    p2 = DLRep(y2, wsum_secrets([x], [g2]))

    and_proof = AndProofStmt(p1, p2)
    prover = and_proof.get_prover()
    verifier = and_proof.get_verifier()

    # An exception should be raised because of a shared secrets linked to two different groups
    with pytest.raises(GroupMismatchError):
        verify(verifier, prover)


def test_and_proof_fails_when_secret_is_wrong(params, group):
    p1, p2, secrets_dict = params
    and_proof = AndProofStmt(p1, p2)
    sec = secrets_dict.copy()
    u = list(sec.keys())
    sec[u[0]] = group.order().random()
    prover = and_proof.get_prover(sec)
    verifier = and_proof.get_verifier()
    assert not verify(verifier, prover)


def test_multiple_and_proofs(params):
    p1, p2, secrets_dict = params
    and_proof = AndProofStmt(p1, p2, p2, p1, p1, p1, p2)
    prover = and_proof.get_prover(secrets_dict)
    verifier = and_proof.get_verifier()
    assert verify(verifier, prover)


def test_compose_and_proofs_1(params):
    p1, p2, secrets_dict = params
    p3 = AndProofStmt(p1, p2)
    p4 = AndProofStmt(AndProofStmt(p1, p2), p1)
    prover = p4.get_prover(secrets_dict)
    verifier = p4.get_verifier()
    assert verify(verifier, prover)


def test_compose_and_proofs_2(params):
    p1, p2, secrets_dict = params
    p3 = AndProofStmt(p1, p2)
    p = AndProofStmt(AndProofStmt(p1, AndProofStmt(p3, AndProofStmt(p1, p2))), p2)
    prover = p.get_prover(secrets_dict)
    verifier = p.get_verifier()
    assert verify(verifier, prover)


def test_and_proof_simulation_1(group):
    n = 3
    secret_values = [Bn(i) for i in range(n)]
    secrets = [Secret() for _ in range(n)]
    generators = make_generators(n, group)
    lhs = group.wsum(secret_values, generators)

    subproof1 = DLRep(lhs, wsum_secrets(secrets, generators))
    subproof2 = DLRep(lhs, wsum_secrets(secrets, generators))
    andp = AndProofStmt(subproof1, subproof2)
    andv = andp.get_verifier()
    tr = andp.simulate_proof()
    tr.stmt_hash = andp.prehash_statement().digest()
    assert not andv.verify_nizk(tr)


def test_and_proof_simulation_2(group):
    n = 3
    secret_values = [Bn(i) for i in range(n)]
    secrets = [Secret() for _ in range(n)]
    generators = make_generators(n, group)
    lhs = group.wsum(secret_values, generators)

    subproof1 = DLRep(lhs, wsum_secrets(secrets, generators))
    subproof2 = DLRep(lhs, wsum_secrets(secrets, generators))
    andp = AndProofStmt(subproof1, subproof2)
    tr = andp.simulate()
    assert andp.verify_simulation_consistency(tr)
    assert not andp.verify(tr)


def test_and_proof_non_interactive(params):
    p1, p2, secrets = params
    p = AndProofStmt(p1, p2)
    message = "whatever"
    tr = p.prove(secrets, message=message)
    assert p.verify(tr, message=message)


def test_and_proof_non_interactive_fails_when_wrong_secrets(params, group):
    p1, p2, secrets = params
    andp = AndProofStmt(p1, p2)

    bad_secrets = secrets.copy()
    u = list(bad_secrets.keys())
    bad_secrets[u[0]] = group.order().random()

    message = "whatever"
    tr = andp.prove(bad_secrets, message=message)
    assert not andp.verify(tr, message=message)


def test_and_proof_infix_operator(params):
    p1, p2, secrets_dict = params
    and_proof = p1 & p2 & p1
    prover = and_proof.get_prover(secrets_dict)
    verifier = and_proof.get_verifier()
    assert verify(verifier, prover)


def test_and_proof_with_complex_expression(group):
    g = group.generator()
    g1 = 2 * g
    g2 = 5 * g
    g3 = 10 * g
    x1 = Secret()
    x2 = Secret()
    x3 = Secret()
    proof = DLRep(10 * g1 + 15 * g2, x1 * g1 + x2 * g2) & DLRep(
        15 * g1 + 35 * g3, x2 * g1 + x3 * g3
    )
    prover = proof.get_prover({x1: 10, x2: 15, x3: 35})
    verifier = proof.get_verifier()
    assert verify(verifier, prover)


def test_or_proof(params):
    p1, p2, secrets = params
    orproof = OrProofStmt(p1, p2, p1, p2, p1, p2)
    prov = orproof.get_prover(secrets)
    verif = orproof.get_verifier()
    com = prov.commit()
    chal = verif.send_challenge(com)
    resp = prov.compute_response(chal)

    # Here we see that some responses have an identical first element.
    # The only one with a different first element is the non-simulated one.
    assert verif.verify(resp)


def test_or_proof_manual(params):
    """
    TODO: Clarify what is being tested here.
    """
    p1, p2, secrets = params
    orproof = OrProofStmt(p1, p2, p1, p2, p1, p2)

    subproofs = orproof.subproofs
    rep = 0
    chosen = []
    sims = [True]
    while rep < 10:
        sims = []

        # Make random subproofs simulated.
        for proof in subproofs:
            is_simulated = random.choice([True, False])
            sims.append(is_simulated)
            proof.set_simulated(is_simulated)

        if all(sims):
            continue

        for i in range(30):
            # Choose a subproof, look if it was a valid choice, store the result
            prov = orproof.get_prover(secrets)
            chosen.append(sims[orproof.chosen_idx] == False)

        rep += 1

    assert all(chosen)


def test_and_or_proof_composition(params):
    p1, p2, secrets = params
    g1 = 7 * p1.bases[0]
    g2 = 8 * p1.bases[0]
    xb = Secret(name="xb")
    xa = Secret(name="xa")

    p0 = DLRep(7 * g1 + 18 * g2, xb * g1 + xa * g2)
    secrets[xb] = 7
    secrets[xa] = 18

    orproof = OrProofStmt(p1, p2)
    andp = AndProofStmt(orproof, p0)
    andp = AndProofStmt(andp, DLRep(15 * p1.bases[0], Secret(value=15) * p1.bases[0]))

    prover = andp.get_prover(secrets)
    verifier = andp.get_verifier()
    assert verify(verifier, prover)


def test_or_and_proof_composition(params):
    p1, p2, secrets = params
    andp = AndProofStmt(p1, p2)

    g1 = 7 * p1.bases[0]
    g2 = 8 * p1.bases[0]
    xb = Secret(name="xb")
    xa = Secret(name="xa")
    p0 = DLRep(7 * g1 + 18 * g2, xb * g1 + xa * g2)
    secrets[xa] = 7
    secrets[Secret(name="xc")] = 18

    orproof = OrProofStmt(p0, andp)
    prover = orproof.get_prover(secrets)
    verifier = orproof.get_verifier()
    assert verify(verifier, prover)


def test_or_or_proof_composition(params):
    p1, p2, secrets = params

    first_or = OrProofStmt(p1, p2)
    g1 = 7 * p1.bases[0]
    g2 = 8 * p1.bases[0]
    xb = Secret(name="xb")
    xa = Secret(name="xa")

    p0 = DLRep(7 * g1 + 18 * g2, xb * g1 + xa * g2)
    secrets[xa] = 7
    secrets[Secret()] = 18

    orproof = OrProofStmt(p0, first_or)
    prover = orproof.get_prover(secrets)
    verifier = orproof.get_verifier()
    assert verify(verifier, prover)


def test_or_proof_simulation(params):
    p1, p2, secrets = params
    first_or = OrProofStmt(p1, p2)
    tr = first_or.simulate()
    assert first_or.verify_simulation_consistency(tr)
    assert not first_or.verify(tr)


def test_multiple_or_proofs(group, params):
    p1, p2, secrets = params
    g = group.generator()
    x10 = Secret()
    secrets.update({x10: 13})
    orproof = OrProofStmt(p1, OrProofStmt(p2, DLRep(13 * g, x10 * g)))
    assert verify_proof(orproof, secrets)


def test_multiple_or_proofs_composition(group, params):
    p1, p2, secrets = params
    g = group.generator()
    x10 = Secret()
    secrets.update({x10: 13})
    orp1 = OrProofStmt(p2, p1)
    orp2 = OrProofStmt(p1, DLRep(13 * g, x10 * g))
    orproof = OrProofStmt(orp1, p2, orp2)
    assert verify_proof(orproof, secrets)


def test_or_proof_infix_operator(params):
    p1, p2, secrets = params
    orproof = p1 | p2
    assert verify_proof(orproof, secrets)

def test_multiple_or_proof_infix_operator(group, params):
    p1, p2, secrets = params
    g = group.generator()
    x10 = Secret()
    secrets.update({x10: 13})
    orproof = p1 | p2 | DLRep(13 * g, x10 * g)
    assert verify_proof(orproof, secrets)


def test_or_non_interactive(params):
    p1, p2, secrets = params
    p = OrProofStmt(p1, p2)
    message = "whatever"
    tr = p.prove(secrets, message=message)
    assert p.verify(tr, message=message)


def test_or_non_interactive_fails_on_wrong_secrets(group, params):
    p1, p2, secrets = params
    p = OrProofStmt(p1, p2)
    bad_secrets = secrets.copy()
    u = list(bad_secrets.keys())
    bad_secrets[u[0]] = group.order().random()
    bad_secrets[u[1]] = group.order().random()
    bad_secrets[u[2]] = group.order().random()
    bad_secrets[u[3]] = group.order().random()

    message = "whatever"
    tr = p.prove(bad_secrets, message=message)
    assert not p.verify(tr, message=message)


def test_malicious_and_proofs():
    x0 = Secret()
    x2 = Secret()
    x1 = Secret()
    generators = make_generators(3)
    g1 = generators[0]
    g2 = generators[1]
    g3 = generators[2]
    secret_dict = {x0: 3, x2: 50, x1: 12}
    mal_secret_dict = {x0: 3, x2: 51}
    andp = AndProofStmt(
        DLRep(12 * g1 + 50 * g2, x1 * g1 + x2 * g2),
        DLRep(3 * g3 + 51 * g2, x0 * g1 + x2 * g2),
    )

    prov = andp.get_prover(secret_dict)
    prov.subs[1].secret_values = mal_secret_dict
    verif = andp.get_verifier()

    com = prov.commit()
    chal = verif.send_challenge(com)
    resp = prov.compute_response(chal)
    with pytest.raises(ValidationError):
        verif.verify(resp)

# Secret used both inside and outside of or clause
def test_invalid_or_composition():
    r = Secret(10)
    g1, g2, g3 = make_generators(3)
    st1 = DLRep(10 * g1, r * g1)

    st21 = DLRep(10 * g2, r * g2)
    st22 = DLRep(12 * g3, r * g3)
    st22.set_simulated()
    st2 = st21 | st22
    st = st1 & st2

    with pytest.raises(InvalidSecretsError):
        st.prove()


# Secret used both inside two different or clauses
def test_invalid_or_composition_inside_two_or():
    r = Secret(10)
    g1, g2, g3, g4 = make_generators(4)
    st11 = DLRep(r.value * g1, r * g1)
    st12 = DLRep(2 * g2, r * g2)
    st12.set_simulated()
    st1 = st11 | st12

    st21 = DLRep(7 * g3, r * g3)
    st21.simluation = True
    st22 = DLRep(r.value * g4, r * g4)
    st2 = st21 | st22
    st = st1 & st2

    with pytest.raises(InvalidSecretsError):
        st.prove()
