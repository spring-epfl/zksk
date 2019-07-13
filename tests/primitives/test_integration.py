import pytest

from petlib.bn import Bn

from zkbuilder import Secret
from zkbuilder.pairings import BilinearGroupPair

from zkbuilder import DLRep
from zkbuilder.composition import OrProofStmt, AndProofStmt
from zkbuilder.exceptions import VerificationError
from zkbuilder.primitives.bbsplus import Keypair, SignatureCreator, SignatureStmt
from zkbuilder.primitives.dl_notequal import DLNotEqual
from zkbuilder.utils.debug import SigmaProtocol
from zkbuilder.utils import make_generators

# TODO: Add test for signature simulation and or signature, when or with DLNE is fixed


@pytest.fixture(params=[2, 10])
def proof_params(request):
    num = request.param
    secrets = [Secret() for _ in range(num)]
    generators = make_generators(num)
    return secrets, generators


def get_secrets(num):
    secrets = [Secret() for _ in range(num)]
    secret_values = list(range(num))
    secret_dict = {x: v for x, v in zip(secrets, secret_values)}
    return secrets, secret_values, secret_dict


def get_secrets_new(num):
    secrets = [Secret(i * 1337 + i) for i in range(num)]
    return secrets


# BBS+ & BBS+
def test_bbsplus_and_proof():
    mG = BilinearGroupPair()
    keypair = Keypair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]

    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.commitment_message)
    signature = creator.obtain_signature(presignature)
    e, s, m1, m2, m3 = (Secret() for _ in range(5))
    secret_dict = {
        e: signature.e,
        s: signature.s,
        m1: messages[0],
        m2: messages[1],
        m3: messages[2],
    }

    sigproof = SignatureStmt([e, s, m1, m2, m3], pk, signature)

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature2 = sk.sign(lhs.commitment_message)
    signature2 = creator.obtain_signature(presignature2)
    e1, s1, m1, m2, m3 = (Secret() for _ in range(5))
    secret_dict2 = {
        e1: signature2.e,
        s1: signature2.s,
        m1: messages[0],
        m2: messages[1],
        m3: messages[2],
    }
    sigproof1 = SignatureStmt([e1, s1, m1, m2, m3], pk, signature2)

    secret_dict.update(secret_dict2)
    andp = sigproof & sigproof1
    prov = andp.get_prover(secret_dict)
    ver = andp.get_verifier()
    protocol = SigmaProtocol(ver, prov)
    assert protocol.verify()


# BBS+ & BBS+
def test_and_sig_non_interactive():
    mG = BilinearGroupPair()
    keypair = Keypair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]

    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.commitment_message)
    signature = creator.obtain_signature(presignature)
    e, s, m1, m2, m3 = (Secret() for _ in range(5))
    secret_dict = {
        e: signature.e,
        s: signature.s,
        m1: messages[0],
        m2: messages[1],
        m3: messages[2],
    }

    sigproof = SignatureStmt([e, s, m1, m2, m3], pk, signature)

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature2 = sk.sign(lhs.commitment_message)
    signature2 = creator.obtain_signature(presignature2)

    e1, s1 = (Secret() for _ in range(2))
    secret_dict2 = {
        e1: signature2.e,
        s1: signature2.s,
        m1: messages[0],
        m2: messages[1],
        m3: messages[2],
    }
    sigproof1 = SignatureStmt([e1, s1, m1, m2, m3], pk, signature2)

    secret_dict.update(secret_dict2)
    andp = sigproof & sigproof1
    tr = andp.prove(secret_dict)
    assert andp.verify(tr)


# DLNE(BBS+, BBS+)
def test_signature_and_dlrne():
    """
    Construct a signature on a set of messages, and then pair the proof of knowledge of this signature with
    a proof of non-equality of two DL, one of which is the blinding exponent 's' of the signature.
    """
    mG = BilinearGroupPair()
    keypair = Keypair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]
    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.commitment_message)
    signature = creator.obtain_signature(presignature)
    e, s, m1, m2, m3 = (Secret() for _ in range(5))
    secret_dict = {
        e: signature.e,
        s: signature.s,
        m1: messages[0],
        m2: messages[1],
        m3: messages[2],
    }

    sigproof = SignatureStmt([e, s, m1, m2, m3], pk, signature)
    g1 = mG.G1.generator()
    pg1 = signature.s * g1
    pg2, g2 = mG.G1.order().random() * g1, mG.G1.order().random() * g1
    dneq = DLNotEqual((pg1, g1), (pg2, g2), s, bind=True)
    andp = sigproof & dneq

    secrets = [Secret() for _ in range(5)]
    sigproof1 = SignatureStmt(secrets, pk)
    dneq1 = DLNotEqual((pg1, g1), (pg2, g2), secrets[1], bind=True)
    andp1 = sigproof1 & dneq1
    prov = andp.get_prover(secret_dict)
    ver = andp1.get_verifier()
    ver.process_precommitment(prov.precommit())
    commitment = prov.commit()

    challenge = ver.send_challenge(commitment)
    responses = prov.compute_response(challenge)
    assert ver.verify(responses)


# DLNE(BBS+, BBS+)
def test_signature_and_dlrne_fails_on_wrong_secret():
    """
    We manually modify a secret in the DLNE member, i.e we wrongfully claim to use the same "s" i the
    signature and in the DLNE.
    Should be detected and raise an Exception.
    """
    mG = BilinearGroupPair()
    keypair = Keypair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]
    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.commitment_message)
    signature = creator.obtain_signature(presignature)
    e, s, m1, m2, m3 = (Secret() for _ in range(5))
    secret_dict = {
        e: signature.e,
        s: signature.s,
        m1: messages[0],
        m2: messages[1],
        m3: messages[2],
    }

    sigproof = SignatureStmt([e, s, m1, m2, m3], pk, signature)

    g1 = mG.G1.generator()
    pg1 = signature.s * g1
    pg2, g2 = mG.G1.order().random() * g1, mG.G1.order().random() * g1
    dneq = DLNotEqual((pg1, g1), (pg2, g2), s, bind=True)

    secrets = [Secret() for _ in range(5)]
    sigproof1 = SignatureStmt(secrets, pk, signature)
    dneq1 = DLNotEqual((pg1, g1), (pg2, g2), secrets[1], bind=True)

    andp = sigproof & dneq
    andp1 = sigproof1 & dneq1
    prov = andp.get_prover(secret_dict)

    prov.subs[1].secret_values[s] = signature.s + 1
    ver = andp1.get_verifier()

    ver.process_precommitment(prov.precommit())

    commitment = prov.commit()

    challenge = ver.send_challenge(commitment)
    responses = prov.compute_response(challenge)
    with pytest.raises(VerificationError):
        ver.verify(responses)


# DLNE(BBS+, BBS+)
def test_signature_and_dlrne_does_not_fail_on_wrong_secret_when_non_binding():
    """
    Manually modify a secret in the DLNE member, i.e we wrongfully claim to use the same "s" i the
    signature and in the DLNE.  Should not be detected since bindings in the DLNE are False.
    """

    mG = BilinearGroupPair()
    keypair = Keypair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]
    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.commitment_message)
    signature = creator.obtain_signature(presignature)
    e, s, m1, m2, m3 = (Secret() for _ in range(5))
    secret_dict = {
        e: signature.e,
        s: signature.s,
        m1: messages[0],
        m2: messages[1],
        m3: messages[2],
    }
    sigproof = SignatureStmt([e, s, m1, m2, m3], pk, signature)

    g1 = mG.G1.generator()
    pg1 = signature.s * g1 + g1
    pg2, g2 = mG.G1.order().random() * g1, mG.G1.order().random() * g1
    splus = Secret(signature.s + 1)
    dneq = DLNotEqual((pg1, g1), (pg2, g2), splus, bind=False)

    secrets = [Secret() for _ in range(5)]
    sigproof1 = SignatureStmt(secrets, pk, signature)
    # Note difference: dneq above uses an independent secret for dneq,
    # here it is bound to the secret s (secrets[1]) from the signature proof
    dneq1 = DLNotEqual((pg1, g1), (pg2, g2), secrets[1])

    andp = sigproof & dneq
    andp1 = sigproof1 & dneq1
    prov = andp.get_prover(secret_dict)

    ver = andp1.get_verifier()
    ver.process_precommitment(prov.precommit())
    commitment = prov.commit()

    challenge = ver.send_challenge(commitment)
    responses = prov.compute_response(challenge)
    assert ver.verify(responses)


# BBS+ | BBS+
def test_or_signature_non_interactive():
    mG = BilinearGroupPair()
    keypair = Keypair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]

    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.commitment_message)
    signature = creator.obtain_signature(presignature)
    e, s, m1, m2, m3 = (Secret() for _ in range(5))
    secret_dict = {
        e: signature.e,
        s: signature.s,
        m1: messages[0],
        m2: messages[1],
        m3: messages[2],
    }

    sigproof = SignatureStmt([e, s, m1, m2, m3], pk, signature)

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature2 = sk.sign(lhs.commitment_message)
    signature2 = creator.obtain_signature(presignature2)

    e1, s1 = (Secret() for _ in range(2))
    secret_dict2 = {
        e1: signature2.e,
        s1: signature2.s,
        m1: messages[0],
        m2: messages[1],
        m3: messages[2],
    }
    sigproof1 = SignatureStmt([e1, s1, m1, m2, m3], pk, signature2)

    secret_dict.update(secret_dict2)
    andp = sigproof | sigproof1
    tr = andp.prove(secret_dict)
    assert andp.verify(tr)


# BBS+ | BBS+
def test_or_signature_non_interactive():
    mG = BilinearGroupPair()
    keypair = Keypair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]

    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.commitment_message)
    signature = creator.obtain_signature(presignature)
    e, s, m1, m2, m3 = (Secret() for _ in range(5))
    secret_dict = {
        e: signature.e,
        s: signature.s,
        m1: messages[0],
        m2: messages[1],
        m3: messages[2],
    }
    sigproof = SignatureStmt([e, s, m1, m2, m3], pk, signature)
    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature2 = sk.sign(lhs.commitment_message)
    signature2 = creator.obtain_signature(presignature2)

    e1, s1 = (Secret() for _ in range(2))
    secret_dict2 = {
        e1: signature2.e,
        s1: signature2.s,
        m1: messages[0],
        m2: messages[1],
    }
    sigproof1 = SignatureStmt([e1, s1, m1, m2, m3], pk, signature2)

    secret_dict.update(secret_dict2)
    andp = sigproof | sigproof1
    orp = OrProofStmt(andp, sigproof)
    tr = orp.prove(secret_dict)
    assert orp.verify(tr)


# BBS+ | DLNE
def test_signature_or_dlrne():
    """
    Construct a signature on a set of messages, and then pairs the proof of knowledge of this signature with
    a proof of non-equality of two DL, one of which is the blinding exponent 's' of the signature.
    """
    mG = BilinearGroupPair()
    keypair = Keypair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]
    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.commitment_message)
    signature = creator.obtain_signature(presignature)
    e, s, m1, m2, m3 = (Secret() for _ in range(5))
    secret_dict = {e: signature.e, s: signature.s, m1: messages[0], m2: messages[1], m3: messages[2]}

    sigproof = SignatureStmt([e, s, m1, m2, m3], pk, signature)
    g1 = mG.G1.generator()
    pg1 = signature.s * g1
    pg2, g2 = mG.G1.order().random() * g1, mG.G1.order().random() * g1
    dneq = DLNotEqual((pg1, g1), (pg2, g2), s, bind=True)
    andp = sigproof | dneq

    secrets = [Secret() for _ in range(5)]
    sigproof1 = SignatureStmt(secrets, pk)
    dneq1 = DLNotEqual((pg1, g1), (pg2, g2), secrets[1], bind=True)
    andp1 = sigproof1 | dneq1
    prov = andp.get_prover(secret_dict)
    ver = andp1.get_verifier()
    ver.process_precommitment(prov.precommit())
    commitment = prov.commit()

    challenge = ver.send_challenge(commitment)
    responses = prov.compute_response(challenge)
    assert ver.verify(responses)


# DLNE & DLNE
def test_and_dlrne():
    secrets, secret_values, secret_dict = get_secrets(3)
    generators = make_generators(3)

    lhs_values = [x * g for x, g in zip(secret_values, generators)]
    p1 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p2 = DLNotEqual(
        [lhs_values[1], generators[1]], [lhs_values[2], generators[2]], secrets[1]
    )
    andp = p1 & p2

    p1_prime = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p2_prime = DLNotEqual(
        [lhs_values[1], generators[1]], [lhs_values[2], generators[2]], secrets[1]
    )

    andp_prime = p1_prime & p2_prime
    protocol = SigmaProtocol(andp_prime.get_verifier(), andp.get_prover(secret_dict))
    assert protocol.verify()


# DLNE & DLNE
def test_and_dlrne_fails_on_same_dl():
    """
    Second subproof is not correct as the two members have the same DL
    """
    secrets, secret_values, secret_dict = get_secrets(4)
    generators = make_generators(4)

    lhs_values = [x * g for x, g in zip(secret_values, generators)]
    y3 = secret_values[1] * generators[3]
    p1 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True
    )
    p2 = DLNotEqual(
        [lhs_values[1], generators[1]],
        [y3, generators[3]],
        secrets[1],
    )

    andp = p1 & p2
    p1_prime = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True
    )

    p2_prime = DLNotEqual(
        [lhs_values[1], generators[1]],
        [y3, generators[3]],
        secrets[1]
    )

    andp_prime = p1_prime & p2_prime
    protocol = SigmaProtocol(andp_prime.get_verifier(), andp.get_prover(secret_dict))
    assert not protocol.verify()


# DLREP & DLNE
def test_and_dlrne_binding_1():
    secrets, secret_values, secret_dict = get_secrets(4)
    generators = make_generators(4)
    lhs_values = [x * g for x, g in zip(secret_values, generators)]

    p1 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p2 = DLRep(lhs_values[0], secrets[0] * generators[0])
    andp = p1 & p2

    p1_prime = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p2_prime = DLRep(lhs_values[0], Secret(name=secrets[0].name) * generators[0])
    andp_prime = p1_prime & p2_prime

    protocol = SigmaProtocol(andp_prime.get_verifier(), andp.get_prover(secret_dict))
    assert protocol.verify()


# DLREP & DLNE
def test_and_dlrne_does_not_fail_on_same_dl_when_not_binding():
    """
    Prove (H0 = h0*x, H1 != h1*x), H2 = h2*x with same secret name x. Should not be detected as
    binding is off by default.
    """
    secrets, secret_values, secret_dict = get_secrets(4)
    generators = make_generators(4)
    lhs_values = [x * g for x, g in zip(secret_values, generators)]

    y3 = secret_values[2] * generators[3]
    s0 = secrets[0]

    p1 = DLNotEqual([lhs_values[0], generators[0]], [lhs_values[1], generators[1]], s0)
    p2 = DLRep(lhs_values[2], s0 * generators[2])
    andp = p1 & p2

    s0_prime = Secret(name=secrets[0].name)
    p1_prime = DLNotEqual([lhs_values[0], generators[0]], [lhs_values[1], generators[1]],
            s0_prime)
    p2_prime = DLRep(lhs_values[2], s0_prime * generators[2])
    andp_prime = p1_prime & p2_prime

    prov = andp.get_prover(secret_dict)
    prov.subs[1].secret_values[s0] = secret_values[2]

    protocol = SigmaProtocol(andp_prime.get_verifier(), prov)
    assert protocol.verify()


# DLREP & DLNE
def test_dlrep_and_dlrne_fails_on_same_dl_when_binding():
    """
    Prove (H0 = h0*x, H1 != h1*x), H2 = h2*x with same secret name x. Should be detected as
    binding is on.
    """
    secrets, secret_values, secret_dict = get_secrets(4)
    generators = make_generators(4)
    lhs_values = [x * g for x, g in zip(secret_values, generators)]

    y3 = secret_values[2] * generators[3]
    p1 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p2 = DLRep(lhs_values[2], secrets[0] * generators[2])
    andp = p1 & p2

    # Twin proof
    s0_prime = Secret(name=secrets[0].name)
    p1_prime = DLNotEqual(
        [lhs_values[0], generators[0]], [lhs_values[1], generators[1]], s0_prime, bind=True
    )
    p2_prime = DLRep(lhs_values[2], s0_prime * generators[2])
    andp_prime = p1_prime & p2_prime

    prov = andp.get_prover(secret_dict)
    prov.subs[1].secret_values[secrets[0]] = secret_values[2]

    ver = andp_prime.get_verifier()
    ver.process_precommitment(prov.precommit())
    com = prov.commit()
    chal = ver.send_challenge(com)
    resp = prov.compute_response(chal)

    with pytest.raises(VerificationError):
        ver.verify(resp)


# DLNE & DLNE
def test_and_dlrne_fails_on_contradiction_when_binding():
    """
    Claim to use (H0 = h0*x, H1 != h1*x), (H1 = h1*x, H3 != h3*x) with the same x (not only
    cheating, a contradiction). Should be detected as binding is on.
    """
    secrets, secret_values, secret_dict = get_secrets(4)
    generators = make_generators(4)
    lhs_values = [x * g for x, g in zip(secret_values, generators)]

    y3 = secret_values[2] * generators[3]
    p1 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p2 = DLNotEqual(
        [lhs_values[1], generators[1]], [y3, generators[3]], secrets[0], bind=True
    )
    andp = p1 & p2

    p1_prime = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p2_prime = DLNotEqual(
        [lhs_values[1], generators[1]], [y3, generators[3]], secrets[0], bind=True
    )
    andp_prime = p1_prime & p2_prime

    prov = andp.get_prover(secret_dict)
    prov.subs[1].secret_values[secrets[0]] = secret_values[1]

    protocol = SigmaProtocol(andp_prime.get_verifier(), prov)
    with pytest.raises(VerificationError):
        protocol.verify()



# DLNE & DLNE
def test_and_dlrep_partial_binding():
    """
    Claim to use (H0 = h0*x, H1 != h1*x) , (H1 = h1*x, H3 != h3*x) with the same x (not only
    cheating, a contradiction).  Should be undetected as binding is off in at least one proof
    """
    secrets = get_secrets_new(4)
    generators = make_generators(4)
    lhs_values = [x.value * g for x, g in zip(secrets, generators)]

    y3 = secrets[2].value * generators[3]
    p1 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=False,
    )
    p2 = DLNotEqual(
        [lhs_values[1], generators[1]], [y3, generators[3]], secrets[1], bind=True
    )
    andp = p1 & p2

    sprime = Secret()
    p1_prime = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        sprime,
        bind=False,
    )
    p2_prime = DLNotEqual(
        [lhs_values[1], generators[1]], [y3, generators[3]], sprime, bind=True
    )
    andp_prime = p1_prime & p2_prime

    protocol = SigmaProtocol(andp_prime.get_verifier(), andp.get_prover())
    assert protocol.verify()


# DLNE & DLREP & DLNE & DLNE
def test_multiple_and_dlrep_binding():
    secrets = get_secrets_new(4)
    generators = make_generators(4)
    lhs_values = [x.value * g for x, g in zip(secrets, generators)]

    p1 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=False,
    )
    p2 = DLRep(lhs_values[2], secrets[2] * generators[2])

    p3 = DLNotEqual(
        [lhs_values[2], generators[2]],
        [lhs_values[1], generators[1]],
        secrets[2],
        bind=True,
    )
    p4 = DLNotEqual(
        [lhs_values[1], generators[1]],
        [lhs_values[3], generators[3]],
        secrets[1],
        bind=True,
    )

    andp = p1 & p2 & p3 & p4

    s0 = Secret()
    s2 = Secret()
    p1prime = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        s0,
        bind=False,
    )
    p2prime = DLRep(lhs_values[2], s2 * generators[2])

    p3prime = DLNotEqual(
        [lhs_values[2], generators[2]], [lhs_values[1], generators[1]], s2, bind=True
    )
    # Note difference: p4prime binds s0 instead of secrets[1] in the original proof
    p4prime = DLNotEqual(
        [lhs_values[1], generators[1]], [lhs_values[3], generators[3]], s0, bind=True
    )

    andp1 = p1prime & p2prime & p3prime & p4prime
    protocol = SigmaProtocol(andp1.get_verifier(), andp.get_prover())
    assert protocol.verify()


# DLNE & DLREP & DLNE & DLNE
def test_multiple_and_dlrep_fails_on_bad_secret_when_binding():
    secrets, secret_values, secret_dict = get_secrets(4)
    generators = make_generators(4)
    lhs_values = [x * g for x, g in zip(secret_values, generators)]

    p1 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p2 = DLRep(lhs_values[0], secrets[0] * generators[0])

    p3 = DLNotEqual(
        [lhs_values[2], generators[2]],
        [lhs_values[1], generators[1]],
        secrets[2],
        bind=True,
    )
    p4 = DLNotEqual(
        [lhs_values[1], generators[1]],
        [lhs_values[3], generators[3]],
        secrets[0],
        bind=True,
    )

    andp = p1 & p2 & p3 & p4

    p11 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p21 = DLRep(lhs_values[0], secrets[0] * generators[0])

    p31 = DLNotEqual(
        [lhs_values[2], generators[2]],
        [lhs_values[1], generators[1]],
        secrets[2],
        bind=True,
    )
    p41 = DLNotEqual(
        [lhs_values[1], generators[1]],
        [lhs_values[3], generators[3]],
        secrets[0],
        bind=True,
    )

    andp1 = p11 & p21 & p31 & p41

    prov = andp.get_prover(secret_dict)
    prov.subs[1].secret_values[secrets[0]] = secret_values[1]

    protocol = SigmaProtocol(andp1.get_verifier(), prov)
    with pytest.raises(VerificationError):
        protocol.verify()


# DLNE & DLNE & DLREP
def test_and_dlrne_non_interactive_1(group):
    g = group.generator()
    x = Secret(value=3)
    y = 3 * g
    y2 = 397474 * g
    g2 = 1397 * g

    pr = DLNotEqual([y, g], [y2, g2], x, bind=True)
    p2 = DLNotEqual([2 * y, 2 * g], [y2, g2], x, bind=True)
    andp = pr & p2 & DLRep(y, x * g)
    tr = andp.prove()
    assert andp.verify(tr)


# DLNE & DLNE & DLREP
def test_and_dlrne_non_interactive_2():
    secrets, secret_values, secret_dict = get_secrets(4)
    generators = make_generators(4)
    lhs_values = [x * g for x, g in zip(secret_values, generators)]

    p1 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p2 = DLRep(lhs_values[0], secrets[0] * generators[0])

    p3 = DLNotEqual(
        [lhs_values[2], generators[2]],
        [lhs_values[1], generators[1]],
        secrets[2],
        bind=True,
    )

    andp = p1 & p2 & p3

    s0 = Secret()
    s2 = Secret()
    p11 = DLNotEqual(
        [lhs_values[0], generators[0]], [lhs_values[1], generators[1]], s0, bind=True
    )
    p21 = DLRep(lhs_values[0], s0 * generators[0])

    p31 = DLNotEqual(
        [lhs_values[2], generators[2]], [lhs_values[1], generators[1]], s2, bind=True
    )

    andp1 = p11 & p21 & p31

    tr = andp.prove(secret_dict)
    assert andp1.verify(tr)


# DLNE & DLREP & DLNE & DLNE
def test_multiple_dlrne_simulation():
    secrets, secret_values, secret_dict = get_secrets(4)
    generators = make_generators(4)
    lhs_values = [x * g for x, g in zip(secret_values, generators)]

    p1 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=False,
    )
    p2 = DLRep(lhs_values[2], secrets[2] * generators[2])

    p3 = DLNotEqual(
        [lhs_values[2], generators[2]],
        [lhs_values[1], generators[1]],
        secrets[2],
        bind=True,
    )
    p4 = DLNotEqual(
        [lhs_values[1], generators[1]],
        [lhs_values[3], generators[3]],
        secrets[0],
        bind=True,
    )

    andp = p1 & p2 & p3 & p4
    tr = andp.simulate()
    assert andp.verify_simulation_consistency(tr)
    assert not andp.verify(tr)


# DLNE & DLNE
def test_dlrne_simulation_binding():
    secrets, secret_values, secret_dict = get_secrets(4)
    generators = make_generators(4)
    lhs_values = [x * g for x, g in zip(secret_values, generators)]

    y3 = secret_values[2] * generators[3]
    p1 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p2 = DLNotEqual(
        [lhs_values[1], generators[1]], [y3, generators[3]], [secrets[0]]
    )
    andp = p1 & p2
    tr = andp.simulate()
    assert andp.verify_simulation_consistency(tr)
    assert not andp.verify(tr)


# DLNE | DLNE
def test_or_dlrne():
    secrets, secret_values, secret_dict = get_secrets(4)
    generators = make_generators(4)
    lhs_values = [x * g for x, g in zip(secret_values, generators)]

    y3 = secret_values[2] * generators[3]
    p1 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p2 = DLNotEqual(
        [lhs_values[1], generators[1]], [y3, generators[3]], secrets[1]
    )
    orp = OrProofStmt(p1, p2)
    prov = orp.get_prover(secret_dict)
    ver = orp.get_verifier()
    precom = prov.precommit()
    ver.process_precommitment(precom)
    com = prov.commit()
    chal = ver.send_challenge(com)
    resp = prov.compute_response(chal)
    assert ver.verify(resp)


# DLNE | DLNE
def test_or_dlrne_non_interactive():
    secrets, secret_values, secret_dict = get_secrets(4)
    generators = make_generators(4)
    lhs_values = [x * g for x, g in zip(secret_values, generators)]

    y3 = secret_values[2] * generators[3]
    p1 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p2 = DLNotEqual(
        [lhs_values[1], generators[1]], [y3, generators[3]], secrets[1], bind=True
    )
    orp = p1 | p2
    tr = orp.prove(secret_dict)
    assert orp.verify(tr)


# (DLNE | DLNE) | DLNE | DLNE
def test_or_or_dlrne():
    secrets, secret_values, secret_dict = get_secrets(4)
    generators = make_generators(4)
    lhs_values = [x * g for x, g in zip(secret_values, generators)]

    y3 = secret_values[2] * generators[3]
    p1 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p11 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p2 = DLNotEqual(
        [lhs_values[1], generators[1]], [y3, generators[3]], secrets[1]
    )
    p3 = DLNotEqual(
        [lhs_values[1], generators[1]], [y3, generators[3]], secrets[1]
    )
    orp_nested = OrProofStmt(p1, p2)
    orp = OrProofStmt(orp_nested, p11, p3)
    prov = orp.get_prover(secret_dict)
    ver = orp.get_verifier()
    precom = prov.precommit()
    ver.process_precommitment(precom)
    com = prov.commit()
    chal = ver.send_challenge(com)
    resp = prov.compute_response(chal)
    assert ver.verify(resp)


# (DLNE & DLNE) | DLNE | DLNE
def test_or_and_dlrne():
    secrets, secret_values, secret_dict = get_secrets(4)
    generators = make_generators(4)
    lhs_values = [x * g for x, g in zip(secret_values, generators)]

    y3 = secret_values[2] * generators[3]
    p1 = DLNotEqual(
        [lhs_values[0], generators[0]],
        [lhs_values[1], generators[1]],
        secrets[0],
        bind=True,
    )
    p2 = DLNotEqual(
        [lhs_values[1], generators[1]], [y3, generators[3]], secrets[1], bind=True
    )
    andp_nested = AndProofStmt(p1, p2)
    orp = OrProofStmt(andp_nested, p1, p2)
    prov = orp.get_prover(secret_dict)
    ver = orp.get_verifier()
    precom = prov.precommit()
    ver.process_precommitment(precom)
    com = prov.commit()
    chal = ver.send_challenge(com)
    resp = prov.compute_response(chal)
    assert ver.verify(resp)

