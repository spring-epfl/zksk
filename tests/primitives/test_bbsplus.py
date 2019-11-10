from petlib.bn import Bn

from zksk import Secret
from zksk.pairings import BilinearGroupPair
from zksk.primitives.bbsplus import BBSPlusKeypair, BBSPlusSignatureCreator
from zksk.primitives.bbsplus import BBSPlusSignatureStmt


def test_signature_setup():
    mG = BilinearGroupPair()
    keypair = BBSPlusKeypair.generate(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32), Bn(12)]

    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = BBSPlusSignatureCreator(pk)
    com = creator.commit(messages, zkp=True)
    presignature = sk.sign(com.com_message)
    signature = creator.obtain_signature(presignature)

    assert com.verify_blinding(pk) and signature.verify_signature(
        pk, messages
    )


def test_signature_proof():
    mG = BilinearGroupPair()
    keypair = BBSPlusKeypair.generate(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]

    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = BBSPlusSignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.com_message)
    signature = creator.obtain_signature(presignature)
    e, s, m1, m2, m3 = (Secret() for _ in range(5))
    secret_dict = {
        e: signature.e,
        s: signature.s,
        m1: messages[0],
        m2: messages[1],
        m3: messages[2],
    }

    p1 = BBSPlusSignatureStmt([e, s, m1, m2, m3], pk, signature)
    prover = p1.get_prover(secret_dict)
    p2 = BBSPlusSignatureStmt([Secret() for _ in range(5)], pk)
    verifier = p2.get_verifier()
    pc = prover.precommit()
    verifier.process_precommitment(pc)
    com = prover.commit()
    chal = verifier.send_challenge(com)
    resp = prover.compute_response(chal)
    assert verifier.verify(resp)


def test_signature_non_interactive_proof():
    mG = BilinearGroupPair()
    keypair = BBSPlusKeypair.generate(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32)]

    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = BBSPlusSignatureCreator(pk)
    lhs = creator.commit(messages)
    presignature = sk.sign(lhs.com_message)
    signature = creator.obtain_signature(presignature)
    e, s, m1, m2, m3 = (Secret() for _ in range(5))
    secret_dict = {
        e: signature.e,
        s: signature.s,
        m1: messages[0],
        m2: messages[1],
        m3: messages[2],
    }

    p1 = BBSPlusSignatureStmt([e, s, m1, m2, m3], pk, signature)
    tr = p1.prove(secret_dict)
    p1 = BBSPlusSignatureStmt([Secret() for _ in range(5)], pk)
    assert p1.verify(tr)


def test_bbsplus_and_range():
    from zksk.primitives.rangeproof import RangeStmt
    from zksk.utils import make_generators

    mG = BilinearGroupPair()
    keypair = BBSPlusKeypair.generate(mG, 9)

    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = BBSPlusSignatureCreator(pk)
    msg_val = Bn(30)
    lhs = creator.commit([msg_val])
    presignature = sk.sign(lhs.com_message)
    signature = creator.obtain_signature(presignature)
    e, s, m = Secret(signature.e), Secret(signature.s), Secret(msg_val)

    p1 = BBSPlusSignatureStmt([e, s, m], pk, signature)

    g, h = make_generators(2, mG.G1)
    randomizer = Secret(value=mG.G1.order().random())
    com = m * g + randomizer * h
    p2 = RangeStmt(com.eval(), g, h, 18, 9999, m, randomizer)

    stmt = p1 & p2
    proof = stmt.prove()
    assert stmt.verify(proof)
