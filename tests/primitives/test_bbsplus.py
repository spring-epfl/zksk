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

