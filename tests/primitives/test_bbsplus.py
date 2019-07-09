from petlib.bn import Bn

from zkbuilder import Secret
from zkbuilder.pairings import BilinearGroupPair
from zkbuilder.primitives.bbsplus import Keypair, SignatureCreator, SignatureProof


def test_signature_setup():
    mG = BilinearGroupPair()
    keypair = Keypair(mG, 9)
    messages = [Bn(30), Bn(31), Bn(32), Bn(12)]

    pk, sk = keypair.pk, keypair.sk
    generators, h0 = keypair.generators, keypair.h0

    creator = SignatureCreator(pk)
    usr_commitment = creator.commit(messages, zkp=True)
    presignature = sk.sign(usr_commitment.commitment_message)
    signature = creator.obtain_signature(presignature)

    assert usr_commitment.verify_blinding(pk) and signature.verify_signature(
        pk, messages
    )


def test_signature_proof():
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

    p = SignatureProof([e, s, m1, m2, m3], pk, signature)
    prover = p.get_prover(secret_dict)
    p1 = SignatureProof([Secret() for _ in range(5)], pk)
    verifier = p1.get_verifier()
    pc = prover.precommit()
    verifier.process_precommitment(pc)
    comm = prover.commit()
    chal = verifier.send_challenge(comm)
    resp = prover.compute_response(chal)
    assert verifier.verify(resp)


def test_signature_non_interactive_proof():
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

    p = SignatureProof([e, s, m1, m2, m3], pk, signature)
    tr = p.prove(secret_dict)
    p1 = SignatureProof([Secret() for _ in range(5)], pk)
    assert p1.verify(tr)

