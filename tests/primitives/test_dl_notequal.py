import pytest

from petlib.bn import Bn

from zkbuilder import Secret
from zkbuilder.pairings import BilinearGroupPair

from zkbuilder.primitives.dl_notequal import DLNotEqual


def test_dlne_interactive(group):
    g = group.generator()
    x = Secret()
    y = 3 * g
    y2 = 397474 * g
    g2 = 1397 * g

    p1 = DLNotEqual([y, g], [y2, g2], x, bind=True)
    p2 = DLNotEqual([y, g], [y2, g2], x, bind=True)
    secret_dict = {x: 3}
    prover = p1.get_prover(secret_dict)
    verifier = p2.get_verifier()
    verifier.process_precommitment(prover.precommit())
    commitment = prover.commit()
    challenge = verifier.send_challenge(commitment)
    responses = prover.compute_response(challenge)

    assert verifier.proof.is_valid()
    assert verifier.verify(responses)


def test_dlne_non_interactive_1(group):
    g = group.generator()
    x = Secret()
    y = 3 * g
    y2 = 397474 * g
    g2 = 1397 * g

    p1 = DLNotEqual([y, g], [y2, g2], x, bind=True)
    secret_dict = {x: 3}
    tr = p1.prove(secret_dict)
    p2 = DLNotEqual([y, g], [y2, g2], x, bind=True)
    assert p2.verify(tr)


def test_dlne_non_interactive_2(group):
    g = group.generator()
    x = Secret(value=3)
    y = 3 * g
    y2 = 397474 * g
    g2 = 1397 * g

    p1 = DLNotEqual([y, g], [y2, g2], x, bind=True)
    tr = p1.prove()
    p2 = DLNotEqual([y, g], [y2, g2], Secret(), bind=True)
    assert p2.verify(tr)


def test_dlne_fails_when_non_binding(group):
    """
    TODO: Describe what is being tested here.
    """
    g = group.generator()
    x = Secret()
    y = 3 * g
    g2 = 1397 * g
    y2 = 3 * g2

    p1 = DLNotEqual([y, g], [y2, g2], x)
    p2 = DLNotEqual([y, g], [y2, g2], x)
    secret_dict = {x: 3}
    prover = p1.get_prover(secret_dict)
    verifier = p2.get_verifier()
    verifier.process_precommitment(prover.precommit())
    commitment = prover.commit()
    challenge = verifier.send_challenge(commitment)
    responses = prover.compute_response(challenge)

    assert not verifier.verify(responses)


def test_dlne_simulate(group):
    g = group.generator()
    x = Secret()
    y = 3 * g
    y2 = 397474 * g
    g2 = 1397 * g

    p = DLNotEqual([y, g], [y2, g2], x, bind=True)
    secret_dict = {x: 3}
    tr = p.simulate()
    assert p.verify_simulation_consistency(tr)
    assert not p.verify(tr)
