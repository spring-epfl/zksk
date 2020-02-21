"""
Common clases, including subclassable basic provers and verifiers.
"""

import abc
import random
import string
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.pack import *
import binascii
import msgpack
from hashlib import sha256
from collections import defaultdict
import attr

from zksk.utils import get_random_num
from zksk.consts import CHALLENGE_LENGTH
from zksk.exceptions import ValidationError


@attr.s
class NIZK:
    """
    Non-interactive zero-knowledge proof.
    """

    challenge = attr.ib()
    responses = attr.ib()
    precommitment = attr.ib(default=None)
    stmt_hash = attr.ib(default=None)


@attr.s
class SimulationTranscript:
    """
    Simulated proof transcript.
    """

    commitment = attr.ib()
    challenge = attr.ib()
    responses = attr.ib()
    precommitment = attr.ib(default=None)
    stmt_hash = attr.ib(default=None)


def build_fiat_shamir_challenge(stmt_prehash, *args, message=""):
    """Generate a Fiat-Shamir challenge.

    >>> prehash = sha256(b"statement id")
    >>> commitment = 42 * EcGroup().generator()
    >>> isinstance(build_fiat_shamir_challenge(prehash, commitment), Bn)
    True

    Args:
        prehash: Hash object seeded with the proof statement ID.
        args: Items to hash (e.g., commitments)
        message: Message to make it a signature PK.
    """
    # Start building the complete hash for the challenge
    for elem in args:
        if not isinstance(elem, bytes) and not isinstance(elem, str):
            encoded = encode(elem)
        else:
            encoded = elem
        stmt_prehash.update(encoded)

    stmt_prehash.update(message.encode())
    return Bn.from_hex(stmt_prehash.hexdigest())


class Prover(metaclass=abc.ABCMeta):
    """
    Abstract interface representing Prover used in sigma protocols.

    Args:
        stmt: The Proof instance from which we draw the Prover.
        secret_values: The values of the secrets as a dict.
    """

    def __init__(self, stmt, secret_values):
        self.stmt = stmt
        self.secret_values = secret_values

    @abc.abstractmethod
    def compute_response(self, challenge):
        """
        Computes the responses associated to each Secret object in the statement.

        Returns a list of responses.
        """
        pass

    def precommit(self):
        """
        Generate a precommitment.
        """
        return None

    def commit(self, randomizers_dict=None):
        """
        Constuct the proof commitment.

        Args:
            randomizers_dict: Optional dictionary of random values. Each random values is assigned
                to a secret.
        """
        return (
            self.stmt.prehash_statement().digest(),
            self.internal_commit(randomizers_dict),
        )

    def get_nizk_proof(self, message=""):
        """
        Construct a non-interactive proof transcript using Fiat-Shamir heuristic.

        The transcript contains only the challenge and the responses, as the commitment can be
        deterministically recomputed.

        The challenge is a hash of the commitment, the stmt statement and all the bases in the
        statement (including the left-hand-side).

        Args:
            message (str): Optional message to make a signature stmt of knowledge.
        """
        # Precommit to gather encapsulated precommitments. They are already included in their
        # respective statement.
        precommitment = self.precommit()
        commitment = self.internal_commit()

        # Generate the challenge.
        prehash = self.stmt.prehash_statement()
        stmt_hash = prehash.digest()
        challenge = build_fiat_shamir_challenge(
            prehash, precommitment, commitment, message=message
        )

        responses = self.compute_response(challenge)
        return NIZK(
            challenge=challenge,
            responses=responses,
            precommitment=precommitment,
            stmt_hash=stmt_hash,
        )


class Verifier(metaclass=abc.ABCMeta):
    """
    An abstract interface representing Prover used in sigma protocols
    """

    def __init__(self, stmt):
        self.stmt = stmt

    @abc.abstractmethod
    def check_responses_consistency(self, response, response_dict=None):
        """
        Verify that for two identical secrets, the responses are also the same.
        """
        return False

    def process_precommitment(self, precommitment):
        """
        Receive a precommitment and process it.
        """
        pass

    def send_challenge(self, commitment):
        """
        Store the received commitment and generate a challenge.

        The challenge is chosen at random between 0 and ``CHALLENGE_LENGTH`` (excluded).

        Args:
            commitment: A tuple containing a hash of the stmt statement, to be
                compared against the local statement, and the commmitment as a
                (potentially multi-level list of) base(s) of the group.
        """
        statement, self.commitment = commitment
        self.stmt.check_statement(statement)
        self.challenge = get_random_num(bits=CHALLENGE_LENGTH)
        return self.challenge

    def pre_verification_validation(self, response, *args, **kwargs):
        self.stmt.full_validate(*args, **kwargs)

        if not self.check_responses_consistency(response, {}):
            raise ValidationError("Responses for the same secret name do not match.")

    def verify(self, response, *args, **kwargs):
        """
        Verify the responses of an interactive sigma protocol.

        To do so, generates a pseudo-commitment based on the stored challenge and the received
        responses, and compares it against the stored commitment.

        Args:
            response: The response given by the prover

        Returns:
            bool: True if verification succeeded, False otherwise.
        """
        # TODO: I really don't think this chain should be raising exceptions
        self.pre_verification_validation(response, *args, **kwargs)

        # Retrieve the commitment using the verification identity
        return self.commitment == self.stmt.recompute_commitment(
            self.challenge, response
        )

    def verify_nizk(self, nizk, message="", *args, **kwargs):
        """
        Verify a non-interactive proof.

        Unpacks the attributes and checks their consistency by computing a pseudo-commitment and
        drawing from a pseudo-challenge. Compares the pseudo-challenge with the nizk challenge.

        Args:
            nizk (:py:class:`NIZK`): Non-interactive proof
            message: A message if a signature proof.

        Return:
            bool: True of verification succeeded, False otherwise.
        """
        # Build the complete stmt if necessary.
        # TODO: If empty precommit() function, this is always true.
        if nizk.precommitment is not None:
            self.process_precommitment(nizk.precommitment)

        # Check the proofs statements match, gather the local statement.
        prehash = self.stmt.check_statement(nizk.stmt_hash)
        self.pre_verification_validation(nizk.responses, *args, **kwargs)

        # Retrieve the commitment using the verification identity.
        commitment_prime = self.stmt.recompute_commitment(
            nizk.challenge, nizk.responses
        )
        challenge_prime = build_fiat_shamir_challenge(
            prehash, nizk.precommitment, commitment_prime, message=message
        )
        return nizk.challenge == challenge_prime
