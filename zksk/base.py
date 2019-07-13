import abc
import random
import string
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.pack import *
import binascii
import msgpack
import pdb
from hashlib import sha256
from collections import defaultdict
import attr

from zksk.utils import get_random_num
from zksk.consts import CHALLENGE_LENGTH
from zksk.exceptions import ValidationError


@attr.s
class NITranscript:
    """
    Non-interactive proofs transcripts.
    """

    challenge = attr.ib()
    responses = attr.ib()
    precommitment = attr.ib(default=None)
    statement = attr.ib(default=None)


@attr.s
class SimulationTranscript:
    """
    Simulated stmt transcript
    """

    commitment = attr.ib()
    challenge = attr.ib()
    responses = attr.ib()
    precommitment = attr.ib(default=None)
    statement = attr.ib(default=None)


class Prover(metaclass=abc.ABCMeta):
    """
    An abstract interface representing Prover used in sigma protocols

    Args:
        stmt: The Proof instance from which we draw the Prover.
        secret_values: The values of the secrets as a dict.
    """

    def __init__(self, stmt, secret_values):
        """
        """
        self.stmt = stmt
        self.secret_values = secret_values

    @abc.abstractmethod
    def compute_response(self, challenge):
        """
        Computes the responses associated to each Secret object in the stmt, and returns the list.
        """
        pass

    def precommit(self):
        """
        Generates a precommitment set to None if this function is not overriden.
        """
        return None

    def commit(self, randomizers_dict=None):
        """
        Gathers the commitment of the instantiated prover, and appends a hash of the stmt statement
        to it. Returns the tuple.

        Args:
            randomizers_dict: Optional dictionary of random values. Each random values is assigned
                to a secret.
        """
        return (
            self.stmt.prehash_statement().digest(),
            self.internal_commit(randomizers_dict),
        )

    def get_secret_values(self):
        """
        A simple getter for the secret dictionary. Called by an AndProver/OrProver to gather the
        secret values of its subproofs.
        """
        return self.secret_values

    def get_NI_proof(self, message=""):
        """
        Construct a non-interactive stmt transcript using Fiat-Shamir heuristic.

        The transcript contains only the challenge and the responses, as the commitment can be
        deterministically recomputed.

        The challenge is a hash of the commitment, the stmt statement and all the bases in the
        stmt (including the left-hand-side).

        Args:
            message (str): Optional message to make a signature stmt of knowledge.
        """
        # Precommit to gather encapsulated precommitments. They are already included in their
        # respective stmt statement.
        precommitment = self.precommit()
        commitment = encode(self.internal_commit())

        # Create a hash object with stmt statement.
        prehash = self.stmt.prehash_statement()

        # Save a hash of the stmt statement only
        statement = prehash.digest()

        # Start building the complete hash for the challenge
        prehash.update(commitment)
        prehash.update(message.encode())
        challenge = Bn.from_hex(binascii.hexlify(prehash.digest()).decode())

        responses = self.compute_response(challenge)
        return NITranscript(challenge=challenge, responses=responses, precommitment=precommitment,
                statement=statement)


class Verifier(metaclass=abc.ABCMeta):
    """
    An abstract interface representing Prover used in sigma protocols
    """

    def __init__(self, stmt):
        self.stmt = stmt

    @abc.abstractmethod
    def check_responses_consistency(self, response, response_dict=None):
        """
        Verifies that for two identical secrets, the responses are also the same.
        Returns False by default, should be overriden.
        """
        return False

    def process_precommitment(self, precommitment):
        """
        Receives a precommitment and processes it, i.e instantiates a constructed stmt if
        necessary. If not overriden, does nothing.
        """
        pass

    def send_challenge(self, commitment):
        """
        Stores the received commitment and generates a challenge. The challenge is chosen at random
        between 0 and CHALLENGE_LENGTH (excluded).

        Args:
            commitment: A tuple containing a hash of the stmt statement, to be compared against the local statement,
                and the commmitment as a (potentially multi-level list of) base(s) of the group.
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
        Verifies the responses of an interactive sigma protocol. To do so, generates a
        pseudo-commitment based on the stored challenge and the received responses,
        and compares it against the stored commitment.

        Args:
            response: The response given by the prover

        Returns:
            bool: True if verification succeeded, False otherwise.
        """
        self.pre_verification_validation(response, *args, **kwargs)

        # Retrieve the commitment using the verification identity
        return self.commitment == self.stmt.recompute_commitment(self.challenge, response)

    def verify_NI(self, transcript, message="", *args, **kwargs):
        """
        Verify a non-interactive transcript.

        Unpacks the attributes and checks their consistency by computing a pseudo-commitment and
        drawing from it a pseudo-challenge. Compares the pseudo-challenge with the transcript
        challenge.

        Args:
            transcript: A instance of :py:`NonInteractiveTranscript`
            message: A message if a signature stmt.

        Return:
            bool: True of verification succeeded, False otherwise.
        """
        # Build the complete stmt if necessary.
        if transcript.precommitment is not None:
            self.process_precommitment(transcript.precommitment)

        # Check the proofs statements match, gather the local statement.
        prehash = self.stmt.check_statement(transcript.statement)
        self.pre_verification_validation(transcript.responses, *args, **kwargs)

        # Retrieve the commitment using the verification identity.
        commitment_prime = self.stmt.recompute_commitment(
            transcript.challenge, transcript.responses
        )

        # Hash the commitment and the optional message.
        prehash.update(encode(commitment_prime))
        prehash.update(message.encode())
        return transcript.challenge == Bn.from_hex(
            binascii.hexlify(prehash.digest()).decode()
        )

