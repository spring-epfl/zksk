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
from zksk.exceptions import VerificationError


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
    Simulated proof transcript
    """

    commitment = attr.ib()
    challenge = attr.ib()
    responses = attr.ib()
    precommitment = attr.ib(default=None)
    statement = attr.ib(default=None)


class Prover(metaclass=abc.ABCMeta):
    """
    An abstract interface representing Prover used in sigma protocols
    """

    def __init__(self, proof, secret_values):
        """
        Constructs a Prover. Called by Proof.get_prover(), either by directly the user or by a composition Prover such as AndProver, OrProver.
        :param proof: The Proof instance from which we draw the Prover.
        :param secret_values: The values of the secrets as a dict.
        """
        self.proof = proof
        self.secret_values = secret_values

    @abc.abstractmethod
    def compute_response(self, challenge):
        """
        Computes the responses associated to each Secret object in the proof, and returns the list.
        """
        pass

    def precommit(self):
        """
        Generates a precommitment set to None if this function is not overriden.
        """
        return None

    def commit(self, randomizers_dict=None):
        """
        Gathers the commitment of the instantiated prover, and appends a hash of the proof statement
        to it. Returns the tuple.

        Args:
            randomizers_dict: Optional dictionary of random values. Each random values is assigned
                to a secret.
        """
        return (
            self.proof.prehash_statement().digest(),
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
        Construct a non-interactive proof transcript using Fiat-Shamir heuristic.

        The transcript contains only the challenge and the responses, as the commitment can be
        deterministically recomputed.

        The challenge is a hash of the commitment, the proof statement and all the bases in the
        proof (including the left-hand-side).

        Args:
            message (str): Optional message to make a signature proof of knowledge.
        """
        # Precommit to gather encapsulated precommitments. They are already included in their
        # respective proof statement.
        precommitment = self.precommit()
        commitment = self.proof.ec_encode(self.internal_commit())

        # Create a hash object with proof statement.
        prehash = self.proof.prehash_statement()

        # Save a hash of the proof statement only
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

    def __init__(self, proof):
        self.proof = proof

    @abc.abstractmethod
    def check_responses_consistency(self, response, response_dict=None):
        """
        Verifies that for two identical secrets, the responses are also the same.
        Returns False by default, should be overriden.
        """
        return False

    def process_precommitment(self, precommitment):
        """
        Receives a precommitment and processes it, i.e instantiates a constructed proof if
        necessary. If not overriden, does nothing.
        """
        pass

    def send_challenge(self, commitment):
        """
        Stores the received commitment and generates a challenge. The challenge is chosen at random
        between 0 and CHALLENGE_LENGTH (excluded).

        Args:
            commitment: A tuple containing a hash of the proof statement, to be compared against the local statement,
                and the commmitment as a (potentially multi-level list of) base(s) of the group.
        """
        statement, self.commitment = commitment
        self.proof.check_statement(statement)
        self.challenge = get_random_num(bits=CHALLENGE_LENGTH)
        return self.challenge

    def verify(self, arg):
        """
        Verifies the responses of an interactive sigma protocol. To do so, generates a
        pseudo-commitment based on the stored challenge and the received responses,
        and compares it against the stored commitment.

        Args:
            response: The response given by the prover

        Returns:
            bool: True if verification succeeded, False otherwise.
        """
        # Optional verification criteria.
        if not self.proof.is_valid():
            return False

        if not self.check_responses_consistency(arg, {}):
            raise VerificationError("Responses for the same secret name do not match!")

        # Retrieve the commitment using the verification identity
        return self.commitment == self.proof.recompute_commitment(self.challenge, arg)

    def verify_NI(self, transcript, message="", encoding=None):
        """
        Verify a non-interactive transcript.

        Unpacks the attributes and checks their consistency by computing a pseudo-commitment and
        drawing from it a pseudo-challenge. Compares the pseudo-challenge with the transcript
        challenge.

        Args:
            transcript: A instance of :py:`NonInteractiveTranscript`
            message: A message if a signature proof.

        Return:
            bool: True of verification succeeded, False otherwise.
        """
        # Build the complete proof if necessary.
        if transcript.precommitment is not None:
            self.process_precommitment(transcript.precommitment)

        # Check the proofs statements match, gather the local statement.
        prehash = self.proof.check_statement(transcript.statement)

        # Optional verification criteria.
        if not self.proof.is_valid():
            return False
        if not self.check_responses_consistency(transcript.responses, {}):
            raise Exception("Responses for a same secret name do not match!")

        # Retrieve the commitment using the verification identity.
        r_guess = self.proof.recompute_commitment(
            transcript.challenge, transcript.responses
        )

        # Hash the commitment and the optional message.
        prehash.update(self.proof.ec_encode(r_guess))
        prehash.update(message.encode())
        return transcript.challenge == Bn.from_hex(
            binascii.hexlify(prehash.digest()).decode()
        )


