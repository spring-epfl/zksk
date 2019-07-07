"""

Known limitations :
        - In a non-interactive proof, if the prover and the verifier use two mathematically equivalent yet syntaxically
            different expressions (e.g "p1 & p2" and "p2 & p1"), the verification fails because of the get_proof_id routine not aware of
            distributivity and commutativity.
"""

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


CHALLENGE_LENGTH = Bn(128)


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
        Gathers the commitment of the instantiated prover, and appends a hash of the proof statement to it. Returns the tuple.
        :param randomizers_dict: An optional dictionnary of random values. Each random values is assigned to a secret.
        """
        return (
            self.proof.prehash_statement().digest(),
            self.internal_commit(randomizers_dict),
        )

    def get_secret_values(self):
        """
        A simple getter for the secret dictionary. Called by an AndProver/OrProver to gather the secret values of its subproofs.
        """
        return self.secret_values

    def get_NI_proof(self, message=""):
        """
        Constructs a non-interactive proof transcript embedding only a challenge and responses, since the commitment can be recomputed (deterministic).
        The challenge is a hash of the commitment, the proof statement and all the bases in the proof (including the left-hand-side).
        :param message: An optional string message.
        """
        # precommit to gather encapsulated precommitments. They are already included in their respective proof statement.
        precommitment = self.precommit()

        commitment = self.proof.ec_encode(self.internal_commit())

        # Create a SHA-256 hash object with proof statement.
        prehash = self.proof.prehash_statement()
        # Save a hash of the proof statement only
        statement = prehash.digest()
        # Start building the complete hash for the challenge
        prehash.update(commitment)
        prehash.update(message.encode())

        challenge = Bn.from_hex(binascii.hexlify(prehash.digest()).decode())

        responses = self.compute_response(challenge)
        return NITranscript(challenge=challenge, responses=responses, precommitment=precommitment, statement=statement)


class Verifier(metaclass=abc.ABCMeta):
    """
    An abstract interface representing Prover used in sigma protocols
    """

    def __init__(self, proof):
        self.proof = proof

    def process_precommitment(self, precommitment):
        """
        Receives a precommitment and processes it, i.e instantiates a constructed proof if necessary. If not overriden, does nothing.
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
        self.challenge = chal_randbits(CHALLENGE_LENGTH)
        return self.challenge

    def verify(self, arg):
        """
        Verifies the responses of an interactive sigma protocol. To do so, generates a
        pseudo-commitment based on the stored challenge and the received responses,
        and compares it against the stored commitment.

        Args:
            response: The response given by the prover

        Return: bool
        """
        # Optional verification criteria
        if not self.proof.check_adequate_lhs():
            return False
        if not self.check_responses_consistency(arg, {}):
            raise Exception("Responses for a same secret name do not match!")
        # Retrieve the commitment using the verification identity
        return self.commitment == self.proof.recompute_commitment(self.challenge, arg)

    def verify_NI(self, transcript, message="", encoding=None):
        """
        Verify a non-interactive transcript. Unpacks the attributes and checks their consistency by computing a pseudo-commitment
        and drawing from it a pseudo-challenge. Compares the pseudo-challenge with the transcript challenge. (Fiat-Shamir heuristics)

        Args:
            transcript: A instance of :py:`NonInteractiveTranscript`
            message: A message if a signature proof.

        Return: bool
        """
        # Build the complete proof if necessary
        if transcript.precommitment is not None:
            self.process_precommitment(transcript.precommitment)
        # Check the proofs statements match, gather the local statement
        prehash = self.proof.check_statement(transcript.statement)
        # Optional verification criteria
        if not self.proof.check_adequate_lhs():
            return False
        if not self.check_responses_consistency(transcript.responses, {}):
            raise Exception("Responses for a same secret name do not match!")
        # Retrieve the commitment using the verification identity
        r_guess = self.proof.recompute_commitment(
            transcript.challenge, transcript.responses
        )
        # Add to the hash object the commitment and the optional message, then digest
        prehash.update(self.proof.ec_encode(r_guess))
        prehash.update(message.encode())
        return transcript.challenge == Bn.from_hex(
            binascii.hexlify(prehash.digest()).decode()
        )

    def check_responses_consistency(self, response, response_dict={}):
        """
        Verifies that for two identical secrets, the responses are also the same.
        Returns False by default, should be overriden.
        """
        return False


def chal_randbits(bitlength=CHALLENGE_LENGTH):
    """
    Draws a random number of given bitlength.
    """
    order = Bn(2).pow(bitlength)
    return order.random()


def get_secret_vars(sub_list):
    """
    Gathers all Secret objects in a list of Proofs.
    """
    secrets = []
    [secrets.extend(elem.secret_vars) for elem in sub_list]
    return secrets


def get_generators(sub_list):
    """
    Gathers all generators in a list of Proofs.
    """
    generators = []
    [generators.extend(elem.generators) for elem in sub_list]
    return generators


def add_Bn_array(arr, modulus):
    """
    Sum elements an array under a modulus. Used in OrProof.
    """
    if not isinstance(modulus, Bn):
        modulus = Bn(modulus)
    res = Bn(0)
    for elem in arr:
        if not isinstance(elem, Bn):
            elem = Bn(elem)
        res = res.mod_add(elem, modulus)
    return res


def enc_GXpt(obj):
    """
    Custom encode for petlib.pack module. Used to pack points which are not instances of petlib.ec.EcPt
    """
    return msgpack.ExtType(10, obj.__repr__().encode())


def find_residual_chal(arr, challenge, chal_length):
    """
    Tool function to determine the complement to a global challenge in a list, i.e:
    To find c1 such that c = c1 + c2 +c3 mod k,
    We compute c2 + c3 -c and take the opposite
    :param arr: The array of subchallenges c2, c3...
    :param challenge: The global challenge to reach
    :param chal_length: the modulus to reduce to
    """
    modulus = Bn(2).pow(chal_length)
    temp_arr = arr.copy()
    temp_arr.append(-challenge)
    return -add_Bn_array(temp_arr, modulus)


def sub_proof_prover(sub_proof, secrets_dict):
    """
    Tool function used in both Or and And proofs to get a prover from a subproof
    by giving it only the secrets it should know and not more.
    :param sub_proof: The proof from which to get a prover
    :param secrets_dict: The secret values to filter out before passing them to the prover
    """
    keys = set(sub_proof.secret_vars)
    secrets_for_prover = {}
    for s_name in secrets_dict.keys():
        if s_name in keys:
            secrets_for_prover[s_name] = secrets_dict[s_name]
    return sub_proof.get_prover(secrets_for_prover)
