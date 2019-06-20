import random, string
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.pack import *
import binascii
import msgpack
import pdb
from hashlib import sha256
from collections import defaultdict


CHAL_LENGTH = Bn(128)

""" Known limitations :
        - In a non-interactive proof, if the prover and the verifier use two mathematically equivalent yet syntaxically 
            different expressions (e.g "p1 & p2" and "p2 & p1"), the verification fails because of the get_proof_id routine not aware of
            distributivity and commutativity.
        - multiple Or Proofs are still bugged for DLRNE and signatures because of constructed_proof objects diverging 
"""


class NITranscript:
    """
    A named tuple for non-interactive proofs transcripts.
    """

    def __init__(self, challenge, responses, precommitment=None, statement=None):
        self.challenge = challenge
        self.responses = responses
        self.precommitment = precommitment
        self.statement = statement


class SimulationTranscript:
    """
    A named tuple for simulated proofs transcripts.
    """

    def __init__(
        self, commitment, challenge, responses, precommitment=None, statement=None
    ):
        self.commitment = commitment
        self.challenge = challenge
        self.responses = responses
        self.precommitment = precommitment
        self.statement = statement


class Prover:
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

    def commit(self, randomizers_dict=None):
        """
        Gathers the commitment of the instantiated prover, and appends a hash of the proof statement to it. Returns the tuple.
        :param randomizers_dict: An optional dictionnary of random values. Each random values is assigned to a secret.
        """
        return (
            self.proof.prehash_statement().digest(),
            self.internal_commit(randomizers_dict),
        )

    def compute_response(self, challenge):
        """
        Computes the responses associated to each Secret object in the proof, and returns the list.
        """
        pass

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
        return NITranscript(challenge, responses, precommitment, statement)

    def precommit(self):
        """
        Generates a precommitment set to None if this function is not overriden.
        """
        return None


class Verifier:
    """
    An abstract interface representing Prover used in sigma protocols
    """

    def __init__(self, proof):
        self.proof = proof

    def send_challenge(self, commitment):
        """
        Stores the received commitment and generates a challenge. The challenge is chosen at random between 0 and CHAL_LENGTH (excluded).
        :param commitment: A tuple containing a hash of the proof statement, to be compared against the local statement, 
        and the commmitment as a (potentially multi-level list of) base(s) of the group. 
        """
        statement, self.commitment = commitment
        self.proof.check_statement(statement)
        self.challenge = chal_randbits(CHAL_LENGTH)
        return self.challenge

    def process_precommitment(self, precommitment):
        """
        Receives a precommitment and processes it, i.e instantiates a constructed proof if necessary. If not overriden, does nothing.
        """
        pass

    def verify(self, arg):
        """
        Verifies the responses of an interactive sigma protocol. To do so, generates a pseudo-commitment based on the stored challenge and the received responses,
        and compares it against the stored commitment.
        :param response: The response given by the prover
        :rtype: Boolean
        """
        # Optional verification criteria
        if not self.check_adequate_lhs():
            return False
        if not self.check_responses_consistency(arg, {}):
            raise Exception("Responses for a same secret name do not match!")
        # Retrieve the commitment using the verification identity
        return self.commitment == self.proof.recompute_commitment(self.challenge, arg)

    def verify_NI(self, transcript, message="", encoding=None):
        """
        Verifies a non-interactive transcript. Unpacks the attributes and checks their consistency by computing a pseudo-commitment
        and drawing from it a pseudo-challenge. Compares the pseudo-challenge with the transcript challenge. (Fiat-Shamir heuristics)
        :param transcript: A instance of NonInteractiveTranscript
        :rtype: Boolean
        """
        # Build the complete proof if necessary
        if transcript.precommitment is not None:
            self.process_precommitment(transcript.precommitment)
        # Check the proofs statements match, gather the local statement
        prehash = self.proof.check_statement(transcript.statement)
        # Optional verification criteria
        if not self.check_adequate_lhs():
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

    def check_adequate_lhs(self):
        """
        Optional verification criteria to be checked at verification step. Returns True by default, to be overriden if necessary.
        """
        return True


def check_groups(list_of_secret_vars, list_of_generators):
    """
    Tool function checking that if two secrets in the proof are the same, the generators at corresponding indices induce groups of same order.
    Can be deactivated in the future since it can forbid using different groups in one proof.
    Primary utility is to ensure same responses for same secrets will not yield false negatives of chek_responses_consistency due to 
    different group order modular reductions.
    :param list_of_secret_vars: a list of secrets names of type Secret. 
    :param list_of_generators: a list of generators (bases).
    """
    # We map the unique secrets to the indices where they appear
    mydict = defaultdict(list)
    for idx, word in enumerate(list_of_secret_vars):
        mydict[word].append(idx)

    # Now we use this dictionary to check all the generators related to a particular secret live in the same group
    for (word, gen_idx) in mydict.items():
        # word is the key, gen_idx is the value = a list of indices
        ref_order = list_of_generators[gen_idx[0]].group.order()

        for index in gen_idx:
            if list_of_generators[index].group.order() != ref_order:
                raise Exception(
                    "A shared secret has generators which yield different group orders : secret",
                    word,
                )

    return True


def chal_randbits(bitlength=CHAL_LENGTH):
    """
    Draws a random number of given bitlength.
    """
    maxi = Bn(2).pow(bitlength)
    return maxi.random()


def get_secret_vars(sub_list):
    """
    Gathers all Secret objects in a list of Proofs. Used in Or/And Proofs.
    """
    secrets = []
    [secrets.extend(elem.secret_vars) for elem in sub_list]
    return secrets


def get_generators(sub_list):
    """
    Gathers all generators in a list of Proofs. Used in Or/And Proofs.
    """
    generators = []
    [generators.extend(elem.generators.copy()) for elem in sub_list]
    return generators


def add_Bn_array(arr, modulus):
    """ 
    Tool to sum elements an array under a modulus. Used in OrProof.
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


"""
Below are the interface methods
"""


class RightSide:
    """
    A class that can be obtained by composing (with the addition operator) elements of type Secret with group elements.
    It is an abstraction for x1 * g1 + x2 * g2 + ... + xn * gn where xi-s are declared Secrets.
    Parses the sum into an ordered list of Secrets and an ordered list of generators.
    """

    def __init__(self, secret, ecPt):
        """
        :param secret: of type Secret
        :param ecPt: a base of a group
        """
        if not isinstance(secret, Secret):
            raise Exception(
                "in {0} * {1}, the first parameter should be a Secret ".format(
                    secret, ecPt
                )
            )
        self.secrets = [secret]
        self.pts = [ecPt]

    def __add__(self, other):
        """
        Merges RightSide objects along addition.
        :param other: of type RightSide
        :return: an extended version of the current object
        """
        if not isinstance(other, RightSide):
            raise Exception(
                '${0} doesn\'t correspond to something like "x1" * g1 + "x2" * g2 + ... + "xn" * gn'
            )
        self.secrets.extend(other.secrets)
        self.pts.extend(other.pts)
        return self

    def eval(self):
        """
        Computes the actual value of the sum using the values of the Secrets if they are all available.
        """
        for secret in self.secrets:
            if secret.value == None:
                raise Exception(
                    "trying to evaluate secret {0} which was set with no value".format(
                        secret.name
                    )
                )

        def ith_mul(i):
            return self.secrets[i].value * self.pts[i]

        summation = ith_mul(0)
        for i in range(1, len(self.secrets)):
            summation += ith_mul(i)
        return summation


class Secret:
    def __init__(self, alias="", value=None):
        """
        :param alias: String to enforce as name of the Secret. Mostly a debugging tool.
        :param value: Optional petlib.bn.Bn number equal to the secret value. 
        """
        self.name = str(hash(self)) if alias == "" else alias
        self.value = value

    def __mul__(self, ecPt):
        """
        :param ecPt: a base of the cyclic group
        :return: a RightSide fresh instance abstracting the multiplication between this Secret and ecPt
        """
        return RightSide(self, ecPt)

    __rmul__ = __mul__

    def __repr__(self):
        return self.name


def wsum_secrets(secrets, generators):
    """
    Returns a complete RightSide object when passed a list of Secret instances and a list of generators, of same length.
    """
    if len(secrets) != len(generators):
        raise Exception("Bad wsum")
    sum_ = secrets[0] * generators[0]
    for idx in range(len(generators) - 1):
        sum_ = sum_ + secrets[idx + 1] * generators[idx + 1]
    return sum_
