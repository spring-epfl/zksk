import random, string
from functools import reduce
from collections import namedtuple
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.pack import *
import binascii
import pdb
from hashlib import sha256
from collections import defaultdict
from BilinearPairings import *
import msgpack

CHAL_LENGTH = Bn(128)

""" Known flaws :
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
    def __init__(self, commitment, challenge, responses, precommitment=None, statement=None):
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
        pass

    def commit(self, randomizers_dict=None):
        """
        :param randomizers_dict: an optional dictionnary of random values. Each random values is assigned to each secret name
        :return: a single commitment (of type petlib.bn.Bn) for the whole proof
        """
        return self.proof.hash_statement(), self.internal_commit(randomizers_dict)


    def compute_response(self, challenge):
        pass

    def get_NI_proof(self, message="", encoding=None):
        """ Non-interactive proof 
        :param message: a string message.
        :return: a challenge that is a hash of a proof descriptor containing all public information along with left-hand-sides, and a list of responses. 
        """
        # precommit to 1.gather encapsulated precommitments
        # 2.write the precommitments in their respective proof so the get_proof_id embeds them
        precommitment = self.precommit()
        statement, commitment = self.commit()
        message = message.encode()
        protocol = encode(self.proof.get_proof_id(), encoding)

        # Computing the challenge
        conc = protocol
        conc += encode(commitment, encoding)
        conc += message
        myhash = sha256(conc).digest()
        challenge = Bn.from_hex(binascii.hexlify(myhash).decode())

        responses = self.compute_response(challenge)
        return NITranscript(challenge, responses, precommitment, statement)

    def precommit(self):
        return None

    def simulate_proof(self):
        pass


class Verifier:
    def send_challenge(self, commitment):
        """
        :param commitment: a petlib.bn.Bn number
        :return: a random challenge smaller than 2**128
        """
        statement, self.commitment = commitment
        self.proof.check_statement(statement)
        self.challenge = chal_randbits(CHAL_LENGTH)
        return self.challenge

    def process_precommitment(self, precommitment):
        pass

    def verify(self, arg):
        """
        Can verify simulations with optional arguments.
        verifies this proof
        :param response: the response given by the prover
        :return: a boolean telling whether or not the commitment given by the prover matches the one we obtain by recomputing a commitment from the given challenge and response
        """
        if not self.check_adequate_lhs():
            return False
        if not self.check_responses_consistency(arg, {}):
            raise Exception("Responses for a same secret name do not match!")
        return self.commitment == self.proof.recompute_commitment(self.challenge, arg)

    def verify_NI(self, transcript, message="", encoding=None):
        """
        verification for the non interactive proof according to Fiat-Shamir heuristics
        :param challenge: the challenge a petlib.bn.Bn instance computed from get_NI_proof method
        :param response: computed from get_NI_proof
        :return: a boolean telling if the proof is verified
        """
        if transcript.precommitment is not None:
            self.process_precommitment(transcript.precommitment)
        self.proof.check_statement(transcript.statement)
        if not self.check_adequate_lhs():
            return False
        if not self.check_responses_consistency(transcript.responses, {}):
            raise Exception("Responses for a same secret name do not match!")
        message = message.encode()
        protocol = encode(self.get_proof_id(), encoding)
        r_guess = self.proof.recompute_commitment(
            transcript.challenge, transcript.responses
        )
        # We retrieve the commitment using the verification identity
        conc = protocol
        # encode is a petlib.pack function also allowing to use msgpack with external types
        conc += encode(r_guess, encoding)
        conc += message
        myhash = sha256(conc).digest()
        return transcript.challenge == Bn.from_hex(binascii.hexlify(myhash).decode())

    def get_proof_id(self):
        """:return: a descriptor of the Proof with the protocol name and the public info. 
        Does NOT contain the secrets' names.
        """
        return self.proof.get_proof_id()

    def check_responses_consistency(self, response, response_dict={}):
        return True

    def check_adequate_lhs(self):
        return True


def check_groups(list_of_secret_names, list_of_generators):
    """checks that if two secrets are the same, the generators they multiply induce groups of same order
    :param list_of_secret_names: a list of secrets names of type string. 
    :param list_of_generators: a list of generators of type petlib.ec.EcPt.
    """
    # We map the unique secrets to the indices where they appear
    mydict = defaultdict(list)
    for idx, word in enumerate(list_of_secret_names):
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


# Useful for several proofs :


def chal_randbits(bitlength=CHAL_LENGTH):
    maxi = Bn(2).pow(bitlength)
    return maxi.random()


def get_secret_names(sub_list):
    secrets = []
    [secrets.extend(elem.secret_names) for elem in sub_list]
    return secrets


def get_generators(sub_list):
    generators = []
    [generators.extend(elem.generators.copy()) for elem in sub_list]
    return generators


def add_Bn_array(arr, modulus):
    """ Tool to sum an array under a modulus 
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
    return msgpack.ExtType(10, obj.__repr__().encode())


"""
Below are the interface methods
"""


class RightSide:
    """
    A class that can be obtained by composing (with the addition operator) elements of type Secret with element of type petlib.ec.EcPt.
    It is an abstraction for x1 * g1 + x2 * g2 + ... + xn * gn where xi-s have unknown or known values.
    This is essentially a class that types this syntactic sugar: Secret(\"x1\") * g1 + Secret(\"x2\") * g2 + ...  where gi-s are instances of petlib.ec.EcPt
    c.f. DLRepProof to see how RightSide is used.
    Secret("x") can be assigned a value at its creation by creating it like so: Secret("x", val) where val is of type petlib.bn.Bn
    """

    def __init__(self, secret, ecPt):
        """
        :param secret: of type Secret
        :param ecPt: of type petlib.ec.EcPt
        """
        if not isinstance(secret, Secret):
            raise Exception(
                "in {0} * {1}, the first parameter should be a string ".format(
                    secret, ecPt
                )
            )
        self.secrets = [secret]
        self.pts = [ecPt]

    def __add__(self, other):
        """
        :param other: of type RightSide
        :return: a new element of type RightSide representing self + other
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
        this method allows for writing things such as 
        x1 = petlib.bn.Bn(10)
        x2 = petlib.bn.Bn(20)
        rhs = Secret("x1", x1) * g1 + Secret("x2", x2) 
        proof = DLRepProof(rhs.eval(), rhs) # this is where we can be a little bit lazy and not write DLRepProof(x1 * g1 + x2 * g2, rhs)
        proof.get_prover({"x1": x1, "x2": x2})
        :return: the value to which this RightSide is equal to if each Secret has already been assigned a value at its creation
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
    def __init__(self, alias=""):
        """
        :param name: a string equal to the name of this secret 
        :param value: an optional petlib.bn.Bn number equal to the secret value. This can be left for later at the creation of the prover.
        """
        self.name = str(hash(self)) if alias == "" else alias

    def __mul__(self, ecPt):
        """
        :param ecPt: an instance of petlib.ec.EcPt
        :return: a RightSide fresh instance abstracting the multiplication between this Secret and ecPt
        """
        return RightSide(self, ecPt)

    __rmul__ = __mul__

    def __repr__(self):
        return self.name


def wsum_secrets(secrets, generators):
    if len(secrets) != len(generators):
        raise Exception("Bad wsum")
    sum_ = secrets[0] * generators[0]
    for idx in range(len(generators) - 1):
        sum_ = sum_ + secrets[idx + 1] * generators[idx + 1]
    return sum_
