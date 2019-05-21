"""
A module containing multiple classes used to create discrete logarithms proofs.
An example of DL proof would be PK{(x1,x2): y1 = x1 * g1 + x2 * g2} where g1 and g2 are points on a same elliptic curve
over a chosen finite field. 
"""

import random, string
from Subproof import RightSide
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from SigmaProtocol import *
from hashlib import sha256
import binascii
from CompositionProofs import Proof


def randomword(length):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


class DLRepProver(Prover):
    """
    The prover in a discrete logarithm proof.
    """

    def __init__(self, proof, secret_values):
        """
        :param generators: a list of elliptic curve points of type petlib.ec.EcPt
        :param secret_names: a list of strings equal to the names of the secrets.
        :param secret_values: the values of the secrets as a dict.
        :param lhs: the left hand side of the equation of the proof of knowledge. If the proof is PK{(x1,x2): y = x1 * g1 + x2 * g2}, lhs is y. 
        """
        self.secret_values = secret_values
        self.proof = proof

    def get_secret_values(self):
        return self.secret_values

    def get_randomizers(self) -> dict:
        """
        :return: random values to compute the response of the proof of knowledge for each of the secrets. 
        We enforce that if secret are repeated in x1 * g1 + x2 * g2 + ... + xn * gn (that is if xi and xj have the same name) then they will get
        the same random value. 
        """
        output = {}
        for idx, sec in enumerate(
            self.proof.secret_names
        ):  
        # This overwrites if shared secrets but allows to access the appropriate group order
            key = sec
            to_append = self.proof.generators[idx].group.order().random()
            output.update({key: to_append})
        return output

    def commit(self, randomizers_dict=None):
        """
        :param randomizers_dict: an optional dictionnary of random values. Each random values is assigned to each secret name
        :return: a single commitment (of type petlib.ec.EcPt) for the whole proof
        """

        if self.secret_values == {}:
            # We check we are not a strawman prover
            raise Exception(
                "Trying to do a legit proof without the secrets. Can only simulate"
            )
        tab_g = self.proof.generators
        G = tab_g[0].group
        self.group_order = G.order()
        # Will be useful for all the protocol

        if randomizers_dict == None:
            # If we are not provided a randomizer dict from above, we compute it
            secret_to_random_value = self.get_randomizers()
        elif any([sec not in randomizers_dict.keys() for sec in self.proof.secret_names]):
            # We were passed an incomplete dict, fill the empty slots but keep the existing ones
            secret_to_random_value = self.get_randomizers()
            secret_to_random_value.update(randomizers_dict)
        else:
            secret_to_random_value = randomizers_dict

        self.ks = [secret_to_random_value[sec] for sec in self.proof.secret_names]
        commits = [a * b for a, b in zip(self.ks, tab_g)]

        # We build the commitment doing the product g1^k1 g2^k2...
        sum_ = G.infinite()
        for com in commits:
            sum_ = sum_ + com

        return sum_

    def compute_response(self, challenge):
        """
        :param challenge: a number of type petlib.bn.Bn
        :return: a list of responses: for each secret we have a response
        for a given secret x and a challenge c and a random value k (associated to x). We have the response equal to k + c * x
        """
        resps = [
            (self.secret_values[self.proof.secret_names[i]] * challenge + self.ks[i])
            % self.group_order
            for i in range(len(self.ks))
        ]
        return resps

    def simulate_proof(
        self, responses_dict=None, challenge=None
    ): 
        """
        :param responses_dict: a dictionnary from secret names (strings) to responses (petlib.bn.Bn numbers)
        :param challenge: a petlib.bn.Bn equal to the challenge
        :return: a list of valid commitments for each secret value given responses_dict and a challenge
        """
        # Set the recompute_commitment
        if responses_dict is None:
            responses_dict = (
                self.get_randomizers()
            )  # TODO : should we ensure consistency for two identical statements to simulate ?
        if challenge is None:
            challenge = chal_randbits(CHAL_LENGTH)

        response = [
            responses_dict[m] for m in self.proof.secret_names
        ]  
        # random responses, the same for shared secrets
        commitment = self.proof.recompute_commitment(challenge, response)

        return commitment, challenge, response


class DLRepVerifier(Verifier):
    def __init__(self, proof):
        self.proof = proof

    def check_responses_consistency(self, response, responses_dict={}):
        """Goes through the secret names of the current DLRepProof and checks consistency with respect to a response dictionary.
        Updates the dictionary if the entry doesn't exist yet.
        """
        for i in range(len(self.proof.secret_names)):
            s = self.proof.secret_names[i]
            if s in responses_dict.keys():
                if response[i] != responses_dict[s]:
                    print(
                        "names are",
                        self.proof.secret_names,
                        "incorrect for",
                        self.proof.secret_names[i],
                    )
                    print("values are", response[i], "should be", responses_dict[s])
                    return False
            else:
                responses_dict.update({s: response[i]})
        return True


class DLRepProof(Proof):
    """The class is used to model a discrete logarithm proof
    for the sake of having an example say we want to create the proof PK{(x1, x2): y = x1 * g1 + x2 * g2}
    """

    def __init__(self, lhs, rightSide):
        """
        :param rightSide: an instance of the 'RightSide' class. For the previous example 'rightSide' would be: Secret("x1") * g1 + Secret("x2") * g2. Here gi-s are instances of petlib.ec.EcPt
        :param lhs: an instance of petlib.ec.EcPt. The prover has to prove that he knows the secrets xi-s such that x1 * g1 + x2 * g2 + ... + xn * gn = lhs
        """

        if isinstance(rightSide, RightSide):
            self.initialize(
                rightSide.pts, [secret.name for secret in rightSide.secrets], lhs
            )
        else:
            raise Exception("undefined behaviour for this input")

    # len of secretDict and generators param of __init__ must match exactly
    def initialize(self, generators, secret_names, lhs):
        """
        this method exists for historical reasons. It is used in __init__ of this class.
        :param generators: a list of petlib.ec.EcPt
        :secret_names: a list of strings equal to the names of the secrets
        """

        if len(secret_names) != len(generators):
            raise Exception("secret_names and generators must be of the same length")

        # Check all the generators live in the same group
        test_group = generators[0].group
        for g in generators:
            if g.group != test_group:
                raise Exception(
                    "All generators should come from the same group", g.group
                )

        self.generators = generators
        self.secret_names = secret_names
        self.lhs = lhs
        self.simulate = False

    def get_prover(self, secrets_dict):
        """
        :param secrets_dict: a dictionnary mapping secret names to petlib.bn.Bn numbers
        :return: an instance of DLRepProver
        """
        if self.simulate == True or secrets_dict == {}:
            print("Can only simulate")
            return self.get_simulator()
        if len(set(self.secret_names)) != len(secrets_dict):
            raise Exception("We expect as many secrets as different aliases")

        if not isinstance(secrets_dict, dict):
            raise Exception("secrets_dict should be a dictionary")

        # Check that the secret names and the keys of the secret values actually match. Could be simplified since it only matters that all names are in dict
        secret_names_set = set(self.secret_names)
        secrets_keys = set(secrets_dict.keys())
        diff1 = secrets_keys.difference(secret_names_set)
        diff2 = secret_names_set.difference(secrets_keys)

        if len(diff1) > 0 or len(diff2) > 0:
            raise Exception(
                "secrets do not match: those secrets should be checked {0} {1}".format(
                    diff1, diff2
                )
            )

        # We check everything is indeed a BigNumber, else we cast it
        for name, sec in secrets_dict.items():
            if not isinstance(sec, Bn):
                secrets_dict[name] = Bn(sec)

        return DLRepProver(self, secrets_dict)

    def get_simulator(self):
        """ Returns an empty prover which can only simulate (via simulate_proof)
        """
        return DLRepProver(self, {})

    def get_verifier(self):
        """
        :return: a DLRepVerifier for this proof
        """
        return DLRepVerifier(self)

    def get_proof_id(self):
        return ["DLRep", self.lhs, self.generators]

    def recompute_commitment(self, challenge, responses):
        """
        :param challenge: the petlib.bn.Bn representing the challenge
        :param responses: a list of petlib.bn.Bn
        :return: the commitment from the parameters
        """

        leftside = self.lhs.group.wsum(responses, self.generators) + (-challenge) * self.lhs
        return leftside
