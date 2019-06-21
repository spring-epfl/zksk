"""
A module containing multiple classes used to create discrete logarithms proofs.
An example of DL proof would be PK{(x1,x2): y1 = x1 * g1 + x2 * g2} where g1 and g2 are points on a same elliptic curve
over a chosen finite field. 
"""
import os, sys

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_code_path = os.path.join(root_dir, "")
if src_code_path not in sys.path:
    sys.path.append(src_code_path)

from Abstractions import *
from CompositionProofs import Proof

"""
This file gives a framework to build the lowest building block of the compiler i.e a discrete logarithm representation of a base.
All classes inherit from generic classes defined in Abstractions or CompositionProofs.
"""


class DLRepProof(Proof):
    """
    This class is used to model a discrete logarithm proof e.g. PK{(x1, x2): y = x1 * g1 + x2 * g2}.
    Generic class is defined in CompositionProofs
    """

    def __init__(self, lhs, rightSide):
        """
        Parses the constructor arguments to separate Secret objects and generators. Will fail if generators from different groups are combined.
        :param rightSide: An instance of the 'RightSide' class e.g composed of Secret objects and group generators. For the previous example 'rightSide' would be: Secret("x1") * g1 + Secret("x2") * g2.
        :param lhs: The group generator to prove correct construction/factorization of. The prover has to prove that he knows the secrets xi-s such that x1 * g1 + x2 * g2 + ... + xn * gn = lhs
        
        """
        if isinstance(rightSide, RightSide):
            self.generators = rightSide.pts
            self.secret_vars = rightSide.secrets
        else:
            raise Exception("Undefined behaviour for this input")

        # Check all the generators live in the same group
        test_group = self.generators[0].group
        for g in self.generators:
            if g.group != test_group:
                raise Exception(
                    "All generators should come from the same group", g.group
                )
        # Construct a dictionary with the secret values we already know
        self.secret_values = {}
        for sec in self.secret_vars:
            if sec.value is not None:
                self.secret_values[sec] = sec.value
        self.lhs = lhs
        self.simulation = False

    def get_prover(self, secrets_dict={}):
        """
        Draws a DLRepProver from the current Proof. Will fail if any secret value is unknown.
        :param secrets_dict: A dictionnary mapping secret names to petlib.bn.Bn numbers, to update/overwrite the existent complete secrets (of which the values is available).
        :return: An instance of DLRepProver, or None if some secrets values are missing.
        """

        # First we update the dictionary we have with the additional secrets, and process it
        self.secret_values.update(secrets_dict)
        secrets_dict = self.secret_values
        # Forget the secrets if told so. If missing secrets, return now
        if (
            self.simulation == True
            or secrets_dict == {}
            or any(sec not in secrets_dict.keys() for sec in set(self.secret_vars))
        ):
            print("Missing secrets in DLRep with secrets objects", self.secret_vars)
            return None

        # We check everything is indeed a BigNumber, else we cast it
        for name, sec in secrets_dict.items():
            if not isinstance(sec, Bn):
                secrets_dict[name] = Bn(sec)

        return DLRepProver(self, secrets_dict)

    def get_verifier(self):
        """
        Draws a DLRepVerifier from the current Proof. 
        """
        return DLRepVerifier(self)

    def get_proof_id(self):
        """
        Generates a list identifier for the proof. Syntax is ["DLRep", left-hand-side base, [list of other bases]].
        This identifier is used to check the proof statements on the prover and verifier sides are consistent, and to generate a challenge in non-interactive proofs.
        """
        return ["DLRep", self.lhs, self.generators]

    def get_randomizers(self) -> dict:
        """
        Initializes randomizers for each Secret in the associated DLRepProof. Each are drawn at random between 0 and the order of the associated group.
        By using a dict, we enforce that if secret are repeated in x1 * g1 + x2 * g2 + ... + xn * gn (that is if xi and xj have the same name) then they will get
        the same random value. Identical secret values and identical randomizers will yield identical responses, and this identity will be checked by the Verifier.
        :return: Random values to compute the responses of the proof of knowledge for each of the secrets. 
        """
        output = {}
        order = self.generators[0].group.order()
        for sec in set(self.secret_vars):
            output.update({sec: order.random()})
        return output

    def recompute_commitment(self, challenge, responses):
        """
        Applies an equivalent verification equation for the current proof model: computes the commitment which would match the challenge and responses.
        This commitment is to be compared to the actual one in the generic Verifier.verify() method.
        :param challenge: A petlib.bn.Bn representing the challenge
        :param responses: A list of petlib.bn.Bn
        :return: The required commitment matching the parameters
        """

        leftside = (
            self.lhs.group.wsum(responses, self.generators) + (-challenge) * self.lhs
        )
        return leftside

    def simulate_proof(self, responses_dict=None, challenge=None):
        """
        Returns a transcript of a proof simulation. Responses and challenge can be enforced.
        The function will misbehave if passed a non-empty but incomplete responses_dict.
        :param responses_dict: a dictionary from secret names (strings) to responses (petlib.bn.Bn numbers)
        :param challenge: the challenge to enforce in the simulation
        """
        if responses_dict is None or responses_dict == {}:
            responses_dict = self.get_randomizers()
        if challenge is None:
            challenge = chal_randbits(CHAL_LENGTH)

        response = [responses_dict[m] for m in self.secret_vars]
        # Random responses, the same for shared secrets
        commitment = self.recompute_commitment(challenge, response)

        return SimulationTranscript(commitment, challenge, response)


class DLRepProver(Prover):
    """
    The prover in a discrete logarithm proof. See Abstractions file for details on the super class Prover.
    """

    def internal_commit(self, randomizers_dict=None):
        """
        Computes the commitment using the randomizers and returns it. The function will misbehave if passed a non-empty but incomplete randomizers_dict. 
        :param randomizers_dict: Optional dictionary of random values for the Secret objects. Every value not enforced will be generated at random.
        :return: A single commitment (base for the group), sum of bases (each weighted by the corresponding randomizer).
        """
        # We check we are not a strawman prover
        if self.secret_values == {}:
            raise Exception(
                "Trying to do a legit proof without the secrets. Can only simulate"
            )
        # If we are not provided a randomizer dict from above, we compute it.
        if randomizers_dict == None or randomizers_dict == {}:
            randomizers_dict = self.proof.get_randomizers()
        # Compute an ordered list of randomizers mirroring the Secret objects
        self.ks = [randomizers_dict[sec] for sec in self.proof.secret_vars]
        subcommits = [a * b for a, b in zip(self.ks, self.proof.generators)]
        # We build the commitment doing the product g1^k1 g2^k2...
        sum_ = self.proof.generators[0].group.infinite()
        for com in subcommits:
            sum_ = sum_ + com

        return sum_

    def compute_response(self, challenge):
        """
        Constructs an (ordered) list of N response mirroring the N secrets/generators
        :param challenge: A number of type petlib.bn.Bn
        :return: A list of responses, for each secret x and a random value k (associated to x), the response is equal to k + challenge * x
        """
        order = self.proof.generators[0].group.order()
        resps = [
            (self.secret_values[self.proof.secret_vars[i]] * challenge + self.ks[i])
            % order
            for i in range(len(self.ks))
        ]
        return resps


class DLRepVerifier(Verifier):
    """
    The prover in a discrete logarithm proof. See Abstractions file for details on the super class Prover.
    """

    def check_responses_consistency(self, response, responses_dict={}):
        """Goes through the secret names of the current DLRepProof and checks if reoccuring secrets indeed yield the same responses.
        To do so, constructs a map (dict) between secrets and responses.
        """
        for i in range(len(self.proof.secret_vars)):
            s = self.proof.secret_vars[i]
            if s in responses_dict.keys():
                if response[i] != responses_dict[s]:
                    print(
                        "names are",
                        self.proof.secret_vars,
                        "incorrect for",
                        self.proof.secret_vars[i],
                    )
                    print("values are", response[i], "should be", responses_dict[s])
                    return False
            else:
                responses_dict.update({s: response[i]})
        return True
