"""
Classes and tools create discrete-log-representation ZK proofs, our basic building block.

An example of DL proof is :math:`PK{(x_1, x_2): y_1 = x_1 g_1 + x_2 g_2}` where :math:`g_1` and
:math:`g_2` are points on a same elliptic curve over a chosen finite field.

"""

import os, sys

from zkbuilder.base import *
from zkbuilder.composition import *


class DLRepVerifier(Verifier):

    def check_responses_consistency(self, response, responses_dict=None):
        """Goes through the secret names of the current DLRep and checks if reoccuring secrets indeed yield the same responses.
        To do so, constructs a map (dict) between secrets and responses.
        """
        if responses_dict is None:
            responses_dict = {}

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


class DLRep(Proof):
    """
    This class is used to model a discrete logarithm proof e.g. PK{(x1, x2): y = x1 * g1 + x2 * g2}.
    Generic class is defined in CompositionProofs

    Args:
        expr: An :py:`zkbuilder.base.Expression` object. For example: ``Secret("x1") * g1 + Secret("x2") * g_2``
        lhs: The group generator to prove correct construction/factorization of. The prover
            has to prove that he knows the secrets xi-s such that x1 * g1 + x2 * g2 + ... + xn * gn = lhs

    Raises:
        If generators from different groups are combined.
    """
    verifier_cls = DLRepVerifier

    def __init__(self, lhs, expr):
        """
        """
        if isinstance(expr, Expression):
            self.generators = expr.pts
            self.secret_vars = expr.secrets
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

    def get_prover(self, secrets_dict=None):
        """
        Draws a DLRepProver from the current Proof. Will fail if any secret value is unknown.
        :param secrets_dict: A dictionnary mapping secret names to petlib.bn.Bn numbers, to update/overwrite the existent complete secrets (of which the values is available).
        :return: An instance of DLRepProver, or None if some secrets values are missing.
        """
        if secrets_dict is None:
            secrets_dict = {}

        # First we update the dictionary we have with the additional secrets, and process it
        self.secret_values.update(secrets_dict)
        secrets_dict = self.secret_values
        # If missing secrets or simulation parameter set, return now
        if (
            self.simulation == True
            or secrets_dict == {}
            or any(sec not in secrets_dict.keys() for sec in set(self.secret_vars))
        ):
            print("Missing secrets in DLRep with secrets objects", self.secret_vars)
            return None

        # We check everything is indeed a big number, else we cast it
        for name, sec in secrets_dict.items():
            if not isinstance(sec, Bn):
                secrets_dict[name] = Bn(sec)

        return DLRepProver(self, secrets_dict)

    def get_proof_id(self):
        """
        Generates an identifier for the proof. Syntax is ["DLRep", left-hand-side base, [list of
        other bases]].  This identifier is used to check the proof statements on the prover and
        verifier sides are consistent, and to generate a challenge in non-interactive proofs.
        """
        return ["DLRep", self.lhs, self.generators]

    def get_randomizers(self):
        """
        Initializes randomizers for each Secret in the associated DLRep. Each are drawn at
        random between 0 and the order of the associated group.  By using a dict, we enforce that if
        secret are repeated in x1 * g1 + x2 * g2 + ... + xn * gn (that is if xi and xj have the same
        name) then they will get the same random value. Identical secret values and identical
        randomizers will yield identical responses, and this identity will be checked by the
        Verifier.  :return: Random values to compute the responses of the proof of knowledge for
        each of the secrets.
        """
        output = {}
        order = self.generators[0].group.order()
        for sec in set(self.secret_vars):
            output.update({sec: order.random()})
        return output

    def recompute_commitment(self, challenge, responses):
        """
        Applies an equivalent verification equation for the current proof model: computes the
        commitment which would match the challenge and responses.  This commitment is to be compared
        to the actual one in the generic :py:method:`Verifier.verify` method.

        Args:
            challenge: A challenge
            responses: A list of responses

        Return: The required commitment matching the parameters
        """

        leftside = (
            self.lhs.group.wsum(responses, self.generators) + (-challenge) * self.lhs
        )
        return leftside

    def simulate_proof(self, responses_dict=None, challenge=None):
        """
        Returns a transcript of a proof simulation. Responses and challenge can be enforced.  The
        function will misbehave if passed a non-empty but incomplete responses_dict.

        Args:
            responses_dict: a dictionary from secret names (strings) to responses.
            challenge: the challenge to enforce in the simulation
        """
        # Fill the missing positions of the responses dictionary
        responses_dict = self.update_randomizers(responses_dict)
        if challenge is None:
            challenge = chal_randbits(CHALLENGE_LENGTH)

        responses = [responses_dict[m] for m in self.secret_vars]
        # Random responses, the same for shared secrets
        commitment = self.recompute_commitment(challenge, responses)

        return SimulationTranscript(commitment=commitment, challenge=challenge, responses=responses)


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
        # Fill the missing positions of the randomizers dictionary
        randomizers_dict = self.proof.update_randomizers(randomizers_dict)
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

