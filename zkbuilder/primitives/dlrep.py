"""
ZK proof for linear representations of discrete logarithms, our basic building block.

An example of such proof is :math:`PK\{ (x_0, x_1): y = x_0 G_0 + x_1 G_1 \}`, where :math:`x_0` and
:math:`x_1` are secret integers from a finite field, :math:`G_0` and :math:`G_1` are points on a
same elliptic curve, and :math:`y` is the actual value of the expression :math:`x_0 G_0 + x_1 G_1`.

See "`Proof Systems for General Statements about Discrete Logarithms`_" by Camenisch and Stadler,
1997 for the details.


.. _`Proof Systems for General Statements about Discrete Logarithms`:
    ftp://ftp.inf.ethz.ch/pub/crypto/publications/CamSta97b.pdf

"""

from zkbuilder.base import *
from zkbuilder.expr import Secret, Expression
from zkbuilder.composition import *
from zkbuilder.exceptions import IncompleteValuesError

import warnings


class DLRepVerifier(Verifier):

    def check_responses_consistency(self, responses, responses_dict=None):
        """
        Check if reoccuring secrets indeed yield the same responses.

        To do so, go through the names of the secrets in the current DLRep, and construct a mapping
        between secrets and responses.

        Args:
            response: List of responses
            responses_dict: Mapping from secrets or secret names to responses

        Returns:
            bool: True if responses are consistent, False otherwise.
        """
        if responses_dict is None:
            responses_dict = {}

        for i in range(len(self.proof.secret_vars)):
            s = self.proof.secret_vars[i]
            if s in responses_dict.keys():
                if responses[i] != responses_dict[s]:
                    warnings.warn(
                        "Names are",
                        self.proof.secret_vars,
                        "/ Incorrect for",
                        self.proof.secret_vars[i],
                    )
                    warnings.warn("Values are", responses[i], "/ Should be", responses_dict[s])
                    return False
            else:
                responses_dict.update({s: responses[i]})
        return True


class DLRep(Proof):
    """
    Proof statement for a discrete-logarithm representation proof.

    Supported statements of the following form:

    .. math::
        PK\{ (x_0, x_1, ..., x_n): y = x_0 G_0 + x_1 G_1 + ... + x_n G_n \}

    Example usage for :math:`PK\{x: y = x G \}`:

    >>> from petlib.ec import EcGroup
    >>> x = Secret(42, name="x")
    >>> g = EcGroup().generator()
    >>> y = x * g
    >>> stmt = DLRep(y, x * g)
    >>> proof = stmt.prove()

    Args:
        expr (:py:class:`zkbuilder.base.Expression`): Proof statement.
            For example: ``Secret("x") * g`` represents :math:`PK\{ x: y = x G \}`.
        lhs: "Left-hand side." Value of :math:`y`.
    """
    verifier_cls = DLRepVerifier

    def __init__(self, lhs, expr):
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
        Get a prover for the current proof statement.

        Args:
            secrets_dict: Optional mapping from secrets or secret names to their values.

        Returns:
            :py:class:`DLRepProver` or None: Prover object if all secret values are known.
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
            # TODO: Make this raise:
            # raise IncompleteValuesError(self.secret_vars)
            return None

        # We check everything is indeed a big number, else we cast it
        for name, sec in secrets_dict.items():
            if not isinstance(sec, Bn):
                secrets_dict[name] = Bn(sec)

        return DLRepProver(self, secrets_dict)

    def get_proof_id(self):
        """
        Get the identifier for the proof.

        This identifier is used to check the proof statements on the prover and
        verifier sides are consistent, and to generate a challenge in non-interactive proofs.

        Returns:
            str: Proof ID
        """
        return str(["DLRep", self.lhs, self.generators])

    def get_randomizers(self):
        """
        Initialize randomizers for each secret.

        Each randomizer is drawn at random from the associated group.

        By using a dictionary, we enforce that if secret are repeated in :math:`x_0 G_0 + x_1 G_1 +
        ... + x_n G_n`, that is, if :math:`x_i` and :math:`x_j` have the same name, they will get
        the same random value. Identical secret values and identical randomizers will yield
        identical responses, and this identity will be checked by the verifier.

        Returns:
            dict: Mapping from secrets to the random values that are needed to compute the responses
                of the proof.
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
        to the actual one in the generic :py:func:`Verifier.verify` method.

        Args:
            challenge: A challenge value
            responses: A list of responses

        Returns:
            The required commitment matching the parameters.
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
            responses_dict: Optinal mapping from secrets or secret names to responses.
            challenge: Optional challenge to use in the simulation
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
    """The prover in a discrete logarithm proof."""

    def internal_commit(self, randomizers_dict=None):
        """
        Compute the commitment using the randomizers.

        Args:
            randomizers_dict: Optional mapping from secrets or secret names to random values. Every
                random value not given here will be generated at random.

        Returns:
            A single commitment---sum of bases, weighted by the corresponding randomizers
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
        Constructs an (ordered) list of response for each secret.

        For each secret :math:`x` and a random value :math:`k` (associated to :math:`x`), the
        response is equal to :math:`k + c x`, where :math:`c` is the challenge value.

        Args:
            challenge: Challenge value

        Returns:
            A list of responses
        """
        order = self.proof.generators[0].group.order()
        resps = [
            (self.secret_values[self.proof.secret_vars[i]] * challenge + self.ks[i])
            % order
            for i in range(len(self.ks))
        ]
        return resps

