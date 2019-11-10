r"""
ZK proof for linear representations of discrete logarithms, our basic building block.

An example of such proof is :math:`PK\{ (x_0, x_1): y = x_0 G_0 + x_1 G_1 \}`, where :math:`x_0` and
:math:`x_1` are secret integers from a finite field, :math:`G_0` and :math:`G_1` are points on a
same elliptic curve, and :math:`y` is the actual value of the expression :math:`x_0 G_0 + x_1 G_1`.

See "`Proof Systems for General Statements about Discrete Logarithms`_" by Camenisch and Stadler,
1997 for the details.

.. _`Proof Systems for General Statements about Discrete Logarithms`:
    ftp://ftp.inf.ethz.ch/pub/crypto/publications/CamSta97b.pdf

"""
from hashlib import sha256

from petlib.bn import Bn

from zksk.base import Verifier, Prover, SimulationTranscript
from zksk.expr import Secret, Expression
from zksk.utils import get_random_num
from zksk.consts import CHALLENGE_LENGTH
from zksk.composition import ComposableProofStmt
from zksk.exceptions import IncompleteValuesError, InvalidExpression

import warnings


class DLRepVerifier(Verifier):
    def check_responses_consistency(self, responses, responses_dict=None):
        """
        Check if reoccuring secrets yield the same responses.

        To do so, go through the names of the secrets in the current DLRep, and construct a mapping
        between secrets and responses.

        Args:
            response: List of responses
            responses_dict: Mapping from secrets to responses

        Returns:
            bool: True if responses are consistent, False otherwise.
        """
        if responses_dict is None:
            responses_dict = {}

        for i, s in enumerate(self.stmt.secret_vars):
            if s in responses_dict.keys():
                if responses[i] != responses_dict[s]:
                    return False
            else:
                responses_dict.update({s: responses[i]})
        return True


class DLRep(ComposableProofStmt):
    """
    Proof statement for a discrete-logarithm representation proof.

    Supports statements of the following form:

    .. math::
        PK\{ (x_0, x_1, ..., x_n): Y = x_0 G_0 + x_1 G_1 + ... + x_n G_n \}

    Example usage for :math:`PK\{x: Y = x G \}`:

    >>> from petlib.ec import EcGroup
    >>> x = Secret(name="x")
    >>> g = EcGroup().generator()
    >>> y = 42 * g
    >>> stmt = DLRep(y, x * g)
    >>> nizk = stmt.prove({x: 42})
    >>> stmt.verify(nizk)
    True

    Args:
        expr (:py:class:`zksk.base.Expression`): Proof statement.
            For example: ``Secret("x") * g`` represents :math:`PK\{ x: Y = x G \}`.
        lhs: "Left-hand side." Value of :math:`Y`.
    """

    verifier_cls = DLRepVerifier

    def __init__(self, lhs, expr, simulated=False):
        if isinstance(expr, Expression):
            self.bases = list(expr.bases)
            self.secret_vars = list(expr.secrets)
        else:
            raise TypeError("Expected an Expression. Got: {}".format(expr))

        # Check all the generators live in the same group
        test_group = self.bases[0].group
        for g in self.bases:
            if g.group != test_group:
                raise InvalidExpression(
                    "All bases should come from the same group", g.group
                )

        # Construct a dictionary with the secret values we already know
        self.secret_values = {}
        for sec in self.secret_vars:
            if sec.value is not None:
                self.secret_values[sec] = sec.value

        self.lhs = lhs
        self.set_simulated(simulated)

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
            self.set_simulated()
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

    def get_proof_id(self, secret_id_map=None):
        """
        Identifier for the proof statement

        Returns:
            list: Objects that can be used for hashing.
        """
        proof_id = super().get_proof_id(secret_id_map)
        return proof_id + [self.lhs]

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
        order = self.bases[0].group.order()
        for sec in set(self.secret_vars):
            output.update({sec: order.random()})
        return output

    def recompute_commitment(self, challenge, responses):

        commitment = (
            self.lhs.group.wsum(responses, self.bases) + (-challenge) * self.lhs
        )
        return commitment

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
            challenge = get_random_num(CHALLENGE_LENGTH)

        responses = [responses_dict[m] for m in self.secret_vars]
        # Random responses, the same for shared secrets
        commitment = self.recompute_commitment(challenge, responses)

        return SimulationTranscript(
            commitment=commitment, challenge=challenge, responses=responses
        )


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
        randomizers_dict = self.stmt.update_randomizers(randomizers_dict)

        # Compute an ordered list of randomizers mirroring the Secret objects
        self.ks = [randomizers_dict[sec] for sec in self.stmt.secret_vars]
        subcommits = [a * b for a, b in zip(self.ks, self.stmt.bases)]

        # We build the commitment doing the product k0 * g0 + k1 * g1...
        result = self.stmt.bases[0].group.infinite()
        for com in subcommits:
            result = result + com

        return result

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
        order = self.stmt.bases[0].group.order()
        resps = [
            (self.secret_values[self.stmt.secret_vars[i]] * challenge + k) % order
            for i, k in enumerate(self.ks)
        ]
        return resps
