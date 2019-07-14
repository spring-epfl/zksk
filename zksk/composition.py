"""
TODO: Fix docs of and/or proofs.
"""

import abc
import copy
import random
from hashlib import sha256
from collections import defaultdict

from petlib.bn import Bn
from petlib.pack import encode

from zksk.base import Prover, Verifier, SimulationTranscript
from zksk.expr import update_secret_values
from zksk.utils import get_random_num, sum_bn_array
from zksk.consts import CHALLENGE_LENGTH
from zksk.exceptions import StatementSpecError, StatementMismatch
from zksk.exceptions import InvalidSecretsError, GroupMismatchError


def _find_residual_challenge(subchallenges, challenge, modulus):
    """
    Determine the complement to a global challenge in a list

    For example, to find :math:`c_1` such that :math:`c = c_1 + c_2 + c_3 \mod k`, we compute
    :math:`c_2 + c_3 - c` and take the opposite.

    Args:
        subchallenges: The array of subchallenges :math:`c_2`, c_3, ...`
        challenge: The global challenge to reach
        modulus: the modulus :math:`k`
    """
    modulus = Bn(2).pow(modulus)
    temp_arr = subchallenges.copy()
    temp_arr.append(-challenge)
    return -sum_bn_array(temp_arr, modulus)


class ComposableProofStmt(metaclass=abc.ABCMeta):
    """A composable sigma-protocol proof statement."""

    @abc.abstractmethod
    def get_proof_id(self):
        pass

    def get_secret_vars(self):
        """Collect all secrets in this subtree.

        By default tries to get the ``secret_vars`` attribute. Override if needed.
        """
        if not hasattr(self, "secret_vars"):
            raise StatementSpecError(
                "Need to override get_secret_vars or specify secret_vars " "attribute."
            )
        return self.secret_vars

    def get_bases(self):
        """Collect all base points in this subtree.

        By default tries to get the ``bases`` attribute. Override if needed.
        """
        if not hasattr(self, "bases"):
            raise StatementSpecError(
                "Need to override get_bases or specify bases attribute."
            )
        return self.bases

    def __and__(self, other):
        """
        Return a conjuction of proof statements using :py:class:`AndProofStmt`.

        If called multiple times, subproofs are flattened so that only one :py:class:`AndProofStmt`
        remains at the root.
        """
        if isinstance(other, AndProofStmt):
            if isinstance(self, AndProofStmt):
                return AndProofStmt(*self.subproofs, *other.subproofs)
            else:
                return AndProofStmt(self, *other.subproofs)

        elif isinstance(self, AndProofStmt):
            return AndProofStmt(*self.subproofs, other)

        return AndProofStmt(self, other)

    def __or__(self, other):
        """
        Return a disjunction of proof statements using :py:class:`OrProofStmt`.

        If called multiple times, subproofs are flattened so that only one :py:class:`OrProofStmt`
        remains at the root.
        """
        if isinstance(other, OrProofStmt):
            if isinstance(self, OrProofStmt):
                return OrProofStmt(*self.subproofs, *other.subproofs)
            else:
                return OrProofStmt(self, *other.subproofs)

        elif isinstance(self, OrProofStmt):
            return OrProofStmt(*self.subproofs, other)

        return OrProofStmt(self, other)

    def prepare_simulate_proof(self):
        pass

    def get_prover_cls(self):
        if hasattr(self, "prover_cls"):
            return self.prover_cls
        else:
            raise StatementSpecError("No prover class specified.")

    def get_verifier_cls(self):
        if hasattr(self, "verifier_cls"):
            return self.verifier_cls
        else:
            raise StatementSpecError("No verifier class specified.")

    def get_prover(self, secrets_dict=None):
        """
        Return a Verifier object for the current proof.
        """
        return self.get_prover_cls()(self)

    def get_verifier(self):
        """
        Return a Verifier object for the current proof.
        """
        return self.get_verifier_cls()(self)

    def recompute_commitment(self, challenge, response):
        """
        Compute a pseudo-commitment

        A pseudo-commitment is the commitment a verifier should have received if the proof was
        correct. It should be compared to the actual commitment.

        Re-occuring secrets yield identical responses.

        Args:
            challenge: the challenge used in the proof
            response: a list of responses, ordered as the list of secret names, i.e., with as many
                elements as there are secrets in the proof claim.
        """
        pass

    def set_simulate(self):
        self.simulation = True

    def prove(self, secret_dict=None, message=""):
        """
        Generate the transcript of a non-interactive proof.
        """
        if secret_dict is None:
            secret_dict = {}
        prover = self.get_prover(secret_dict)
        return prover.get_nizk_proof(message)

    def verify(self, nizk, message=""):
        """
        Verify a non-interactive proof.
        """
        verifier = self.get_verifier()
        return verifier.verify_nizk(nizk, message)

    def simulate(self, challenge=None):
        """
        Generate the transcript of a simulated non-interactive proof.
        """
        self.set_simulate()
        self.prepare_simulate_proof()
        transcript = self.simulate_proof(challenge=challenge)
        transcript.stmt_hash = self.prehash_statement().digest()
        return transcript

    def check_statement(self, statement_hash):
        """
        Verify the current proof corresponds to the hash passed as a parameter.

        Returns a pre-hash of the current proof, e.g., to be used to verify NIZK proofs.
        """
        h = self.prehash_statement()
        if statement_hash != h.digest():
            raise StatementMismatch("Proof statements mismatch, impossible to verify")
        return h

    def validate(self, *args, **kwargs):
        """
        Validation criteria to be checked. Override if needed.

        Should be overridden if necessary.

        Raises:
            Exception: If statement is invalid.
        """
        pass

    def full_validate(self, *args, **kwargs):
        return self.validate(*args, **kwargs)

    def validate_secrets_reoccurence(self, forbidden_secrets=None):
        """
        Check if a secret appears both inside an outside an or-proof. Does nothing if not overriden.
        """
        pass

    def update_randomizers(self, randomizers_dict):
        """
        Construct a mapping of all secrets to randomizers.

        Does so by copying the values of the passed ``randomizers_dict``, and drawing the other
        values at random until all the secrets have a randomizer.

        These are used as a part of proofs and also as responses in simulations.

        Args:
            randomizers_dict: A dictionary to enforce
        """
        # If we are not provided a randomizer dict from above, we compute it.
        if randomizers_dict is None:
            randomizers_dict = self.get_randomizers()

        # Fill the dictionary.
        elif any([x not in randomizers_dict for x in self.get_secret_vars()]):
            tmp = self.get_randomizers()
            tmp.update(randomizers_dict)
            randomizers_dict = tmp

        return randomizers_dict

    def prehash_statement(self, extra=None):
        """
        Return a hash of the proof's ID.

        .. WARNING::

            Currently, proofs that mix ``petlib.ec.EcPt`` and :py:class:`pairings.G1Point`` are not
            supported.

        Args:
            extra: Optional additional object to pack, e.g a commitment (for non-interactive
                proofs). Avoids having to figure out the encoding mode multiple times.
        """
        # TODO: extra is not used.
        return sha256(encode(str(self.get_proof_id())))

    def verify_simulation_consistency(self, transcript):
        """Check if the fields of a transcript satisfy the verification equation.

        Useful for debugging purposes.

        .. WARNING::

            This is NOT an alternative to the full proof verification, as this function
            accepts simulated proofs.

        """
        verifier = self.get_verifier()
        verifier.process_precommitment(transcript.precommitment)
        self.check_statement(transcript.stmt_hash)
        verifier.commitment, verifier.challenge = (
            transcript.commitment,
            transcript.challenge,
        )
        return verifier.verify(transcript.responses)

    def __repr__(self):
        return str(self.get_proof_id())


def get_default_attr(obj, attr, default_value=None):
    if not hasattr(obj, attr):
        setattr(obj, attr, default_value)
    return getattr(obj, attr)


class ExtendedProofStmt(ComposableProofStmt, metaclass=abc.ABCMeta):
    """
    Proof that deals with precommitments.

    TODO: More details.
    """

    @abc.abstractmethod
    def construct_stmt(self):
        """
        Build internal proof statement for this class

        This function must be overridden. The function should return a
        constructed proof statement. It can use the values that were computed
        by internal_precommit to do so.
        """
        pass

    def precommit(self):
        """
        Compute precommitments. Override if needed.

        Override this function to compute precommitments and set corresponding
        secrets that must be computed before the ZK proof itself can be
        constructed and proven.

        Returns:
            precommitment: The precommitment
        """
        return []

    def simulate_precommit(self):
        """
        Simulate a precommitment. Override if needed.

        Override this method to enable using this proof in or-proofs.

        It should compute the same output as generated by precommit, but without relying on any
        secrets.
        """
        raise StatementSpecError(
            "Override simulate_precommit in order to " "use or-proofs and simulations"
        )

    def validate(self, precommitment, *args, **kwargs):
        """
        Validate proof's construction. Override if needed.
        """
        pass

    def full_validate(self, *args, **kwargs):
        self.validate(self.precommitment, *args, **kwargs)

    @property
    def constructed_stmt(self):
        return get_default_attr(self, "_constructed_stmt")

    @property
    def precommitment(self):
        return get_default_attr(self, "_precommitment")

    def get_prover(self, secrets_dict=None):
        """
        Get a prover object.

        Returns:
            Prover object if all secret values are known, None otherwise.
        """
        if secrets_dict is None:
            secrets_dict = {}

        for k, v in secrets_dict.items():
            k.value = v

        self.secret_values = {}
        self.secret_values.update(secrets_dict)

        return ExtendedProver(self, self.secret_values)

    def get_verifier_cls(self):
        return ExtendedVerifier

    def recompute_commitment(self, challenge, responses):
        """
        Recompute the commitment.
        """
        return self.constructed_stmt.recompute_commitment(challenge, responses)

    def get_proof_id(self):
        """
        Generate a proof identifier that captures the order of bases and secrets.
        """
        if self.constructed_stmt is not None:
            proof_id = (
                self.__class__.__name__,
                self.precommitment,
                self.constructed_stmt.get_proof_id(),
            )
        else:
            raise ValueError("Proof ID unknown before the proof is constructed.")
        return proof_id

    def full_construct_stmt(self, precommitment):
        self._precommitment = precommitment
        self._constructed_stmt = self.construct_stmt(precommitment)
        return self.constructed_stmt

    def prepare_simulate_proof(self):
        self._precommitment = self.simulate_precommit()
        self.full_construct_stmt(self.precommitment)

    def simulate_proof(self, responses_dict=None, challenge=None):
        """
        Simulate the proof.

        Args:
            responses_dict
            challenge
        """
        tr = self._constructed_stmt.simulate_proof(responses_dict, challenge)
        tr.precommitment = self._precommitment
        return tr

    def _precommit(self):
        self._precommitment = self.precommit()
        return self._precommitment


class ExtendedProver(Prover):
    """
    Prover dealing with precommitments.

    This prover will create a constructed Prover object and delegate to its methods.
    """

    def internal_commit(self, randomizers_dict=None):
        """
        Trigger the inside the prover commit.

        Transfers the randomizer_dict if passed. It might be used if the binding of the proof is set
        True.
        """
        if self.stmt.constructed_stmt is None:
            raise StatementSpecError(
                "You need to pre-commit before commiting. The proofs lack parameters otherwise."
            )
        return self.constructed_prover.internal_commit(randomizers_dict)

    def compute_response(self, challenge):
        """
        Wrap the response computation for the inner proof.
        """
        self.challenge = challenge
        self.constructed_prover.challenge = challenge
        self.response = self.constructed_prover.compute_response(challenge)
        return self.response

    def precommit(self):
        self.precommitment = self.stmt._precommit()
        self.process_precommitment()
        return self.precommitment

    def process_precommitment(self):
        """
        Triggers the inner proof construction and extracts a prover from it given the secrets.
        """
        self.stmt.full_construct_stmt(self.precommitment)
        self.constructed_prover = self.stmt._constructed_stmt.get_prover(
            self.secret_values
        )


class ExtendedVerifier(Verifier):
    """
    Verifier that deals with precommitments.
    """

    def process_precommitment(self, precommitment):
        """
        Receive the precommitment and trigger the inner proof construction.
        """
        self.precommitment = precommitment
        self.stmt.full_construct_stmt(precommitment)
        self.constructed_verifier = self.stmt.constructed_stmt.get_verifier()

    def send_challenge(self, com):
        """
        Check the received statement and transfer the commitment to the inner proof

        Does not not actually check any statements.
        """

        statement, self.commitment = com
        self.stmt.check_statement(statement)
        self.challenge = self.constructed_verifier.send_challenge(
            self.commitment, ignore_statement_hash_checks=True
        )
        return self.challenge

    def check_responses_consistency(self, responses, responses_dict):
        """
        Wrap the inner proof responses consistency check.
        """
        return self.constructed_verifier.check_responses_consistency(
            responses, responses_dict
        )


class _CommonComposedMixin:
    def get_secret_vars(self):
        secret_vars = []
        for sub in self.subproofs:
            secret_vars.extend(sub.get_secret_vars())
        return secret_vars

    def get_bases(self):
        bases = []
        for sub in self.subproofs:
            bases.extend(sub.get_bases())
        return bases

    def validate_group_orders(self):
        """
        Check that if two secrets are the same, their bases induce groups of the same order.

        The primary goal is to ensure same responses for same secrets will not yield false negatives of
        :py:meth:`base.Verifier.check_responses_consistency` due to different group-order modular reductions.

        TODO: Consider deactivating in the future as this forbids using different groups in one proof.
        TODO: Update docs, variable names.

        Args:
            secrets: :py:class:`expr.Secret` objects.
            bases: Elliptic curve base points.
        """
        bases = self.get_bases()
        secrets = self.get_secret_vars()

        # We map the unique secrets to the indices where they appear
        mydict = defaultdict(list)
        for idx, word in enumerate(secrets):
            mydict[word].append(idx)

        # Now we use this dictionary to check all the bases related to a particular secret live in
        # the same group
        for (word, gen_idx) in mydict.items():
            # Word is the key, gen_idx is the value = a list of indices
            ref_order = bases[gen_idx[0]].group.order()

            for index in gen_idx:
                if bases[index].group.order() != ref_order:
                    raise GroupMismatchError(
                        "A shared secret has bases which yield different group orders: %s"
                        % word
                    )

    def get_proof_id(self):
        secret_id_map = {}
        counter = 0
        secrets = self.get_secret_vars()
        # Assign each secret a consecutive identifier, unique per name.
        for secret in secrets:
            if secret.name not in secret_id_map:
                secret_id_map[secret.name] = counter
                counter += 1

        ordered_secret_ids = tuple([secret_id_map[s.name] for s in secrets])
        proof_ids = tuple([sub.get_proof_id() for sub in self.subproofs])
        return (self.__class__.__name__, ordered_secret_ids, proof_ids)

    def full_validate(self, *args, **kwargs):
        """
        Validate subproofs.

        For instance, it will return False if a :py:class:`primitives.DLNotEqual` statement is about
        to prove its components are in fact equal.
        """
        for sub in self.subproofs:
            sub.full_validate(*args, **kwargs)


class OrProofStmt(_CommonComposedMixin, ComposableProofStmt):
    """
    An disjunction of several subproofs.

    Subproofs are copied at instantiation.

    Args:
        subproofs: Two or more proof statements.
    """

    def __init__(self, *subproofs):
        if len(subproofs) < 2:
            raise ValueError("OrProofStmt needs > 1 arguments")

        # We make a shallow copy of each subproof so they don't mess up each other.  This step is
        # important, as we can have different outputs for the same proof (independent simulations or
        # simulations/execution)
        self.subproofs = [copy.copy(p) for p in list(subproofs)]
        self.simulation = False

    def recompute_commitment(self, challenge, responses):
        """
        Recompute the commitments, raise an Exception if the global challenge was not respected.

        Args:
            challenge: The global challenge sent by the verifier.
            responses: A tuple (subchallenges, actual_responses) containing the subchallenges each
                proof used (ordered list), and a list of responses (also ordered)
        """
        # We retrieve the challenges, hidden in the responses tuple
        self.or_challenges = responses[0]
        responses = responses[1]

        # We check for challenge consistency i.e the constraint was respected
        if _find_residual_challenge(
            self.or_challenges, challenge, CHALLENGE_LENGTH
        ) != Bn(0):
            raise Exception("Inconsistent challenge")

        # Compute the list of commitments, one for each proof with its challenge and responses
        # (in-order)
        com = []
        for i in range(len(self.subproofs)):
            p = self.subproofs[i]
            com.append(p.recompute_commitment(self.or_challenges[i], responses[i]))
        return com

    def get_prover(self, secrets_dict=None):
        """
        Get an OrProver, which is built on one legit prover constructed from a
        subproof picked at random among all possible candidates.
        """
        if secrets_dict is None:
            secrets_dict = {}

        # First we update the dictionary we have with the additional secrets, and process it
        # TODO: check this secret_values handling totally different
        update_secret_values(secrets_dict)

        if self.simulation == True:
            return None

        # TODO: ADD TEST: simulation must be True/False for all subproofs

        # Prepare the draw. Disqualify proofs with simulation parameter set to true
        candidates = {}
        for idx in range(len(self.subproofs)):
            if not self.subproofs[idx].simulation:
                candidates[idx] = self.subproofs[idx]

        if len(candidates) == 0:
            print("Cannot run an or-proof if all elements are simulated")
            return None

        # Now choose a proof among the possible ones and try to get a prover from it.
        # If for some reason it does not work (e.g some secrets are missing), remove it
        # from the list of possible proofs and try again
        random_gen = random.SystemRandom()
        possible = list(candidates.keys())
        self.chosen_idx = random_gen.choice(possible)

        # Feed the selected proof the secrets it needs if we have them, and try to get_prover
        valid_prover = self.subproofs[self.chosen_idx].get_prover(secrets_dict)
        while valid_prover is None:
            possible.remove(self.chosen_idx)
            # If there is no proof left, abort and say we cannot get a prover
            if len(possible) == 0:
                self.chosen_idx = None
                return None
            self.chosen_idx = random_gen.choice(possible)
            valid_prover = self.subproofs[self.chosen_idx].get_prover(secrets_dict)
        return OrProver(self, valid_prover)

    def get_verifier(self):
        return OrVerifier(self, [subp.get_verifier() for subp in self.subproofs])

    def validate_composition(self):
        self.validate_group_orders()

    def validate_secrets_reoccurence(self, forbidden_secrets=None):
        """
        Check for re-occurence of secrets both inside and outside an or-proof.

        Method is called from :py:meth:`AndProofStmt.validate_secrets_reoccurence`.

        Args:
            forbidden_secrets: A list of all the secrets in the mother proof.

        Raises:
            InvalidSecretsError: If any secrets re-occur in an unsupported way.
        """
        secret_vars = self.get_secret_vars()
        if forbidden_secrets is None:
            return

        for secret in set(secret_vars):
            if forbidden_secrets.count(secret) > secret_vars.count(secret):
                raise InvalidSecretsError(
                    "Invalid secrets found. Try to flatten the proof to avoid shared secrets "
                    "inside and outside the or-proof."
                )

    def prepare_simulate_proof(self):
        for subp in self.subproofs:
            subp.prepare_simulate_proof()

    def simulate_proof(self, responses_dict=None, challenge=None):
        """
        Simulate the or-proof.

        To do so, simulates the n-1 first subproofs, computes the complementary challenge and
        simulates the last proof using this challenge. Does not use the responses_dict passed as
        parameter since inside an or-proof responses consistency is not required between subproofs.

        Args:
            challenge: The global challenge, equal to the sum of all the subchallenges mod chal
                bitlength.
            responses_dict: A dictionary of responses to enforce for consistency.
                Useless hiere, kept to have the same prototype for all simulate_proof methods.
        """
        if challenge is None:
            challenge = get_random_num(bits=CHALLENGE_LENGTH)
        com = []
        resp = []
        or_chals = []
        precom = []

        # Generate one simulation at a time and update a list of each attribute.
        for index in range(len(self.subproofs) - 1):
            transcript = self.subproofs[index].simulate_proof()
            com.append(transcript.commitment)
            resp.append(transcript.responses)
            or_chals.append(transcript.challenge)
            precom.append(transcript.precommitment)

        # Generate the last simulation.
        final_chal = _find_residual_challenge(or_chals, challenge, CHALLENGE_LENGTH)
        or_chals.append(final_chal)
        final_transcript = self.subproofs[index + 1].simulate_proof(challenge=final_chal)
        com.append(final_transcript.commitment)
        resp.append(final_transcript.responses)
        precom.append(final_transcript.precommitment)

        # Pack everything into a SimulationTranscript, pack the or-challenges in the response field.
        return SimulationTranscript(
            commitment=com,
            challenge=challenge,
            responses=(or_chals, resp),
            precommitment=precom,
        )


class OrProver(Prover):
    """
    Prover for the or proof.

    This prover is built with only one subprover, and needs to have access to the index of the
    corresponding subproof in its mother proof. Runs all the simulations for the other proofs and
    stores them.
    """

    def __init__(self, proof, subprover):
        self.subprover = subprover
        self.stmt = proof
        self.true_prover_idx = self.stmt.chosen_idx

        # Create a list to store the SimulationTranscripts
        self.simulations = []
        self.setup_simulations()

    def setup_simulations(self):
        """
        Runs all the required simulations and stores them.
        """
        for index in range(len(self.stmt.subproofs)):
            if index != self.true_prover_idx:
                self.stmt.subproofs[index].prepare_simulate_proof()
                cur = self.stmt.subproofs[index].simulate_proof()
                self.simulations.append(cur)

    def precommit(self):
        """
        Generate precommitment for the legit subprover, and gather the precommitments from the
        stored simulations.  Outputs a list of the precommitments needed by the subproofs if any.
        Else, returns None.
        """
        precommitment = []
        for index in range(len(self.stmt.subproofs)):
            if index == self.true_prover_idx:
                precommitment.append(self.subprover.precommit())
            else:
                if index > self.true_prover_idx:
                    index1 = index - 1
                else:
                    index1 = index
                # TODO: not sure when simulations are created
                precommitment.append(self.simulations[index1].precommitment)
        if not any(precommitment):
            return None
        return precommitment

    def internal_commit(self, randomizers_dict=None):
        """
        Commits from the subprover, gathers the commitments from the stored simulations. Packs into
        a list.

        Args:
            randomizers_dict: A dictionary of randomizers to use for responses consistency. Not used
                in this proof. Parameter kept so all internal_commit methods have the same prototype.
        """
        # Now that all proofs have been constructed, we can check
        self.stmt.validate_composition()

        commitment = []
        for index in range(len(self.stmt.subproofs)):
            if index == self.true_prover_idx:
                commitment.append(self.subprover.internal_commit())
            else:
                if index > self.true_prover_idx:
                    index1 = index - 1
                else:
                    index1 = index
                commitment.append(self.simulations[index1].commitment)
        return commitment

    def compute_response(self, challenge):
        """
        Computes the complementary challenge with respect to the received global challenge and the
        list of challenges used in the stored simulations.  Computes the responses of the subprover
        using this auxiliary challenge, gathers the responses from the stored simulations.  Returns
        both the complete list of subchallenges (included the auxiliary challenge) and the list of
        responses, both ordered.

        Args:
            challenge: The global challenge to use. All subchallenges must add to this one.
        """
        residual_chal = _find_residual_challenge(
            [el.challenge for el in self.simulations], challenge, CHALLENGE_LENGTH
        )
        response = []
        challenges = []
        for index in range(len(self.stmt.subproofs)):
            if index == self.true_prover_idx:
                challenges.append(residual_chal)
                response.append(self.subprover.compute_response(residual_chal))
            else:
                # Note that len(simulations) = len(subproofs) - 1.
                if index > self.true_prover_idx:
                    index1 = index - 1
                else:
                    index1 = index
                challenges.append(self.simulations[index1].challenge)
                response.append(self.simulations[index1].responses)

        # We carry the or-challenges in a tuple, will be unpacked by the verifier calling
        # recompute_commitment.
        return (challenges, response)


class OrVerifier(Verifier):
    """
    Verifier for the or-proof.

    The verifier is built on a list of subverifiers, which will unpack the received attributes.
    """

    def __init__(self, proof, subverifiers):
        self.subs = subverifiers
        self.stmt = proof

    def process_precommitment(self, precommitment):
        """
        Reads the received list of precommitments (or None if non applicable) and distributes them
        to the subverifiers so they can finalize their proof construction if necessary.

        Args:
            precommitment: A list of all required precommitments, ordered.
        """
        if precommitment is None:
            return
        for idx in range(len(self.subs)):
            self.subs[idx].process_precommitment(precommitment[idx])

    def check_responses_consistency(self, responses, responses_dict=None):
        """
        Checks that for a same secret, response are actually the same.

        Since every member is run with its own challenge, it is enough that one member is consistent
        within itself.

        Args:
            responses: a tuple (subchallenges, actual_responses) from which we extract only the
                actual responses for each subverifier.
        """
        if responses_dict is None:
            responses_dict = {}
        for idx in range(len(self.subs)):
            if not self.subs[idx].check_responses_consistency(responses[1][idx], {}):
                return False
        return True


class AndProofStmt(_CommonComposedMixin, ComposableProofStmt):
    def __init__(self, *subproofs):
        """
        Constructs the And conjunction of several subproofs.
        Subproofs are copied at instantiation.
        :param subproofs: An arbitrary number of proofs.
        """
        if len(subproofs) < 2:
            raise ValueError("AndProofStmt needs > 1 arguments")

        # We make a shallow copy of each subproof so they dont mess with each other.  This step is
        # important in case we have proofs which locally draw random values.  It ensures several
        # occurrences of the same proof in the tree indeed have their own randomnesses.
        self.subproofs = [copy.copy(p) for p in list(subproofs)]

        self.simulation = False

    def validate_composition(self, *args, **kwargs):
        self.validate_group_orders()
        self.validate_secrets_reoccurence()

    def recompute_commitment(self, challenge, andresp):
        """
        Recomputes the commitment consistent with the given challenge and response, as a list of
        commitments of the subproofs.
        :param challenge: The challenge to use in the proof
        :param andresp: A list of responses (themselves being lists), ordered as the list of subproofs.
        """
        comm = []
        for i in range(len(self.subproofs)):
            cur_proof = self.subproofs[i]
            comm.append(cur_proof.recompute_commitment(challenge, andresp[i]))
        return comm

    def get_prover(self, secrets_dict=None):
        """
        Constructs a Prover for the and-proof, which is a list of the Provers related to each subproof, in order.
        If any of the collected Provers is invalid (None), returns None.
        """
        if secrets_dict is None:
            secrets_dict = {}

        # First we update the dictionary we have with the additional secrets, and process it
        update_secret_values(secrets_dict)

        if self.simulation == True:
            return None

        subs = [sub_proof.get_prover(secrets_dict) for sub_proof in self.subproofs]

        if None in subs:
            # TODO: It'd be great if we can get rid of the Nones, so we know which
            # sub proofs are failing
            print(subs)
            raise Exception("Failed to construct prover for a conjunct")

        return AndProver(self, subs)

    def get_verifier(self):
        """
        Constructs a Verifier for the and-proof, based on a list of the Verifiers of each subproof.
        """
        return AndVerifier(self, [subp.get_verifier() for subp in self.subproofs])

    def get_randomizers(self):
        """
        Create a dictionary of randomizers by querying the subproofs' maps and merging them.
        """
        random_vals = {}

        # Pair each Secret to one generator. Overwrites when a Secret re-occurs but since the
        # associated bases should yield groups of same order, it's fine.
        dict_name_gen = {s: g for s, g in zip(self.get_secret_vars(), self.get_bases())}

        # Pair each Secret to a randomizer.
        for u in dict_name_gen:
            random_vals[u] = dict_name_gen[u].group.order().random()

        return random_vals

    def prepare_simulate_proof(self):
        for subp in self.subproofs:
            subp.prepare_simulate_proof()

    def simulate_proof(self, responses_dict=None, challenge=None):
        """
        Simulate the And proof

        To do so, draw a global challenge, a global dictionary of responses (for consistency) and
        simulate each subproof.

        Gathers the commitments, and pack everything into a :py:class:`base.SimulationTranscript`.

        Args:
            responses_dict: A dictionary of responses to override (could come from an upper And
                Proof, for example). Draw randomly if None.
            challenge: The challenge to use in the proof. Draw one if None.
        """
        # Fill the missing positions of the responses dictionary
        responses_dict = self.update_randomizers(responses_dict)

        if challenge is None:
            challenge = get_random_num(CHALLENGE_LENGTH)
        com = []
        resp = []
        precom = []

        # Simulate all subproofs and gather their attributes, repack them in a unique
        # SimulationTranscript.
        for subp in self.subproofs:
            simulation = subp.simulate_proof(responses_dict, challenge)
            com.append(simulation.commitment)
            resp.append(simulation.responses)
            precom.append(simulation.precommitment)

        return SimulationTranscript(
            commitment=com, challenge=challenge, responses=resp, precommitment=precom
        )

    def validate_secrets_reoccurence(self, forbidden_secrets=None):
        """
        Check re-occuring secrets both inside and outside an or-proof.

        This method gets the list of all secrets in the tree and triggers a depth-first search for
        or-proofs

        Args:
            forbidden_secrets: A list of all the secrets in the mother proof.

        Raises:

        """
        if forbidden_secrets is None:
            forbidden_secrets = self.get_secret_vars().copy()
        for p in self.subproofs:
            p.validate_secrets_reoccurence(forbidden_secrets)


class AndProver(Prover):
    def __init__(self, proof, subprovers):
        """
        Constructs a Prover for an and-proof, from a list of valid subprovers.
        """
        self.subs = subprovers
        self.stmt = proof

    def precommit(self):
        """
        Computes the precommitment for an and-proof, i.e a list of the precommitments of the subprovers.
        If not applicable (not subprover outputs a precommitment), returns None.
        """
        precommitment = []
        for idx in range(len(self.subs)):

            # Collects precommitments one by one
            subprecom = self.subs[idx].precommit()
            if subprecom is not None:
                if len(precommitment) == 0:
                    precommitment = [None] * len(self.subs)
                precommitment[idx] = subprecom

        # If any precommitment is valid, return the list. If all were None, return None.
        return precommitment if len(precommitment) != 0 else None

    def internal_commit(self, randomizers_dict=None):
        """
        Computes the commitment.

        Args:
            randomizers_dict: Randomizers.
        """
        # Now that we have constructed the proofs, validate
        self.stmt.validate_composition()

        randomizers_dict = self.stmt.update_randomizers(randomizers_dict)
        self.commitment = []
        for subp in self.subs:
            self.commitment.append(
                subp.internal_commit(randomizers_dict=randomizers_dict)
            )
        return self.commitment

    def compute_response(self, challenge):
        """
        Returns a list of the responses of each subprover.
        """
        return [subp.compute_response(challenge) for subp in self.subs]


class AndVerifier(Verifier):
    def __init__(self, proof, subverifiers):
        """
        Constructs a Verifier for the and-proof, with a list of subverifiers.
        """
        self.subs = subverifiers
        self.stmt = proof

    def send_challenge(self, commitment, ignore_statement_hash_checks=False):
        """
        Stores the received commitment and generates a challenge. Checks the received hashed
        statement matches the one of the current proof.  Only called at the highest level or in
        embedded proofs working with precommitments.

        Args:
            commitment: A tuple (statement, actual_commitment) with actual_commitment a list of commitments, one for each subproof.
            ignore_statement_hash_checks: Optional parameter to deactivate the statement check. In this case, the commitment
                parameter is simply the actual commitment. Useful in 2-level proofs for which we don't
                check the inner statements.
        """
        if ignore_statement_hash_checks:
            self.commitment = commitment
        else:
            statement, self.commitment = commitment
            self.stmt.check_statement(statement)
        self.challenge = get_random_num(CHALLENGE_LENGTH)
        return self.challenge

    def check_responses_consistency(self, responses, responses_dict=None):
        """
        Checks the responses are consistent for reoccurring secret names.
        Iterates through the subverifiers, gives them the responses related to them and constructs a response dictionary (with respect to secret names).
        If an inconsistency if found during this build, an error code is returned.
        :param responses: The received list of responses for each subproof.
        :param responses_dict: The dictionary to construct and use for comparison.
        """
        if responses_dict is None:
            responses_dict = {}

        for i in range(len(self.subs)):
            if not self.subs[i].check_responses_consistency(
                responses[i], responses_dict
            ):
                return False
        return True

    def process_precommitment(self, precommitment):
        """
        Receives a list of precommitments for the subproofs (or None) and distributes them to the subverifiers.
        """
        if precommitment is None:
            return
        for idx in range(len(self.subs)):
            self.subs[idx].process_precommitment(precommitment[idx])
