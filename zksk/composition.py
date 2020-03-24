"""
Composable proof statements, provers, and verifiers.
"""

import abc
import copy
import random
from hashlib import sha256
from collections import defaultdict

from petlib.bn import Bn
from petlib.pack import encode

from zksk.consts import CHALLENGE_LENGTH
from zksk.base import Prover, Verifier, SimulationTranscript
from zksk.expr import Secret, update_secret_values
from zksk.utils import get_random_num, sum_bn_array
from zksk.utils.misc import get_default_attr
from zksk.exceptions import StatementSpecError, StatementMismatch
from zksk.exceptions import InvalidSecretsError, GroupMismatchError
from zksk.exceptions import InconsistentChallengeError


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


def _assign_secret_ids(secret_vars):
    """
    Assign consecutive identifiers to secrets.

    Needed for proof statement idenfifiers.

    >>> x, y = Secret(name='x'), Secret(name='y')
    >>> _assign_secret_ids([x, y, x])
    {'x': 0, 'y': 1}

    Args:
        secret_vars: :py:class:`expr.Secret` objects.
    """
    secret_id_map = {}
    counter = 0
    for secret in secret_vars:
        if secret.name not in secret_id_map:
            secret_id_map[secret.name] = counter
            counter += 1
    return secret_id_map


class ComposableProofStmt(metaclass=abc.ABCMeta):
    """
    A composable sigma-protocol proof statement.

    In the composed proof tree, these objects are the atoms/leafs.
    """

    def get_proof_id(self, secret_id_map=None):
        """
        Identifier for the proof statement.

        This identifier is used to check the proof statements on the prover and
        verifier sides are consistent, and to generate a challenge in non-interactive proofs.

        Args:
            secret_id_map: A map from secret names to consecutive identifiers.

        Returns:
            list: Objects that can be used for hashing.
        """
        secret_vars = self.get_secret_vars()
        bases = self.get_bases()
        if secret_id_map is None:
            secret_id_map = _assign_secret_ids(secret_vars)
        ordered_secret_ids = [secret_id_map[s.name] for s in secret_vars]
        return [self.__class__.__name__, bases, ordered_secret_ids]

    def get_secret_vars(self):
        """
        Collect all secrets in this subtree.

        By default tries to get the ``secret_vars`` attribute. Override if needed.
        """
        if not hasattr(self, "secret_vars"):
            raise StatementSpecError(
                "Need to override get_secret_vars or specify secret_vars attribute."
            )
        return self.secret_vars

    def get_bases(self):
        """
        Collect all base points in this subtree.

        By default tries to get the ``bases`` attribute. Override if needed.
        """
        if not hasattr(self, "bases"):
            raise StatementSpecError(
                "Need to override get_bases or specify bases attribute."
            )
        return self.bases

    def __and__(self, other):
        """
        Make a conjuction of proof statements using :py:class:`AndProofStmt`.

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
        Make a disjunction of proof statements using :py:class:`OrProofStmt`.

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
        Get the :py:class:`base.Prover` for the current proof.
        """
        return self.get_prover_cls()(self)

    def get_verifier(self):
        """
        Return the :py:class:`base.Verifier` for the current proof.
        """
        return self.get_verifier_cls()(self)

    def recompute_commitment(self, challenge, response):
        """
        Compute a pseudo-commitment.

        A pseudo-commitment is the commitment a verifier should have received if the proof was
        correct. It should be compared to the actual commitment.

        Re-occuring secrets yield identical responses.

        Args:
            challenge: the challenge used in the proof
            response: a list of responses, ordered as the list of secret names, i.e., with as many
                elements as there are secrets in the proof claim.
        """
        pass

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

        For example, a :py:class:`primitives.DLNotEqual` statement should
        not validate if its proof components are in fact equal.

        Should raise an `exceptions.ValidationError` if does not validate.
        """
        pass

    def full_validate(self, *args, **kwargs):
        """
        For or/and-proofs, perform recursive validation of subproofs.
        """
        # TODO: calling return here is deceptive if we ask to throw an Exception
        return self.validate(*args, **kwargs)

    def validate_secrets_reoccurence(self, forbidden_secrets=None):
        """
        Check if a secret appears both inside an outside an or-proof.

        Does nothing if not overriden.
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

        # TODO: This can be done easier.

        # Fill the dictionary.
        elif any([x not in randomizers_dict for x in self.get_secret_vars()]):
            tmp = self.get_randomizers()
            tmp.update(randomizers_dict)
            randomizers_dict = tmp

        return randomizers_dict

    def prehash_statement(self):
        """
        Return a hash of the proof's ID.
        """
        return sha256(encode(str(self.get_proof_id())))

    @property
    def simulated(self):
        """
        Tell if this proof is designated as to be simulated in an or-proof.

        By default is False.
        """
        return get_default_attr(self, "_simulated", False)

    def set_simulated(self, value=True):
        """
        Designate this proof statement as simulated in an or-proof.

        Args:
            value (bool): Whether to simulate this proof.
        """
        self._simulated = value

    def prepare_simulate_proof(self):
        """
        Additional steps to prepare before simulating the proof. Override if needed.
        """
        pass

    def simulate(self, challenge=None):
        """
        Generate the transcript of a simulated non-interactive proof.
        """
        self.set_simulated()
        self.prepare_simulate_proof()
        transcript = self.simulate_proof(challenge=challenge)
        transcript.stmt_hash = self.prehash_statement().digest()
        return transcript

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
        # TODO: Not a great repr (cannot copy-paste and thus recreate the object).
        return str(self.get_proof_id())


class _CommonComposedStmtMixin:
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

        The primary goal is to ensure same responses for same secrets will not yield false negatives
        of :py:meth:`base.Verifier.check_responses_consistency` due to different group-order modular
        reductions.

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
        for index, word in enumerate(secrets):
            mydict[word].append(index)

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

    def get_proof_id(self, secret_id_map=None):
        secret_vars = self.get_secret_vars()
        bases = self.get_bases()
        if secret_id_map is None:
            secret_id_map = _assign_secret_ids(secret_vars)

        proof_ids = [sub.get_proof_id(secret_id_map) for sub in self.subproofs]
        return (self.__class__.__name__, proof_ids)

    def full_validate(self, *args, **kwargs):
        for sub in self.subproofs:
            sub.full_validate(*args, **kwargs)


class OrProofStmt(_CommonComposedStmtMixin, ComposableProofStmt):
    """
    An disjunction of several subproofs.


    Args:
        suproofs: Proof statements.

    Raise:
        ValueError: If less than two subproofs given.
    """

    def __init__(self, *subproofs):
        if len(subproofs) < 2:
            raise ValueError("Need at least two subproofs")

        # We make a shallow copy of each subproof so they don't mess up each other.  This step is
        # important, as we can have different outputs for the same proof (independent simulations or
        # simulations/execution)
        self.subproofs = [copy.copy(p) for p in list(subproofs)]

    def recompute_commitment(self, challenge, responses):
        # We retrieve the challenges, hidden in the responses tuple
        self.or_challenges = responses[0]
        responses = responses[1]

        # We check for challenge consistency i.e the constraint was respected
        if _find_residual_challenge(
            self.or_challenges, challenge, CHALLENGE_LENGTH
        ) != Bn(0):
            raise InconsistentChallengeError("Inconsistent challenges.")

        # Compute the list of commitments, one for each proof with its challenge and responses
        # (in-order)
        com = []
        for index, subproof in enumerate(self.subproofs):
            com.append(
                subproof.recompute_commitment(
                    self.or_challenges[index], responses[index]
                )
            )
        return com

    def get_prover(self, secrets_dict=None):
        if secrets_dict is None:
            secrets_dict = {}

        # The prover is built on one legit prover constructed from a subproof picked at random among
        # candidates.
        # First we update the dictionary we have with the additional secrets, and process it
        # TODO: Check this secret_values handling totally different
        update_secret_values(secrets_dict)

        if self.simulated:
            return None

        # TODO: Add a unit test where simulation must be True/False for all subproofs

        # Prepare the draw. Disqualify proofs with simulation parameter set to true
        candidates = {}
        for index, subproof in enumerate(self.subproofs):
            if not self.subproofs[index].simulated:
                candidates[index] = subproof

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
        return OrVerifier(self, [sub.get_verifier() for sub in self.subproofs])

    def validate_composition(self):
        """
        Validate that composition is done correctly.
        """
        self.validate_group_orders()

    def validate_secrets_reoccurence(self, forbidden_secrets=None):
        """
        Check for re-occurence of secrets both inside and outside an or-proof.

        Method is called from :py:meth:`AndProofStmt.validate_secrets_reoccurence`.

        Args:
            forbidden_secrets: A list of all the secrets in the mother proof.

        Raises:
            :py:class:`exceptions.InvalidSecretsError`: If any secrets re-occur in an
                unsupported way.
        """
        secret_vars = self.get_secret_vars()
        if forbidden_secrets is None:
            return

        for secret in set(secret_vars):
            if forbidden_secrets.count(secret) > secret_vars.count(secret):
                raise InvalidSecretsError(
                    "Invalid secrets found. Try to flatten the proof to avoid "
                    "using secrets used inside an or-proof in other parts of "
                    "the proof too (e.g., in other and or or-clauses)"
                )

    def prepare_simulate_proof(self):
        for sub in self.subproofs:
            sub.prepare_simulate_proof()

    def simulate_proof(self, challenge=None, *args, **kwargs):
        # Simulate the n-1 first subproofs, computes the complementary challenge and
        # simulates the last proof using this challenge.
        if challenge is None:
            challenge = get_random_num(bits=CHALLENGE_LENGTH)
        com = []
        resp = []
        or_chals = []
        precom = []

        # Generate one simulation at a time and update a list of each attribute.
        for index, subproof in enumerate(self.subproofs[:-1]):
            transcript = subproof.simulate_proof()
            com.append(transcript.commitment)
            resp.append(transcript.responses)
            or_chals.append(transcript.challenge)
            precom.append(transcript.precommitment)

        # Generate the last simulation.
        final_chal = _find_residual_challenge(or_chals, challenge, CHALLENGE_LENGTH)
        or_chals.append(final_chal)
        final_transcript = self.subproofs[index + 1].simulate_proof(
            challenge=final_chal
        )
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
    Prover for the or-proof.

    This prover is built with only one subprover, and needs to have access to the index of the
    corresponding subproof in its mother proof. Runs all the simulations for the other proofs and
    stores them.
    """

    def __init__(self, stmt, subprover):
        self.subprover = subprover
        self.stmt = stmt
        self.true_prover_idx = self.stmt.chosen_idx

        # Create a list storing the SimulationTranscripts
        self.setup_simulations()

    def setup_simulations(self):
        """
        Run all the required simulations and stores them.
        """
        self.simulations = []
        for index, subproof in enumerate(self.stmt.subproofs):
            if index != self.true_prover_idx:
                subproof.prepare_simulate_proof()
                sim = subproof.simulate_proof()
                self.simulations.append(sim)

    def precommit(self):
        # Generate precommitment for the legit subprover, and gather the precommitments from the
        # stored simulations.
        precommitment = []
        for index, _ in enumerate(self.stmt.subproofs):
            if index == self.true_prover_idx:
                precommitment.append(self.subprover.precommit())
            else:
                if index > self.true_prover_idx:
                    index1 = index - 1
                else:
                    index1 = index
                precommitment.append(self.simulations[index1].precommitment)
        if not any(precommitment):
            return None
        return precommitment

    def internal_commit(self, randomizers_dict=None):
        """
        Gather the commitments from the stored simulations.

        Args:
            randomizers_dict: A dictionary of randomizers to use for responses consistency. Not used
                in this proof. Parameter kept so all internal_commit methods have the same prototype.
        """
        # Now that all proofs have been constructed, we can check
        self.stmt.validate_composition()

        commitment = []
        for index, _ in enumerate(self.stmt.subproofs):
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
        Compute complementary challenges and responses.

        Computes the complementary challenge with respect to the received global challenge and the
        list of challenges used in the stored simulations.  Computes the responses of the subprover
        using this auxiliary challenge, gathers the responses from the stored simulations.  Returns
        both the complete list of subchallenges (including the auxiliary challenge) and the list of
        responses, both ordered.

        Args:
            challenge: The global challenge to use. All subchallenges must add to this one.
        """
        residual_chal = _find_residual_challenge(
            [el.challenge for el in self.simulations], challenge, CHALLENGE_LENGTH
        )
        response = []
        challenges = []
        for index, subproof in enumerate(self.stmt.subproofs):
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

        return (challenges, response)


class OrVerifier(Verifier):
    """
    Verifier for the or-proof.

    The verifier is built on a list of subverifiers, which will unpack the received attributes.
    """

    def __init__(self, stmt, subverifiers):
        self.subs = subverifiers
        self.stmt = stmt

    def process_precommitment(self, precommitment):
        """
        Reads the received list of precommitments (or None if non applicable) and distributes them
        to the subverifiers so they can finalize their proof construction if necessary.

        Args:
            precommitment: A list of all required precommitments, ordered.
        """
        if precommitment is None:
            return
        for index, sub in enumerate(self.subs):
            sub.process_precommitment(precommitment[index])

    def check_responses_consistency(self, responses, responses_dict=None):
        """
        Checks that for a same secret, response are actually the same.

        Since every member is run with its own challenge, it is enough that one
        member is consistent within itself.

        Args:
            responses: a tuple (subchallenges, actual_responses) from which we extract only the
                actual responses for each subverifier.
        """
        if responses_dict is None:
            responses_dict = {}
        for index, sub in enumerate(self.subs):
            if not sub.check_responses_consistency(responses[1][index], {}):
                return False
        return True


class AndProofStmt(_CommonComposedStmtMixin, ComposableProofStmt):
    def __init__(self, *subproofs):
        """
        Constructs the And conjunction of several subproofs.
        Subproofs are copied at instantiation.

        Args:
            suproofs: Proof statements.

        Raise:
            ValueError: If less than two subproofs given.
        """
        if len(subproofs) < 2:
            raise ValueError("Need at least two subproofs")

        # We make a shallow copy of each subproof so they dont mess with each other.  This step is
        # important in case we have proofs which locally draw random values.  It ensures several
        # occurrences of the same proof in the tree indeed have their own randomnesses.
        self.subproofs = [copy.copy(p) for p in list(subproofs)]

    def validate_composition(self, *args, **kwargs):
        """
        Validate that composition is done correctly.
        """
        self.validate_group_orders()
        self.validate_secrets_reoccurence()

    def recompute_commitment(self, challenge, responses):
        com = []
        for index, subproof in enumerate(self.subproofs):
            com.append(subproof.recompute_commitment(challenge, responses[index]))
        return com

    def get_prover(self, secrets_dict=None):
        if secrets_dict is None:
            secrets_dict = {}

        # First we update the dictionary we have with the additional secrets, and process it
        update_secret_values(secrets_dict)

        if self.simulated:
            return None

        subs = [sub_proof.get_prover(secrets_dict) for sub_proof in self.subproofs]

        if None in subs:
            # TODO: It'd be great to know which one is failing.
            raise ValueError("Failed to construct prover for a conjunct")

        return AndProver(self, subs)

    def get_verifier(self):
        """
        Constructs a Verifier for the and-proof, based on a list of the Verifiers of each subproof.
        """
        return AndVerifier(self, [sub.get_verifier() for sub in self.subproofs])

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
        for sub in self.subproofs:
            sub.prepare_simulate_proof()

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
        for sub in self.subproofs:
            simulation = sub.simulate_proof(
                challenge=challenge, responses_dict=responses_dict
            )
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
            :py:class:`exceptions.InvalidSecretsError`: If any secrets re-occur in an
                unsupported way.
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
        Computes the precommitment for an and-proof.

        This precommitment is the list of precommitments of the subprovers.

        If not applicable (no subprover outputs a precommitment), returns None.
        """
        precommitment = []
        for index, sub in enumerate(self.subs):
            # Collect precommitments one by one
            sub_precommitment = sub.precommit()
            if sub_precommitment is not None:
                if len(precommitment) == 0:
                    precommitment = [None] * len(self.subs)
                precommitment[index] = sub_precommitment

        # If any precommitment is valid, return the list. If all were None, return None.
        return precommitment if len(precommitment) != 0 else None

    def internal_commit(self, randomizers_dict=None):
        """
        Compute the internal commitment.

        Args:
            randomizers_dict: Mapping from secrets to randomizers.
        """
        # Now that we have constructed the proofs, validate.
        self.stmt.validate_composition()

        randomizers_dict = self.stmt.update_randomizers(randomizers_dict)
        self.commitment = []
        for sub in self.subs:
            self.commitment.append(
                sub.internal_commit(randomizers_dict=randomizers_dict)
            )
        return self.commitment

    def compute_response(self, challenge):
        """
        Return a list of responses of each subprover.
        """
        return [sub.compute_response(challenge) for sub in self.subs]


class AndVerifier(Verifier):
    def __init__(self, proof, subverifiers):
        self.subs = subverifiers
        self.stmt = proof

    def send_challenge(self, commitment, ignore_statement_hash_checks=False):
        """
        Store the received commitment and generate a challenge.

        Additionally checks the received hashed statement matches the one of the current proof. Only
        called at the highest level or in extended proofs.

        Args:
            commitment: A tuple (statement, actual_commitment) with
                actual_commitment a list of commitments, one for each subproof.
            ignore_statement_hash_checks: Optional parameter to deactivate the
                statement check. In this case, the commitment parameter is
                simply the actual commitment. Useful in 2-level proofs for which
                we don't check the inner statements.
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
        Check that the responses are consistent for re-occurring secret names.

        Iterates through the subverifiers, gives them the responses related to
        them and constructs a response dictionary.  If an inconsistency if found
        during this build, returns False.

        Args:
            responses: Rreceived list of responses for each subproof.
            responses_dict: Dictionary to construct and use for comparison.
        """
        if responses_dict is None:
            responses_dict = {}

        for index, sub in enumerate(self.subs):
            if not sub.check_responses_consistency(responses[index], responses_dict):
                return False
        return True

    def process_precommitment(self, precommitment):
        """
        Distribute the list of precommitments to the subverifiers.
        """
        if precommitment is None:
            return
        for index, sub in enumerate(self.subs):
            sub.process_precommitment(precommitment[index])
