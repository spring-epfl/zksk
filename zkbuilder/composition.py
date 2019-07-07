from zkbuilder.base import *
from zkbuilder.utils import check_groups

import copy


class Proof:
    """A composable sigma-protocol proof statement."""

    def __and__(self, other):
        """
        Returns an AndProof from this proof and the other proof using the infix '&' operator.
        If called again, subproofs are merged so only one AndProof remains in the end.
        """
        if isinstance(other, AndProof):
            if isinstance(self, AndProof):
                return AndProof(*self.subproofs, *other.subproofs)
            else:
                return AndProof(self, *other.subproofs)
        elif isinstance(self, AndProof):
            return AndProof(*self.subproofs, other)
        return AndProof(self, other)

    def __or__(self, other):
        """
        :return: an OrProof from this proof and the other proof using the infix '|' operator.
        If called again, subproofs are merged so only one OrProof remains in the end.
        """
        if isinstance(other, OrProof):
            if isinstance(self, OrProof):
                return OrProof(*self.subproofs, *other.subproofs)
            else:
                return OrProof(self, *other.subproofs)
        elif isinstance(self, OrProof):
            return OrProof(*self.subproofs, other)
        return OrProof(self, other)

    def get_prover_cls(self):
        if hasattr(self, "prover_cls"):
            return self.prover_cls
        else:
            raise ValueError("No prover class specified.")

    def get_verifier_cls(self):
        if hasattr(self, "verifier_cls"):
            return self.verifier_cls
        else:
            raise ValueError("No verifier class specified.")

    def get_prover(self, secrets_dict=None):
        """
        Returns a :py:class:`Prover` object for the current proof.
        """
        return self.get_prover_cls()(self)

    def get_verifier(self):
        """
        Returns a :py:class:`Verifier` object for the current proof.
        """
        return self.get_verifier_cls()(self)

    def recompute_commitment(self, challenge, response):
        """
        Computes a pseudo-commitment: the commitment you should have received
        if the proof was correct. It should be compared to the actual commitment.

        Reoccuring secrets yield identical responses.

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
        return prover.get_NI_proof(message)

    def verify(self, transcript, message=""):
        """
        Verify the transcript of a non-interactive proof.
        """
        verifier = self.get_verifier()
        return verifier.verify_NI(transcript, message)

    def simulate(self, challenge=None):
        """
        Generate the transcript of a simulated non-interactive proof.
        """
        self.set_simulate()
        transcript = self.simulate_proof(challenge=challenge)
        transcript.statement = self.prehash_statement().digest()
        return transcript

    def check_statement(self, statement):
        """
        Verify the current proof corresponds to the hash passed as a parameter.
        Returns a pre-hash of the current proof, e.g., to be used to verify NI proofs
        """
        cur_statement = self.prehash_statement()
        if statement != cur_statement.digest():
            raise StatementMismatch("Proof statements mismatch, impossible to verify")
        return cur_statement

    def check_adequate_lhs(self):
        """
        Optional verification criteria to be checked at verification step. Returns True by default, to be overriden if necessary.
        """
        return True

    def check_or_flaw(self, forbidden_secrets=None):
        """
        Check if a secret appears both inside an outside an Or Proof. Does nothing if not overriden.
        """
        pass

    def update_randomizers(self, randomizers_dict):
        """
        Constructs a full dictionary of randomizers (also used as responses in simulations) by copying the values of the dict passed as parameter,
        and drawing the other values at random until all the secrets have a randomizer.
        :param randomizers_dict: A dictionary to enforce
        """
        # If we are not provided a randomizer dict from above, we compute it.
        if randomizers_dict is None:
            randomizers_dict = self.get_randomizers()
        # If we were passed an incomplete dictionary, fill it
        elif any([x not in randomizers_dict for x in self.secret_vars]):
            tmp = self.get_randomizers()
            tmp.update(randomizers_dict)
            randomizers_dict = tmp
        return randomizers_dict

    def ec_encode(self, data):
        """
        Figures out which encoder to use in the petlib.pack function encode() and uses it.
        Can break if both petlib.ec.EcPt points and custom BilinearPairings points are used in the same proof.
        """
        if not isinstance(self.generators[0], EcPt):
            encoding = enc_GXpt
        else:
            encoding = None
        return encode(data, custom_encoder=encoding)

    def prehash_statement(self, other=None):
        """
        Returns a hash of the proof's descriptor.
        Since for now proofs mixing EcPt and G1Pt are not supported, we typecheck to encode with the petlib.pack function.
        :arg other: An optional other object to pack, e.g a commitment (for non-interactive proofs). Avoids having to figure out the encoding mode multiple times.
        """
        ppp = sha256(self.ec_encode(self.get_proof_id()))
        return ppp

    def verify_simulation_consistency(self, transcript):
        """
        Tool function useful for debugging. Checks if a the fields of a transcript satisfy the verification equation.
        Should NOT be used instead of proof.verify() since it would accept simulations !
        """
        verifier = self.get_verifier()
        verifier.process_precommitment(transcript.precommitment)
        self.check_statement(transcript.statement)
        verifier.commitment, verifier.challenge = (
            transcript.commitment,
            transcript.challenge,
        )
        return verifier.verify(transcript.responses)

    def __repr__(self):
        return "\n" + str(self.get_proof_id())


class BaseProof(Proof):
    """
    A framework for Proofs dealing with precommitments.
    One needs to initalize self.ProverClass and self.VerifierClass in the init.
    The idea is to draw a Prover capable of generating a precommitment, and use it to construct a legit constructed proof.
    """

    def get_prover(self, secrets_dict={}):
        # Construct a dictionary with the secret values we already know
        self.secret_values = {}
        for sec in self.secret_vars:
            if sec.value is not None:
                self.secret_values[sec] = sec.value
        # First we update the dictionary we have with the additional secrets, and process it
        self.secret_values.update(secrets_dict)
        if (
            self.simulation
            or self.secret_values == {}
            or any(
                sec not in self.secret_values.keys() for sec in set(self.secret_vars)
            )
        ):
            # TODO: not sure None is the right output here
            return None

        return self.ProverClass(self, self.secret_values)

    def get_verifier(self):
        return self.VerifierClass(self)

    def recompute_commitment(self, challenge, responses):
        """
        Recomputes the commitment.
        """
        return self.constructed_proof.recompute_commitment(challenge, responses)

    def get_proof_id(self):
        """
        Packs the proof statement as the proof name, the list of generators and the precommitment.
        """
        if self.constructed_proof is not None:
            st = [
                self.__class__.__name__,
                self.precommitment,
                self.constructed_proof.get_proof_id(),
            ]
        else:
            st = [self.__class__.__name__, self.generators]
        return st

    def simulate_proof(self, responses_dict=None, challenge=None):
        """
        Simulates the BaseProof.
        Assumes all precommitment elements are in the same group, and that the number of such elements is known in advance.
        """
        group = self.generators[0].group
        precommitment = self.simulate_precommitment()
        self.build_constructed_proof(precommitment)
        tr = self.constructed_proof.simulate_proof(responses_dict, challenge)
        tr.precommitment = precommitment
        return tr

    def simulate_precommitment(self):
        """
        Simulates a precommitment, returned as a list. Should be overriden when using simulations/Or Proof.
        """
        raise Exception("Override BaseProof.simulate_precommitment() in order to use Or Proof and simulations")


class BaseProver(Prover):
    """
    A framework for Provers dealing with precommitments. The Prover will create a constructed Prover and wrap its methods.
    """

    def internal_commit(self, randomizers_dict=None):
        """
        Triggers the inside prover commit. Transfers the randomizer dict coming from above, which will be
        used if the binding of the proof is set True.
        """
        if self.proof.constructed_proof is None:
            raise Exception(
                "Please precommit before commiting, else proofs lack parameters"
            )
        return self.constructed_prover.internal_commit(randomizers_dict)

    def compute_response(self, challenge):
        """
        Wraps the response computation for the inner proof.
        """
        self.challenge = challenge
        self.constructed_prover.challenge = challenge
        self.response = self.constructed_prover.compute_response(challenge)
        return self.response

    def precommit(self):
        self.precommitment = self.internal_precommit()
        self.process_precommitment()
        return self.precommitment

    def internal_precommit(self):
        """Computes precommitments and additional secrets for proof

        Override this function to compute precommitments and corresponding
        secrets that must be computed before the ZK proof itself can be
        constructed and proven.

        Returns:
            precommitment: The precommitment
            constructed_secrets: New secrets used in the proof
        """
        return [], []

    def process_precommitment(self):
        """
        Triggers the inner proof construction and extracts a prover from it given the secrets.
        """
        self.proof.build_constructed_proof(self.precommitment)
        self.constructed_prover = self.proof.constructed_proof.get_prover(
            self.secret_values
        )


class BaseVerifier(Verifier):
    """
    A framework for Verifiers dealing with precommitments.
    """

    def process_precommitment(self, precommitment):
        """
        Receives the precommitment and triggers the inner proof construction.
        """
        self.precommitment = precommitment
        self.proof.build_constructed_proof(precommitment)
        self.constructed_verifier = self.proof.constructed_proof.get_verifier()

    def send_challenge(self, com):
        """
        Checks the received statement and transfers the commitment to the inner proof, without making it check any statement.
        """
        statement, self.commitment = com
        self.proof.check_statement(statement)
        self.challenge = self.constructed_verifier.send_challenge(
            self.commitment, mute=True
        )
        return self.challenge

    def check_responses_consistency(self, response, response_dict):
        """
        Wraps the inner proof responses consistency check.
        """
        return self.constructed_verifier.check_responses_consistency(
            response, response_dict
        )


class OrProof(Proof):
    def __init__(self, *subproofs):
        """
        Constructs the Or conjunction of several subproofs.
        Subproofs are copied at instantiation.
        :param subproofs: An arbitrary number of proofs.
        """
        if len(subproofs) < 2:
            raise Exception("OrProof needs >1 arguments !")
        # We will make a shallow copy of each subproof so they dont mess up with each other.
        # This step is important in Or Proof since we can have different outputs for a same proof (independent simulations or simulations/execution)
        self.subproofs = [copy.copy(p) for p in list(subproofs)]

        self.generators = get_generators(self.subproofs)
        self.secret_vars = get_secret_vars(self.subproofs)
        # Construct a dictionary with the secret values we already know
        self.secret_values = {}
        for sec in self.secret_vars:
            if sec.value is not None:
                self.secret_values[sec] = sec.value
        self.simulation = False
        check_groups(self.secret_vars, self.generators)
        # For now we consider the same constraints as in the And Proof

    def get_proof_id(self):
        return ["Or", [sub.get_proof_id() for sub in self.subproofs]]

    def recompute_commitment(self, challenge, responses):
        """
        Recomputes the commitments, raises an Exception if the global challenge was not respected.
        :param challenge: The global challenge sent by the verifier.
        :param responses: A tuple (subchallenges, actual_responses) containing the subchallenges
        each proof used (ordered list), and a list of responses (also ordered)
        """
        # We retrieve the challenges, hidden in the responses tuple
        self.or_challenges = responses[0]
        responses = responses[1]
        comm = []
        # We check for challenge consistency i.e the constraint was respected
        if find_residual_chal(self.or_challenges, challenge, CHALLENGE_LENGTH) != Bn(0):
            raise Exception("Inconsistent challenge")
        # Compute the list of commitments, one for each proof with its challenge and responses (in-order)
        for i in range(len(self.subproofs)):
            cur_proof = self.subproofs[i]
            comm.append(
                cur_proof.recompute_commitment(self.or_challenges[i], responses[i])
            )
        return comm

    def get_prover(self, secrets_dict={}):
        """
        Gets an OrProver, which is built on one legit prover constructed from a
        subproof picked at random among all possible candidates.
        """

        # First we update the dictionary we have with the additional secrets, and process it
        self.secret_values.update(secrets_dict)
        secrets_dict = self.secret_values
        if self.simulation == True or secrets_dict == {}:
            return None

        # Prepare the draw. Disqualify proofs with simulation parameter set to true
        candidates = {}
        for idx in range(len(self.subproofs)):
            if not self.subproofs[idx].simulation:
                candidates[idx] = self.subproofs[idx]

        if len(candidates) == 0:
            print("Cannot run an Or Proof if all elements are simulated")
            return None

        # Now choose a proof among the possible ones and try to get a prover from it.
        # If for some reason it does not work (e.g some secrets are missing), remove it
        # from the list of possible proofs and try again
        rd = random.SystemRandom()
        # We would appreciate a do...while here >:(
        possible = list(candidates.keys())
        self.chosen_idx = rd.choice(possible)
        # Feed the selected proof the secrets it needs if we have them, and try to get_prover
        valid_prover = sub_proof_prover(self.subproofs[self.chosen_idx], secrets_dict)
        while valid_prover is None:
            possible.remove(self.chosen_idx)
            # If there is no proof left, abort and say we cannot get a prover
            if len(possible) == 0:
                self.chosen_idx = None
                return None
            self.chosen_idx = rd.choice(possible)
            valid_prover = sub_proof_prover(
                self.subproofs[self.chosen_idx], secrets_dict
            )
        return OrProver(self, valid_prover)

    def get_verifier(self):
        return OrVerifier(self, [subp.get_verifier() for subp in self.subproofs])

    def check_or_flaw(self, forbidden_secrets=None):
        """
        Checks for appearance of reoccuring secrets both inside and outside an Or Proof.
        Raises an error if finds any. Method called from AndProof.check_or_flaw
        :param forbidden_secrets: A list of all the secrets in the mother proof.
        """
        if forbidden_secrets is None:
            return
        for secret in set(self.secret_vars):
            if forbidden_secrets.count(secret) > self.secret_vars.count(secret):
                raise Exception(
                    "Or flaw detected. Aborting. Try to flatten the proof to  \
                avoid shared secrets inside and outside an Or"
                )

    def check_adequate_lhs(self):
        """
        Check that all the left-hand sides of the proofs have a coherent value.
        For instance, it will return False if a DLRepNotEqualProof is in the tree and
        if it is about to prove its components are in fact equal.
        This allows to not waste computation time in running useless verifications.
        """
        for sub in self.subproofs:
            if not sub.check_adequate_lhs():
                return False
        return True

    def simulate_proof(self, responses_dict=None, challenge=None):
        """
        Simulates an Or Proof. To do so, simulates the N-1 first subproofs, computes the complementary challenge
        and simulates the last proof using this challenge. Does not use the responses_dict passed as parameter since inside an Or Proof
        responses consistency is not required between subproofs.
        :param challenge: The global challenge, equal to the sum of all the subchallenges mod chal bitlength.
        :param responses_dict: A dictionary of responses to enforce for consistency. Useless hiere, kept to have the same prototype for all simulate_proof methods.
        """
        if challenge is None:
            challenge = chal_randbits(CHALLENGE_LENGTH)
        com = []
        resp = []
        or_chals = []
        precom = []
        # Generate one simulation at a time and update a list of each attribute
        for index in range(len(self.subproofs) - 1):
            transcript = self.subproofs[index].simulate_proof()
            com.append(transcript.commitment)
            resp.append(transcript.responses)
            or_chals.append(transcript.challenge)
            precom.append(transcript.precommitment)
        # Generate the last simulation
        final_chal = find_residual_chal(or_chals, challenge, CHALLENGE_LENGTH)
        or_chals.append(final_chal)
        trfinal = self.subproofs[index + 1].simulate_proof(challenge=final_chal)
        com.append(trfinal.commitment)
        resp.append(trfinal.responses)
        precom.append(trfinal.precommitment)
        # Pack everything into a SimulationTranscript, pack the or_challenges in the response field
        return SimulationTranscript(
                commitment=com, challenge=challenge, responses=(or_chals, resp), precommitment=precom)


class OrProver(Prover):
    def __init__(self, proof, subprover):
        """
        Constructs a Prover for the Or Proof. Is built with only one subprover, and needs to have access to the index of the corresponding subproof in its mother proof.
        Runs all the simulations for the other proofs and stores them.
        """
        self.subprover = subprover
        self.proof = proof
        self.true_prover_idx = self.proof.chosen_idx
        # Create a list to store the SimulationTranscripts
        self.simulations = []
        self.setup_simulations()

    def setup_simulations(self):
        """
        Runs all the required simulations and stores them.
        """
        for index in range(len(self.proof.subproofs)):
            if index != self.true_prover_idx:
                cur = self.proof.subproofs[index].simulate_proof()
                self.simulations.append(cur)

    def precommit(self):
        """
        Generates a precommitment for the legit subprover, and gathers the precommitments from the stored simulations.
        Outputs a list of the precommitments needed by the subproofs if any. Else, returns None.
        """
        precommitment = []
        for index in range(len(self.proof.subproofs)):
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
        Commits from the subprover, gathers the commitments from the stored simulations. Packs into a list.
        :param randomizers_dict: A dictionary of randomizers to use for responses consistency. Not used in this proof. Parameter kept so all internal_commit methods have the same prototype.
        """
        commitment = []
        for index in range(len(self.proof.subproofs)):
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
        Computes the complementary challenge with respect to the received global challenge and the list of challenges used in the stored simulations.
        Computes the responses of the subprover using this auxiliary challenge, gathers the responses from the stored simulations.
        Returns both the complete list of subchallenges (included the auxiliary challenge) and the list of responses, both ordered.
        :param challenge: The global challenge to use. All subchallenges must add to this one.
        """
        residual_chal = find_residual_chal(
            [el.challenge for el in self.simulations], challenge, CHALLENGE_LENGTH
        )
        response = []
        challenges = []
        for index in range(len(self.proof.subproofs)):
            if index == self.true_prover_idx:
                challenges.append(residual_chal)
                response.append(self.subprover.compute_response(residual_chal))
            else:
                # Note len(simulations) = len(subproofs) - 1 !
                if index > self.true_prover_idx:
                    index1 = index - 1
                else:
                    index1 = index
                challenges.append(self.simulations[index1].challenge)
                response.append(self.simulations[index1].responses)

        # We carry the or challenges in a tuple, will be unpacked by the verifier calling recompute_commitment
        return (challenges, response)


class OrVerifier(Verifier):
    def __init__(self, proof, subverifiers):
        """
        Constructs a Verifier for the Or Proof. Is built on a list of subverifiers, which will unpack the received attributes.
        """
        self.subs = subverifiers
        self.proof = proof

    def process_precommitment(self, precommitment):
        """
        Reads the received list of precommitments (or None if non applicable) and distributes them to the subverifiers so they can finalize their proof construction if necessary.
        :param precommitment: A list of all required precommitments, ordered.
        """
        if precommitment is None:
            return
        for idx in range(len(self.subs)):
            self.subs[idx].process_precommitment(precommitment[idx])

    def check_responses_consistency(self, responses, responses_dict={}):
        """
        Checks that for a same secret, response are actually the same.
        Since every member is run with its own challenge, it is enough that one member is consistent within itself.
        :param responses: a tuple (subchallenges, actual_responses) from which we extract only the actual responses for each subverifier.
        """
        for idx in range(len(self.subs)):
            if not self.subs[idx].check_responses_consistency(responses[1][idx], {}):
                return False
        return True


class AndProof(Proof):
    def __init__(self, *subproofs):
        """
        Constructs the And conjunction of several subproofs.
        Subproofs are copied at instantiation.
        :param subproofs: An arbitrary number of proofs.
        """
        if len(subproofs) < 2:
            raise Exception("AndProof needs >1 arguments !")

        # We will make a shallow copy of each subproof so they dont mess up with each other.
        # This step is important in case we have proofs which locally draw random values.
        # It ensures several occurrences of the same proof in the tree indeed have their own randomnesses

        self.subproofs = [copy.copy(p) for p in list(subproofs)]

        self.generators = get_generators(self.subproofs)
        self.secret_vars = get_secret_vars(self.subproofs)
        # Construct a dictionary with the secret values we already know
        self.secret_values = {}
        for sec in self.secret_vars:
            if sec.value is not None:
                self.secret_values[sec] = sec.value
        self.simulation = False
        # Check reoccuring secrets are related to generators of same group order
        check_groups(self.secret_vars, self.generators)
        # Raise an error when detecting a secret occuring both inside and outside an Or Proof
        self.check_or_flaw()

    def recompute_commitment(self, challenge, andresp):
        """
        Recomputes the commitment consistent with the given challenge and response, as a list of commitments of the subproofs.
        :param challenge: The challenge to use in the proof
        :param andresp: A list of responses (themselves being lists), ordered as the list of subproofs.
        """
        comm = []
        for i in range(len(self.subproofs)):
            cur_proof = self.subproofs[i]
            comm.append(cur_proof.recompute_commitment(challenge, andresp[i]))
        return comm

    def get_prover(self, secrets_dict={}):
        """
        Constructs a Prover for the And Proof, which is a list of the Provers related to each subproof, in order.
        If any of the collected Provers is invalid (None), returns None.
        """
        # First we update the dictionary we have with the additional secrets, and process it
        self.secret_values.update(secrets_dict)
        secrets_dict = self.secret_values
        if self.simulation == True or secrets_dict == {}:
            return None

        subs = [
            sub_proof_prover(sub_proof, secrets_dict) for sub_proof in self.subproofs
        ]
        if None in subs:
            # TODO: It'd be great if we can get rid of the Nones, so we know which
            # sub proofs are failing
            print(subs)
            return None
        return AndProver(self, subs)

    def get_verifier(self):
        """
        Constructs a Verifier for the And Proof, based on a list of the Verifiers of each subproof.
        """
        return AndVerifier(self, [subp.get_verifier() for subp in self.subproofs])

    def get_proof_id(self):
        return ["And", [sub.get_proof_id() for sub in self.subproofs]]

    def get_randomizers(self) -> dict:
        """
        Creates a dictionary of randomizers by querying the subproofs dicts and merging them
        """
        random_vals = {}
        # Pair each Secret to one generator. Overwrites when a Secret reoccurs but since the associated generators should yield groups of same order it's fine
        dict_name_gen = dict(zip(self.secret_vars, self.generators))
        # Pair each Secret to a randomizer
        for u in dict_name_gen:
            random_vals[u] = dict_name_gen[u].group.order().random()
        return random_vals

    def simulate_proof(self, responses_dict=None, challenge=None):
        """
        Simulates the And Proof, i.e draws a global challenge, a global dictionary of responses (for consistency) and simulates each subproof.
        Gathers the commitments, and pack everything into a unique SimulationTranscript
        :param responses_dict: A dictionary of responses to enforce (could come from an upper And Proof, for example). Draw one if None.
        :param challenge: The challenge to use in the proof. Draw one if None.
        """
        # Fill the missing positions of the responses dictionary
        responses_dict = self.update_randomizers(responses_dict)
        if challenge is None:
            challenge = chal_randbits(CHALLENGE_LENGTH)
        com = []
        resp = []
        precom = []
        # Simulate all subproofs and gather their attributes, repack them in a unique SimulationTranscript
        for subp in self.subproofs:
            simulation = subp.simulate_proof(responses_dict, challenge)
            com.append(simulation.commitment)
            resp.append(simulation.responses)
            precom.append(simulation.precommitment)
        return SimulationTranscript(commitment=com, challenge=challenge, responses=resp,
                precommitment=precom)

    def check_or_flaw(self, forbidden_secrets=None):
        """
        Checks for appearance of reoccuring secrets both inside and outside an Or Proof.
        Raises an error if finds any. This method only sets the list of all secrets in the tree and triggers a depth-search first for Or Proofs
        :param forbidden_secrets: A list of all the secrets in the mother proof.
        """
        if forbidden_secrets is None:
            forbidden_secrets = self.secret_vars.copy()
        for subp in self.subproofs:
            subp.check_or_flaw(forbidden_secrets)

    def check_adequate_lhs(self):
        """
        Check that all the left-hand sides of the proofs have a coherent value.
        For instance, it will return False if a DLRepNotEqualProof is in the tree and
        if it is about to prove its components are in fact equal.
        This allows to not waste computation time in running useless verifications.
        """
        for sub in self.subproofs:
            if not sub.check_adequate_lhs():
                return False
        return True


class AndProver(Prover):
    def __init__(self, proof, subprovers):
        """
        Constructs a Prover for an And Proof, from a list of valid subprovers.
        """
        self.subs = subprovers
        self.proof = proof

    def precommit(self):
        """
        Computes the precommitment for an And Proof, i.e a list of the precommitments of the subprovers.
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
        # If any precommitment is valid, return the list. If all were None, return None
        return precommitment if len(precommitment) != 0 else None

    def internal_commit(self, randomizers_dict=None):
        """
        Computes the commitment i.e a list of the commitments of the subprovers.
        :param randomizers_dict: Randomizers to enforce to ensure responses consistency, which every subproof must use.
        """
        # Fill the missing values if necessary
        randomizers_dict = self.proof.update_randomizers(randomizers_dict)
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
        Constructs a Verifier for the And Proof, with a list of subverifiers.
        """
        self.subs = subverifiers
        self.proof = proof

    def send_challenge(self, commitment, mute=False):
        """
        Stores the received commitment and generates a challenge. Checks the received hashed
        statement matches the one of the current proof.  Only called at the highest level or in
        embedded proofs working with precommitments.

        Args:
            commitment: A tuple (statement, actual_commitment) with actual_commitment a list of commitments, one for each subproof.
            mute: Optional parameter to deactivate the statement check. In this case, the commitment
                parameter is simply the actual commitment. Useful in 2-level proofs for which we don't
                check the inner statements.
        """
        if mute:
            self.commitment = commitment
        else:
            statement, self.commitment = commitment
            self.proof.check_statement(statement)
        self.challenge = chal_randbits(CHALLENGE_LENGTH)
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
