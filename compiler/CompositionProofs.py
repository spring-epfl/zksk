from Abstractions import *


class Proof:
    """An abstraction of a sigma protocol proof.
    Is in this file because of And/Or operations defined here.
    """

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

    def get_prover(self, secrets_dict={}):
        """
        Returns a Prover for the current proof.
        """
        pass

    def get_verifier(self):
        """
        Returns a Verifier for the current proof.
        """
        pass

    def recompute_commitment(self, challenge, response):

        """
        Computes a pseudo-commitment (literally, the commitment you should have received 
        if the proof was correct. To compare to the actual commitment.
        :param challenge: the challenge used in the proof
        :param response: an list of responses, ordered as the list of secret names i.e with as many elements as secrets in the proof claim.
        Reoccuring secrets should yield identical responses.
        """
        pass

    def set_simulate(self):
        self.simulation = True

    def prove(self, secret_dict={}, message=""):
        """
        Generate the transcript of a non-interactive proof.
        """
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
        Verifies the current proof corresponds to the hash passed as a parameter.
        Returns a preshash of the current proof, e.g to be used to verify NI proofs
        """
        cur_statement = self.prehash_statement()
        if statement != cur_statement.digest():
            raise Exception("Proof statements mismatch, impossible to verify")
        return cur_statement

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


def find_residual_chal(arr, challenge, chal_length):
    """ To find c1 such that c = c1 + c2 +c3 mod k,
    We compute c2 + c3 -c and take the opposite
    """
    modulus = Bn(2).pow(chal_length)
    temp_arr = arr.copy()
    temp_arr.append(-challenge)
    return -add_Bn_array(temp_arr, modulus)


def sub_proof_prover(sub_proof, secrets_dict):
    keys = set(sub_proof.secret_vars)
    secrets_for_prover = {}
    for s_name in secrets_dict.keys():
        if s_name in keys:
            secrets_for_prover[s_name] = secrets_dict[s_name]
    return sub_proof.get_prover(secrets_for_prover)


class OrProof(Proof):
    def __init__(self, *subproofs):
        """
        :param subproofs: an arbitrary number of proofs. 
        Arguments can also be lists of proofs, but not lists of lists.
        :return: A Proof being the Or disjunction of the argument proofs.

        """
        if len(subproofs) < 2:
            raise Exception("AndProof needs >1 arguments !")

        self.subproofs = list(subproofs)

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

    def get_randomizers(self) -> dict:
        """Creates a dictionary of randomizers by querying the subproofs dicts and merging them
        """
        random_vals = {}
        {random_vals.update(subp.get_randomizers()) for subp in self.subproofs}
        return random_vals

    def recompute_commitment(self, challenge, responses):
        """ Recomputes the commitments, sets them to None if the challenge is inconsistent.
        """
        # We retrieve the challenges, hidden in the responses tuple
        self.or_challenges = responses[0]
        responses = responses[1]
        comm = []

        # We check for challenge consistency i.e the constraint was respected
        if find_residual_chal(self.or_challenges, challenge, CHAL_LENGTH) != Bn(0):
            raise Exception("Inconsistent challenge")
        for i in range(len(self.subproofs)):
            cur_proof = self.subproofs[i]
            comm.append(
                cur_proof.recompute_commitment(self.or_challenges[i], responses[i])
            )
        return comm

    def get_prover(self, secrets_dict={}):
        """Gets an OrProver which contains a list of the N subProvers, N-1 of which will be simulators.
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
                return None
            self.chosen_idx = rd.choice(possible)
            valid_prover = sub_proof_prover(
                self.subproofs[self.chosen_idx], secrets_dict
            )
        return OrProver(self, valid_prover)

    def get_verifier(self):
        return OrVerifier(self, [subp.get_verifier() for subp in self.subproofs])

    def simulate_proof(self, responses_dict=None, challenge=None):
        if challenge is None:
            challenge = chal_randbits(CHAL_LENGTH)
        com = []
        resp = []
        or_chals = []
        precom = []
        for index in range(len(self.subproofs) - 1):
            transcript = self.subproofs[index].simulate_proof()
            com.append(transcript.commitment)
            resp.append(transcript.responses)
            or_chals.append(transcript.challenge)
            precom.append(transcript.precommitment)

        final_chal = find_residual_chal(or_chals, challenge, CHAL_LENGTH)
        or_chals.append(final_chal)
        trfinal = self.subproofs[index + 1].simulate_proof(responses_dict, final_chal)
        com.append(trfinal.commitment)
        resp.append(trfinal.responses)
        precom.append(trfinal.precommitment)

        return SimulationTranscript(com, challenge, (or_chals, resp), precom)


"""
Important :
    - shared secrets inside/outside an Or Proof should not appear
"""


class OrProver(Prover):
    def __init__(self, proof, subprover):
        self.subprover = subprover
        self.proof = proof
        self.true_prover_idx = self.proof.chosen_idx
        # Create a list to store the SimulationTranscripts
        self.simulations = []
        self.setup_simulations()

    def setup_simulations(self):
        for index in range(len(self.proof.subproofs)):
            if index != self.true_prover_idx:
                cur = self.proof.subproofs[index].simulate_proof()
                self.simulations.append(cur)

    def precommit(self):
        precommitment = []
        for index in range(len(self.proof.subproofs)):
            if index == self.true_prover_idx:
                precommitment.append(self.subprover.precommit())
            else:
                if index > self.true_prover_idx:
                    index1 = index - 1
                else:
                    index1 = index
                precommitment.append(self.simulations[index1].precommitment)
        return precommitment

    def internal_commit(self, randomizers_dict=None):
        """ First operation of an Or Prover. 
        Runs all the simulators which are needed to obtain commitments for every subprover.
        """
        if self.true_prover_idx == None:
            raise Exception("cannot commit in a simulator")
        commitment = []
        for index in range(len(self.proof.subproofs)):
            if index == self.true_prover_idx:
                commitment.append(self.subprover.internal_commit(randomizers_dict))
            else:
                if index > self.true_prover_idx:
                    index1 = index - 1
                else:
                    index1 = index
                commitment.append(self.simulations[index1].commitment)
        return commitment

    def compute_response(self, challenge):
        chals = [el.challenge for el in self.simulations]
        residual_chal = find_residual_chal(chals, challenge, CHAL_LENGTH)
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
                cur_sim = self.simulations[index1]
                challenges.append(cur_sim.challenge)
                response.append(cur_sim.responses)

        # We carry the or challenges in a tuple so everything works fine with the interface
        return (challenges, response)


class OrVerifier(Verifier):
    def __init__(self, proof, subverifiers):
        self.subs = subverifiers
        self.proof = proof

    def process_precommitment(self, precommitment):
        if precommitment is None:
            return
        for idx in range(len(self.subs)):
            self.subs[idx].process_precommitment(precommitment[idx])

    def check_responses_consistency(self, responses, responses_dict={}):
        """ In an Or Proof, we don't require responses consistency through proofs, so the dictionary is never updated.
        """
        for idx in range(len(self.subs)):
            if not self.subs[idx].check_responses_consistency(responses[1][idx], {}):
                return False
        return True


class AndProof(Proof):
    def __init__(self, *subproofs):
        """
        :param subproofs: an arbitrary number of proofs. 
        Arguments can also be lists of proofs, but not lists of lists.
        :return: An other Proof object being the And conjunction of the argument proofs."""

        if len(subproofs) < 2:
            raise Exception("AndProof needs >1 arguments !")

        self.subproofs = list(subproofs)

        self.generators = get_generators(self.subproofs)
        self.secret_vars = get_secret_vars(self.subproofs)
        # Construct a dictionary with the secret values we already know
        self.secret_values = {}
        for sec in self.secret_vars:
            if sec.value is not None:
                self.secret_values[sec] = sec.value
        self.simulation = False
        check_groups(self.secret_vars, self.generators)
        self.check_or_flaw()

    def recompute_commitment(self, challenge, andresp):
        """
        This function allows to retrieve the commitment generically. 
        """
        comm = []
        for i in range(len(self.subproofs)):
            cur_proof = self.subproofs[i]
            comm.append(cur_proof.recompute_commitment(challenge, andresp[i]))
        return comm

    def get_prover(self, secrets_dict={}):
        """ Returns an AndProver, which contains the whole Proof information but also a list of instantiated subprovers, one for each term of the Proof.
        Has access to the secret values.
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
            return None
        return AndProver(self, subs)

    def get_verifier(self):
        return AndVerifier(self, [subp.get_verifier() for subp in self.subproofs])

    def get_proof_id(self):
        return ["And", [sub.get_proof_id() for sub in self.subproofs]]

    def get_randomizers(self) -> dict:
        """Creates a dictionary of randomizers by querying the subproofs dicts and merging them"""
        random_vals = {}
        dict_name_gen = dict(zip(self.secret_vars, self.generators))
        name_set = set(self.secret_vars)
        for u in name_set:
            random_vals[u] = dict_name_gen[u].group.order().random()
        return random_vals

    def simulate_proof(self, responses_dict=None, challenge=None):
        if responses_dict is None:
            responses_dict = self.get_randomizers()
        elif any([x not in responses_dict.keys() for x in self.secret_vars]):
            # We were passed an incomplete dictionary, fill it
            new_dict = self.get_randomizers()
            new_dict.update(responses_dict)
            responses_dict = new_dict
        if challenge is None:
            challenge = chal_randbits(CHAL_LENGTH)
        com = []
        resp = []
        precom = []
        for subp in self.subproofs:
            filtered = list(set(subp.secret_vars) & set(responses_dict.keys()))
            subdict = {key: responses_dict[key] for key in filtered}
            simulation = subp.simulate_proof(subdict, challenge)
            com.append(simulation.commitment)
            resp.append(simulation.responses)
            precom.append(simulation.precommitment)
        return SimulationTranscript(com, challenge, resp, precom)

    def check_or_flaw(self, forbidden_secrets=None):
        """ Checks for appearance of reoccuring secrets inside and outside an Or Proof
            Raises an error if finds any."""
        if forbidden_secrets is None:
            forbidden_secrets = []
        for subp in self.subproofs:
            if "Or" in subp.__class__.__name__:
                if any(x in subp.secret_vars for x in forbidden_secrets):
                    raise Exception(
                        "Or flaw detected. Aborting. Try to flatten the proof to  \
                        avoid shared secrets inside and outside an Or"
                    )
                for other_sub in self.subproofs:
                    if other_sub != subp and any(
                        set(subp.secret_vars) & set(other_sub.secret_vars)
                    ):
                        raise Exception(
                            "Or flaw detected (same_level). Aborting. Try to flatten the proof to  \
                        avoid shared secrets inside and outside an Or"
                        )
            elif "And" in subp.__class__.__name__:
                fb = subp.secret_vars.copy()
                forbidden_secrets.extend(fb)
                subp.check_or_flaw(forbidden_secrets)


class AndProver(Prover):
    """:param subprovers: instances of Prover"""

    def __init__(self, proof, subprovers):
        self.subs = subprovers
        self.proof = proof

    def precommit(self):
        precommitment = []
        for idx in range(len(self.subs)):
            subprecom = self.subs[idx].precommit()
            if subprecom is not None:
                if len(precommitment) == 0:
                    precommitment = [None] * len(self.subs)
                precommitment[idx] = subprecom
        return precommitment if len(precommitment) != 0 else None

    def internal_commit(self, randomizers_dict=None):
        """:return: a AndProofCommitment instance from the commitments of the subproofs encapsulated by this and-proof"""
        if randomizers_dict is None:
            randomizers_dict = self.proof.get_randomizers()
        elif any(
            [sec not in randomizers_dict.keys() for sec in self.proof.secret_vars]
        ):
            # We were passed an incomplete dict, fill the empty slots but keep the existing ones
            secret_to_random_value = self.proof.get_randomizers()
            secret_to_random_value.update(randomizers_dict)
            randomizers_dict = secret_to_random_value

        self.commitment = []
        for subp in self.subs:
            self.commitment.append(
                subp.internal_commit(randomizers_dict=randomizers_dict)
            )
        return self.commitment

    def compute_response(self, challenge):
        """:return: the list (of type AndProofResponse) containing the subproofs responses"""  # r = secret*challenge + k
        return [subp.compute_response(challenge) for subp in self.subs]


class AndVerifier(Verifier):
    def __init__(self, proof, subverifiers):
        """
        :param subverifiers: instances of subtypes of Verifier
        """

        self.subs = subverifiers
        self.proof = proof

    def send_challenge(self, commitment, mute=False):
        """
        :param commitment: a petlib.bn.Bn number
        :return: a random challenge smaller than 2**128
        """
        if mute:
            self.commitment = commitment
        else:
            statement, self.commitment = commitment
            self.proof.check_statement(statement)
        self.challenge = chal_randbits(CHAL_LENGTH)
        return self.challenge

    def check_responses_consistency(self, responses, responses_dict={}):
        """Checks the responses are consistent for reoccurring secret names. 
        Iterates through the subverifiers, gives them the responses related to them and constructs a response dictionary (with respect to secret names).
        If an inconsistency if found during this build, an error code is returned.
        """
        for i in range(len(self.subs)):
            if not self.subs[i].check_responses_consistency(
                responses[i], responses_dict
            ):
                return False
        return True

    def process_precommitment(self, precommitment):
        if precommitment is None:
            return
        for idx in range(len(self.subs)):
            self.subs[idx].process_precommitment(precommitment[idx])

    def check_adequate_lhs(self):
        """
        Check that all the left-hand sides of the proofs have a coherent value.
        In particular, it will return False if a DLRepNotEqualProof is in the tree and
        if it is about to prove its components are in fact equal.
        This allows not to waste computation time in running useless verifications.
        """
        for sub in self.subs:
            if not sub.check_adequate_lhs():
                return False
        return True
