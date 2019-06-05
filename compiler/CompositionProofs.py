from petlib.bn import Bn
from Abstractions import *

AndProofCommitment = list
AndProofResponse = list
AndProofChallenge = Bn


class Proof:
    """An abstraction of a sigma protocol proof"""

    def __and__(self, other):
        """
        :return: an AndProof from this proof and the other proof using the infix '&' operator
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
        :return: an OrProof from this proof and the other proof using the infix '|' operator
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
        :param: secrets_dict: a mapping from secret names to secret values
        :return: an instance of Prover"""
        pass

    def get_verifier(self):
        """:return: an instance of Verifier"""
        pass

    def recompute_commitment(self, challenge, response):

        """
        :param challenge: the 128 bits challenge used in the proof
        :param response: an list of responses, ordered as the list of secret names i.e with as many elements as secrets in the proof claim.
        Reoccuring secrets should yield identical responses.
        :return: a pseudo-commitment (literally, the commitment you should have received 
        if the proof was correct. To compare to the actual commitment"""
        pass

    def set_simulate(self):
        self.simulate = True

    def prove(self, secret_dict, message="", encoding=None):
        """
        Generate the transcript of a non-interactive proof.
        """
        prover = self.get_prover(secret_dict)
        return prover.get_NI_proof(message, encoding)

    def verify(self, transcript, message="", encoding=None):
        """
        Verify the transcript of a non-interactive proof.
        """
        verifier = self.get_verifier()
        return verifier.verify_NI(transcript, message, encoding)

    def simulate(self):
        """
        Generate the transcript of a simulated non-interactive proof.
        """
        prover = self.get_prover()
        return self.prover.simulate_proof()

    def check_statement(self, statement):
        """ 
        try:
            identifier = encode(self.proof.get_proof_id(), encoding)
        except TypeError:
            raise Exception("If your proof contains pairings, please commit with encoding=enc_GXpt")
        return sha256(identifier).digest(), self.internal_commit(randomizers_dict) """
        if statement != self.hash_statement():
            raise Exception("Proof statements mismatch, impossible to verify")
        return True

    def hash_statement(self):
        if not isinstance(self.generators[0], EcPt):
            encoding = enc_GXpt
        else:
            encoding =None
        return sha256(encode(self.get_proof_id(), encoding)).digest()

def find_residual_chal(arr, challenge, chal_length):
    """ To find c1 such that c = c1 + c2 +c3 mod k,
    We compute c2 + c3 -c and take the opposite
    """
    modulus = Bn(2).pow(chal_length)
    temp_arr = arr.copy()
    temp_arr.append(-challenge)
    return -add_Bn_array(temp_arr, modulus)


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
        self.secret_names = get_secret_names(self.subproofs)
        self.simulate = False
        check_groups(self.secret_names, self.generators)
        # For now we consider the same constraints as in the And Proof

    def get_proof_id(self):
        return ["Or", [sub.get_proof_id() for sub in self.subproofs]]

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
        if self.simulate == True or secrets_dict == {}:
            print("Can only simulate")
            return self.get_simulator()
        bigset = set(secrets_dict.keys())

        # We sort them but we need to keep track of their initial index
        ordered_proofs = dict(enumerate(self.subproofs))
        candidates = {}
        sims = {}
        for key, value in ordered_proofs.items():
            if value.simulate:
                sims[key] = value
            else:
                candidates[key] = value

        # We need to choose one subproof to be actually computed among all which can be computed
        # If the available secrets do not match the ones required in the chosen subproof, choose another
        possible = list(candidates.keys())
        rd = random.SystemRandom()
        chosen_idx = rd.choice(possible)
        while any(x not in bigset for x in (candidates[chosen_idx].secret_names)):
            chosen_idx = rd.choice(possible)

        elem = candidates.pop(chosen_idx)
        subdict = dict((k, secrets_dict[k]) for k in set(elem.secret_names))

        # Now we get the simulators
        sims.update(candidates)
        for to_sim in sims.keys():
            sims[to_sim] = sims[to_sim].get_simulator()

        # We add the legit prover
        sims[chosen_idx] = elem.get_prover(subdict)

        # Return a list of provers in the correct order
        return OrProver(self, [sims[index] for index in sorted(sims)], secrets_dict)

    def get_simulator(self):
        """ Returns an empty prover which can only simulate (via simulate_proof)
        """
        arr = [subp.get_simulator() for subp in self.subproofs]
        return OrProver(self, arr, {})

    def get_verifier(self):
        return OrVerifier(self, [subp.get_verifier() for subp in self.subproofs])


"""
Important :
    - shared secrets inside/outside an Or Proof should not appear
"""


class OrProver(Prover):
    # This prover is built on two subprovers, max one of them being a simulator
    def __init__(self, proof, subprovers, secret_values):
        self.subs = subprovers
        self.proof = proof
        self.secret_values = secret_values
        self.true_prover_idx = self.find_legit_prover()
        self.simulations = []
        self.setup_simulations()

    def find_legit_prover(self):
        for index in range(len(self.subs)):
            # In order to test this we need the OrProver and AndProver to also have a secrets_dict
            if self.subs[index].secret_values != {}:
                return index
        print("No legit prover found, can only simulate the Or Proof")
        return None

    def setup_simulations(self):
        for index in range(len(self.subs)):
            if index != self.true_prover_idx:
                cur = self.subs[index].simulate_proof()
                self.simulations.append(cur)

    def get_randomizers(self) -> dict:
        """Creates a dictionary of randomizers by querying the subproofs dicts and merging them
        """
        random_vals = {}
        {random_vals.update(subp.get_randomizers().copy()) for subp in self.subs}
        return random_vals

    def precommit(self):
        precommitment = []
        for index in range(len(self.subs)):
            if index == self.true_prover_idx:
                precommitment.append(self.subs[index].precommit())
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
        for index in range(len(self.subs)):
            if index == self.true_prover_idx:
                commitment.append(self.subs[index].internal_commit(randomizers_dict))
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
        for index in range(len(self.subs)):
            if index == self.true_prover_idx:
                challenges.append(residual_chal)
                response.append(self.subs[index].compute_response(residual_chal))
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

    def simulate_proof(self, responses_dict=None, challenge=None):
        if responses_dict is None or any(
            [x not in responses_dict.keys() for x in self.proof.secret_names]
        ):
            responses_dict = self.get_randomizers()
        if challenge is None:
            challenge = chal_randbits(CHAL_LENGTH)
        com = []
        resp = []
        or_chals = []
        precom = []
        for index in range(len(self.subs) - 1):
            subdict = {
                key: responses_dict[key] for key in self.subs[index].proof.secret_names
            }
            transcript = self.subs[index].simulate_proof(subdict)
            com.append(transcript.commitment)
            resp.append(transcript.responses)
            or_chals.append(transcript.challenge)
            precom.append(transcript.precommitment)

        final_chal = find_residual_chal(or_chals, challenge, CHAL_LENGTH)
        or_chals.append(final_chal)
        trfinal = self.subs[index + 1].simulate_proof(responses_dict, final_chal)
        com.append(trfinal.commitment)
        resp.append(trfinal.responses)
        precom.append(trfinal.precommitment)

        return SimulationTranscript(com, challenge, (or_chals, resp), precom)


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
        self.secret_names = get_secret_names(self.subproofs)
        self.simulate = False
        check_groups(self.secret_names, self.generators)
        self.check_or_flaw()

    def recompute_commitment(self, challenge, andresp: AndProofResponse):
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
        if self.simulate == True or secrets_dict == {}:
            print("Can only simulate")
            return self.get_simulator()

        def sub_proof_prover(sub_proof):
            keys = set(sub_proof.secret_names)
            secrets_for_prover = []
            for s_name in secrets_dict:
                if s_name in keys:
                    secrets_for_prover.append((s_name, secrets_dict[s_name]))
            return sub_proof.get_prover(dict(secrets_for_prover))

        andp = AndProofProver(
            self,
            [sub_proof_prover(sub_proof) for sub_proof in self.subproofs],
            secrets_dict,
        )
        return andp

    def get_verifier(self):
        return AndProofVerifier(self, [subp.get_verifier() for subp in self.subproofs])

    def get_simulator(self):
        """ Returns an empty prover which can only simulate (via simulate_proof)
        """
        arr = [subp.get_simulator() for subp in self.subproofs]
        return AndProofProver(self, arr, {})

    def get_proof_id(self):
        return ["And", [sub.get_proof_id() for sub in self.subproofs]]

    def check_or_flaw(self, forbidden_secrets=None):
        """ Checks for appearance of reoccuring secrets inside and outside an Or Proof
            Raises an error if finds any."""
        if forbidden_secrets is None:
            forbidden_secrets = []
        for subp in self.subproofs:
            if "Or" in subp.__class__.__name__:
                if any(x in subp.secret_names for x in forbidden_secrets):
                    raise Exception(
                        "Or flaw detected. Aborting. Try to flatten the proof to  \
                        avoid shared secrets inside and outside an Or"
                    )
                for other_sub in self.subproofs:
                    if other_sub != subp and any(
                        set(subp.secret_names) & set(other_sub.secret_names)
                    ):
                        raise Exception(
                            "Or flaw detected (same_level). Aborting. Try to flatten the proof to  \
                        avoid shared secrets inside and outside an Or"
                        )
            elif "And" in subp.__class__.__name__:
                fb = subp.secret_names.copy()
                forbidden_secrets.extend(fb)
                subp.check_or_flaw(forbidden_secrets)


class AndProofProver(Prover):
    """:param subprovers: instances of Prover"""

    def __init__(self, proof, subprovers, secret_values):
        self.subs = subprovers
        self.secret_values = secret_values
        self.proof = proof

    def get_randomizers(self) -> dict:
        """Creates a dictionary of randomizers by querying the subproofs dicts and merging them"""
        random_vals = {}
        dict_name_gen = dict(zip(self.proof.secret_names, self.proof.generators))
        name_set = set(self.proof.secret_names)
        for u in name_set:
            random_vals[u] = dict_name_gen[u].group.order().random()
        return random_vals

    def precommit(self):
        precommitment = []
        for idx in range(len(self.subs)):
            subprecom = self.subs[idx].precommit()
            if subprecom is not None:
                if len(precommitment) == 0:
                    precommitment = [None] * len(self.subs)
                precommitment[idx] = subprecom
        return precommitment if len(precommitment) != 0 else None

    def internal_commit(self, randomizers_dict=None) -> AndProofCommitment:
        """:return: a AndProofCommitment instance from the commitments of the subproofs encapsulated by this and-proof"""
        if randomizers_dict is None:
            randomizers_dict = self.get_randomizers()
        elif any(
            [sec not in randomizers_dict.keys() for sec in self.proof.secret_names]
        ):
            # We were passed an incomplete dict, fill the empty slots but keep the existing ones
            secret_to_random_value = self.get_randomizers()
            secret_to_random_value.update(randomizers_dict)
            randomizers_dict = secret_to_random_value

        self.commitment = []
        for subp in self.subs:
            self.commitment.append(subp.internal_commit(randomizers_dict=randomizers_dict))
        return self.commitment

    def compute_response(self, challenge: AndProofChallenge) -> AndProofResponse:
        """:return: the list (of type AndProofResponse) containing the subproofs responses"""  # r = secret*challenge + k
        return [subp.compute_response(challenge) for subp in self.subs]

    def simulate_proof(self, responses_dict=None, challenge=None):
        if responses_dict is None:
            responses_dict = self.get_randomizers()
        elif any([x not in responses_dict.keys() for x in self.proof.secret_names]):
            # We were passed an incomplete dictionary, fill it
            new_dict = self.get_randomizers()
            new_dict.update(responses_dict)
            responses_dict = new_dict
        if challenge is None:
            challenge = chal_randbits(CHAL_LENGTH)
        com = []
        resp = []
        precom = []
        for subp in self.subs:
            filtered = list(set(subp.proof.secret_names) & set(responses_dict.keys()))
            subdict = {key: responses_dict[key] for key in filtered}
            simulation = subp.simulate_proof(subdict, challenge)
            com.append(simulation.commitment)
            resp.append(simulation.responses)
            precom.append(simulation.precommitment)
        return SimulationTranscript(com, challenge, resp, precom)


class AndProofVerifier(Verifier):
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
