#!/usr/bin/python3
from SigmaProtocol import *
from DLRep import *
import secrets
"""
Question :
    - shared secrets inside/outside an Or Proof should not appear
"""
class OrProver(Prover): # This prover is built on two subprovers, max one of them is a simulator

    def __init__(self, subprovers):
        self.subs = subprovers.copy()

        self.generators = get_generators(subprovers)
        self.secret_names = get_secret_names(subprovers)

        self.simulations = []
        self.true_prover = self.find_legit_prover()

    def find_legit_prover(self):
        for index in range(len(self.subs)):
            if self.subs[index].secret_values != {}:
                return index
        raise Exception("Cannot find a legit prover")


    def get_randomizers(self) -> dict:  #Creates a dictionary of randomizers by querying the subproofs dicts and merging them
        random_vals = {}
        {random_vals.update(subp.get_randomizers().copy()) for subp in self.subs}
        return random_vals

    def commit(self, randomizers_dict = None):
        """ First operation of an Or Prover. 
        Runs all the simulators which are needed to obtain commitments for every subprover.
        """
        # Is this useful in an Or Proof ? TODO : check
        if randomizers_dict is None:
            randomizers_dict = self.get_randomizers()

        # Unify the possible responses to common secret names
        responses_dict = self.get_randomizers()

        commitment = []
        for index in range(len(self.subs)):
            if index == self.true_prover:
                commitment.append(self.subs[index].commit())
            else :
                cur = self.subs[index].simulate_proof(responses_dict)
                self.simulations.append(cur)
                commitment.append(cur[0])
        return commitment

    def compute_response(self, challenge):
        chals = [el[1] for el in self.simulations]
        residual_chal = find_residual_chal(chals, challenge)
        response = []
        challenges = []
        for index in range(len(self.subs)):
            if index == self.true_prover:
                challenges.append(residual_chal)
                response.append(self.subs[index].compute_response(residual_chal))
            else :
                # Note len(simulations) = len(subproofs) - 1 !
                if index > self.true_prover:
                    index1 = index-1
                else :
                    index1 = index
                cur_sim = self.simulations[index1]
                challenges.append(cur_sim[1])
                response.append(cur_sim[2])

        # We carry the or challenges in a tuple so everything works fine with the interface
        return (challenges, response)

    def simulate_proof(self, responses_dict = None, challenge = None):
        if responses_dict is None:
            responses_dict = self.get_randomizers() 
        if challenge is None:
            challenge = chal_128bits()
        com = []
        resp = []
        or_chals = []
        for index in range(len(self.subs)-1):
            (com1, chal1, resp1) = self.subs[index].simulate_proof(responses_dict)
            com.append(com1)
            resp.append(resp1)
            or_chals.append(chal1)
    
        final = find_residual_chal(or_chals, challenge)
        or_chals.append(final)
        com1, __, resp1 = self.subs[index+1].simulate_proof(responses_dict, final)
        com.append(com1)
        resp.append(resp1)

        return com, challenge, (or_chals, resp)
        
            
def find_residual_chal(arr, challenge = Bn(0)):
    temp_arr = arr.copy()
    temp_arr.append(challenge)
    return xor_Bn_array(temp_arr)



class OrVerifier(Verifier):
    def __init__(self, subverifiers):
        self.subs = subverifiers.copy()
        
        self.generators = get_generators(subverifiers)
        self.secret_names = get_secret_names(subverifiers)

        self.recompute_commitment = OrProof.recompute_commitment
    

        

class OrProof:  
    def __init__(self, *subproofs):
        if not subproofs:
            raise Exception('OrProof needs arguments !')
        list_subproofs = []
        for el in subproofs:
            if isinstance(el, list):
                list_subproofs.extend(el)
            else:
                list_subproofs.append(el)

        self.subproofs = list_subproofs

        self.generators = get_generators(self.subproofs)  #For consistency
        self.secret_names = get_secret_names(self.subproofs)
        self.simulate = False
        check_groups(self.secret_names, self.generators) # For now we consider the same constraints as in the And Proof
    


    def recompute_commitment(self, challenge, responses):
        """ Recomputes the commitments, sets them to None if the challenge is inconsistent.
        """
        # We retrieve the challenges, hidden in the responses tuple
        self.or_challenges = responses[0]
        responses = responses[1]
        comm = []
    
        # We check for challenge consistency i.e the constraint was respected
        if find_residual_chal(self.or_challenges) != challenge:
            raise Exception("Inconsistent challenge")
        for i in range(len(self.subs)):
            cur_proof = self.subs[i]
            comm.append(cur_proof.recompute_commitment(cur_proof, self.or_challenges[i], responses[i]))
        return comm

    def get_prover(self, secrets_dict):
        """Gets an OrProver which contains a list of the N subProvers, N-1 of which will be simulators.
        """ 
        bigset = set(self.secret_names)
        
        # We sort them but we need to keep track of their initial index
        ordered_proofs = dict(enumerate(self.subproofs))
        candidates = {}
        sims = {}
        for key, value in ordered_proofs.items():
            if value.simulate:
                sims[key]= value
            else:
                candidates[key] = value

        # We need to choose one subproof to be actually computed among all which can be computed
        # If the available secrets do not match the ones required in the chosen subproof, choose an other
        possible = list(candidates.keys())
        chosen_idx = secrets.choice(possible)
        while any(x not in bigset for x in (candidates[chosen_idx].secret_names)):
            pdb.set_trace()
            chosen_idx = secrets.choice(possible)
        
        elem = candidates.pop(chosen_idx)
        subdict = dict((k, secrets_dict[k]) for k in set(elem.secret_names))
        
        # Now we get the simulators
        sims.update(candidates)
        for to_sim in sims.keys():
            sims[to_sim] = sims[to_sim].get_simulator()

        # We add the legit prover
        sims[chosen_idx] = elem.get_prover(subdict)

        # Return a list of provers in the correct order
        return OrProver([sims[index] for index in sorted(sims)])

    def get_simulator(self):
        """ Returns an empty prover which can only simulate (via simulate_proof)
        """
        arr = [subp.get_simulator() for subp in self.subproofs]
        return OrProver(arr)

    def get_verifier(self):
        return OrVerifier([subp.get_verifier() for subp in self.subproofs])

    def set_simulate(self):
        self.simulate = True


