#!/usr/bin/python3
from SigmaProtocol import *
from DLRep import *

import secrets
import random


class OrProver(Prover): # This prover is built on two subprovers, max one of them is a simulator

    def __init__(self, subprovers):
        self.subs = subprovers.copy()

        self.generators = get_generators(subprovers)
        self.secret_names = get_secret_names(subprovers)


    def find_legit_prover(self):
        for subprover in self.subs:
            is self.subs


    def get_randomizers(self) -> dict:  #Creates a dictionary of randomizers by querying the subproofs dicts and merging them
        random_vals = {}
        {random_vals.update(subp.get_randomizers().copy()) for subp in self.subs}
        return random_vals

    def commit(self, randomizers_dict=None):
        if randomizers_dict is None:
            randomizers_dict = self.get_randomizers()
        

    def computeResponse(self, challenge):
        pass


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
        

    def get_prover(self, secrets_dict):
    """Gets an OrProver which contains a list of the N subProvers, N-1 of which will be simulators.
    """ 
        bigset = set(self.secret_names)
        
        # We sort them but we need to keep track of their initial index
        ordered_proofs = dict(range(self.subproofs), self.subproofs)
        candidates = {}
        sims = {}
        for key, value in ordered_proofs.items():
            {sims[key]= value if value.simulate else candidates[key] = value}

        # We need to choose one subproof to be actually computed among all which can be computed
        # If the available secrets do not match the ones required in the chosen subproof, choose an other
        possible = candidates.keys()
        chosen_idx = secrets.choice(possible)
        while set(candidates[chosen_idx].secret_names) not in bigset:
            chosen_idx = secrets.choice(possible)
        
        elem = candidates.pop(chosen_idx)
        subdict = dict((k, secrets_dict[k]) for k in set(elem.secret_names))
        
        # Now we get the simulators
        sims.update(candidates)
        for to_sim in sims.values():
            to_sim = to_sim.get_simulator()

        # We add the legit prover
        to_sim[chosen_idx] = elem.get_prover(subdict)

        # Return a list of prover in the correct order
        return OrProver([to_sim[index] for index in sorted(to_sim)])

    def get_simulator(self):
        """ Returns an empty prover which can only simulate (via simulate_proof)
        """
        arr = [subp.get_simulator() for subp in self.subproofs]
        return OrProver(arr)

    def get_verifier(self):
        return OrVerifier([subp.get_verifier() for subp in self.subproofs])

    def set_simulate(self):
        self.simulate = True


