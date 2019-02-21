import random, string
from collections import namedtuple
from petlib.ec import EcGroup
from petlib.bn import Bn
import binascii
import pdb
from hashlib import sha256
from collections import defaultdict
import msgpack

""" Known flaws :
        - Malicious prover can trick proofs :
            - claim knowledge of x1 g1, x1 g2 when in fact we have two distinct secrets
            - by-hand craft a prover x1 g1, x2 g2 (without the get_prover being fed a dict)
            - fix : the use of 1 randomizer per different secrets implies that if 
                under a same challenge, two responses are different then the secrets were different.
                Verifier should check that indeed the responses are the same but GLOBALLY (i.e not just in leaves of the And tree)

        - (fixed) In case of reoccuring secrets in an Or Proof, a look at the responses
            allow to guess which proof was truly computed and which were simulated:
            shared secrets yield identical responses through all the simulations,
            but not with the non-simulated one.

            EDIT : since the Or Proof of N subproofs uses N-1 simulations, it is possible to hand back identical responses
            with different secret since the prover chooses the responses. Thus identical responses give no information to the verifier
            about the correctness of the formula used by the prover. Then the prover doesn't have to care about uniyfing
            the responses cross-subproofs, and the problem vanishes.

        - Bitwise xor of the challenges suck because Bn can only convert from 64 bit integers.
            Had to use a hack through hexadecimal notation.

        - In a non-interactive proof, if the prover and the verifier use two mathematically equivalent yet syntaxically 
            different expressions (e.g "p1 & p2" and "p2 & p1"), the verification fails because of the get_proof_id routine not aware of
            distributivity and commutativity.

        - Sometimes, we get the group order by g.group.order() but is the returned value of hashtopoint
        always a generator of the group itself, and not a subgroup ?
"""

class SigmaProtocol:
    """
    an interface for sigma protocols.
    """
    def __init__(self, verifierClass, proverClass):
        self.verifierClass = verifierClass
        self.proverClass = proverClass

    def setup(self):
        pass

    def verify(
            self
    ) -> bool:  # a method used to chain SigmaProtocols verifications
        victor = self.verifierClass
        peggy = self.proverClass

        (commitment) = peggy.commit()
        challenge = victor.send_challenge(commitment)
        response = peggy.compute_response(challenge)
        return victor.verify(response)

    def run(self):
        if self.verify():
            print("Verified for {0}".format(self.__class__.__name__))
            return True
        else:
            print("Not verified for {0}".format(self.__class__.__name__))
            return False


class Prover:  
    """
    An abstract interface representing Prover used in sigma protocols
    """
    def __init__(self, generators, secret_names, secret_values, lhs):
        pass

    def commit(self, randomizers_dict=None):
        """
        :param randomizers_dict: an optional dictionnary of random values. Each random values is assigned to each secret name
        :return: a single commitment (of type petlib.bn.Bn) for the whole proof
        """
        pass
    def get_secret_values(self):
        pass
        
    def compute_response(self, challenge):
        pass

    def get_NI_proof(
            self, message=''
    ):  
        """ Non-interactive proof 
        :param message: a string message.
        :return: a challenge that is a hash of (lhs, commitment, message) and a list of responses. Each response has type petlib.bn.Bn 
        """
        commitment = self.commit()
        message = message.encode()
        protocol = get_proof_id(self)

        # Computing the challenge
        conc = protocol
        conc += flatten_commitment(commitment)
        conc += message
        myhash = sha256(conc).digest()
        challenge = Bn.from_hex(binascii.hexlify(myhash).decode())
        responses = self.compute_response(challenge)
        return (challenge, responses)




class Verifier:  # The Verifier class is built on an array of generators, an array of secrets'IDs and public info
    def __init__(self, generators, secret_names, lhs):
        pass

    def send_challenge(self, commitment):
        """
        :param commitment: a petlib.bn.Bn number
        :return: a default challenge equal to 2**31
        """
        self.commitment = commitment
        self.challenge = chal_128bits()
        print("\nchallenge is ", self.challenge)

        return self.challenge

    def verify(
            self, response, commitment=None,
            challenge=None):  #Can verify simulations with optional arguments
        """
        verifies this proof
        :param response: the response given by the prover
        :return: a boolean telling whether or not the commitment given by the prover matches the one we obtain by recomputing a commitment from the given challenge and response
        """

        if commitment is None:
            commitment = self.commitment
        if challenge is None:
            challenge = self.challenge

        return (commitment == self.recompute_commitment(self, challenge, response) )

    def verify_NI(self, challenge, response, message=''):
        """
        verification for the non interactive proof
        :param challenge: the challenge a petlib.bn.Bn instance computed from get_NI_proof method
        :param response: computed from get_NI_proof
        :return: a boolean telling if the proof is verified
        """
        message = message.encode()
        protocol = get_proof_id(self)
        r_guess = self.recompute_commitment(self, challenge, response)  #We retrieve the commitment using the verification identity
        conc = protocol
        conc += flatten_commitment(r_guess)
        conc += message
        myhash = sha256(conc).digest()
        print(challenge)
        print(Bn.from_hex(binascii.hexlify(myhash).decode()))
        return challenge == Bn.from_hex(binascii.hexlify(myhash).decode())


def check_groups(
        list_of_secret_names, list_of_generators
):  
    """checks that if two secrets are the same, the generators they multiply induce groups of same order
    :param list_of_secret_names: a list of secrets names of type string. 
    :param list_of_generators: a list of generators of type petlib.ec.EcPt.
    """
    # We map the unique secrets to the indices where they appear
    mydict = defaultdict(list)
    for idx, word in enumerate(list_of_secret_names):
        mydict[word].append(idx)

    # Now we use this dictionary to check all the generators related to a particular secret live in the same group
    for word, gen_idx in mydict.items(
    ):  #word is the key, gen_idx is the value = a list of indices
        ref_order = list_of_generators[gen_idx[0]].group.order()

        for index in gen_idx:
            if list_of_generators[index].group.order() != ref_order:
                raise Exception(
                    "A shared secret has generators which yield different group orders : secret",
                    word)

    return True

#Useful for several proofs :

def chal_128bits():
    twoTo128 = Bn.from_binary(bytes.fromhex("1" + "0" * 31))    #TODO : make clearer what is going on here
    return twoTo128.random()

def get_secret_names(sub_list):
    secrets = []
    [secrets.extend(elem.secret_names.copy()) for elem in sub_list]
    return secrets

def get_generators(sub_list):
    generators = []
    [generators.extend(elem.generators.copy()) for elem in sub_list]
    return generators

def get_proof_id(obj):
    """ Generates a deterministic string describer for a proof """
    cur_type = obj.__class__.__name__ #TODO : don't forget to add descriptors here if new primitives are added
    if "DLRep" in cur_type:
        protocol = ["DLRep"]
        protocol.append(obj.lhs.export())

        [protocol.append(g.export()) for g in obj.generators]
    elif "AndProof" in cur_type:
        protocol = ["And"]
        [
            protocol.append(get_proof_id(subprover))
            for subprover in obj.subs
        ]
    elif "Or" in cur_type:
        protocol = ["Or"]
        [
            protocol.append(get_proof_id(subprover))
            for subprover in obj.subs
        ]
    else:
        raise Exception('Generic Prover in the wild')
    return msgpack.packb(protocol)


def flatten_commitment(comm):
    if not isinstance(comm, list):
        return comm.export() # TODO : check if concatenation of several export() is uniquely decodable
    res = ''.encode()
    for el in comm:
        if isinstance(el, list):
            res += flatten_commitment(el)
        else:
            res += el.export()
    return res


def xor_Bn_array(arr):
    """ Horrible tool to xor 128 bits Bn challenges. #TODO : fix this
    """
    res = 0
    for elem in arr:
        res = res^elem.int()
    return Bn.from_hex(hex(res)[2:].upper())