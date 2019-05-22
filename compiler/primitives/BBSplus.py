from primitives.DLRep import *
from Subproof import *
from CompositionProofs import *
from SigmaProtocol import *
from BilinearPairings import *
import pdb
import random, string

RD_LENGTH = 30
DEFAULT_SIGALIASES = ["r1_", "r2_", "delta1_", "delta2_"]


def generate_signature_aliases():
    nb1, nb2 = chal_randbits(), chal_randbits()
    return (
        DEFAULT_SIGALIASES[0] + nb1.hex(),
        DEFAULT_SIGALIASES[1] + nb2.hex(),
        DEFAULT_SIGALIASES[2] + nb1.hex(),
        DEFAULT_SIGALIASES[3] + nb2.hex(),
    )


class Signature:
    def __init__(self, A, e, s_):
        self.A = A
        self.e = e
        self.s = s_

    def verify_signature(self, pk, messages):
        generators = pk.generators[: len(messages) + 2]
        product = generators[0] + generators[0].group.wsum(
            ([self.s] + messages), generators[1:]
        )
        return self.A.pair(pk.w + self.e * pk.h0) == product.pair(pk.h0)


class UserCommitmentMessage:
    """
    Embeds the product to be presigned by the issuer. If blinded by a user pedersen commitment, a NI proof is also specified.
    """

    def __init__(self, commitment, pedersen_NIproof=None):
        self.commitment_message = commitment
        self.NIproof = pedersen_NIproof

    def verify_blinding(self, pk, nb_messages):
        """
        Prototypes a ZK proof for the Pedersen commitment to messages and uses it to
        verify the non-interactive proof passed as argument.
        """
        if self.NIproof is None:
            raise Exception("No proof to verify")
        generators = pk.generators[1 : nb_messages + 2]
        lhs = self.commitment_message
        secret_names = ["s'"] + ["m" + str(i + 1) for i in range(len(generators))]
        proof = DLRepProof(lhs, create_rhs(secret_names, generators))
        return proof.get_verifier().verify_NI(*self.NIproof, encoding=enc_GXpt)


class SignatureCreator:
    def __init__(self, pk):
        self.pk = pk
        self.s1 = None

    def commit(self, messages, zkp=False):
        """
        Prepare a pedersen commitment for the correct construction of the sequence to be signed.
        Returns a non-interactive proof if zkp parameter is set to true.
        """
        lhs = self.pk.generators[0].group.wsum(
            messages, self.pk.generators[2 : len(messages) + 2]
        )
        self.s1 = Bn(0)
        NIproof = None
        if zkp:
            self.s1 = self.pk.generators[0].group.order().random()
            lhs = self.s1 * self.pk.generators[1] + lhs
            # define secret names as s' m1 m2 ...mL
            names = ["s'"] + ["m" + str(i + 1) for i in range(len(messages))]
            secrets = [self.s1] + messages
            rhs = create_rhs(names, self.pk.generators[1:])

            pedersen_proof = DLRepProof(lhs, rhs)
            pedersen_prover = pedersen_proof.get_prover(dict(zip(names, secrets)))
            NIproof = pedersen_prover.get_NI_proof(encoding=enc_GXpt)
        return UserCommitmentMessage(lhs, NIproof)

    def obtain_signature(self, presignature):
        """
        S1 is the part of the signature blinding factor which is on the user side
        """
        new_s = presignature.s + self.s1
        return Signature(presignature.A, presignature.e, new_s)


class KeyPair:
    def __init__(self, bilinearpair, length):
        """
        length should be an upperbound on the number of messages
        """

        self.generators = []
        for i in range(length + 2):
            randWord = str(i + 1)
            self.generators.append(
                bilinearpair.G1.hash_to_point(randWord.encode("UTF-8"))
            )
        self.h0 = bilinearpair.G2.generator()

        self.sk = SecretKey(bilinearpair.G1.order().random(), self)
        self.pk = PublicKey(self.sk.gamma * self.h0, self.generators, self.h0)
        self.sk.pk = self.pk


class PublicKey:
    def __init__(self, w, generators, h0):
        self.w = w
        self.generators = generators
        self.h0 = h0


class SecretKey:
    def __init__(self, value, keypair):
        self.generators = keypair.generators
        self.h0 = keypair.h0
        self.gamma = value

    def sign(self, lhs):
        """
        Signs a committed message Cm ie returns A,e,s such that A = (g0 + s*g1 + Cm) * 1/e+gamma
        """
        pedersen_product = lhs
        e = self.h0.group.order().random()
        s2 = self.h0.group.order().random()
        prod = self.generators[0] + s2 * self.generators[1] + pedersen_product
        A = (self.gamma + e).mod_inverse(self.h0.group.order()) * prod
        return Signature(A, e, s2)


class SignatureProof(Proof):
    """
    Proof of knowledge of a (A,e,s) signature over a set of messages.
    """

    def __init__(self, signature, secret_names, pk):
        """
        Instantiates a Signature Proof which is an enhanced version of AndProof allowing to access additional parameters
        secret_names should be the alias for signature.e, the alias for signature.s, and the aliases for the messages.
        """
        self.pk = pk
        self.generators = pk.generators[: len(secret_names) + 2]
        self.aliases = generate_signature_aliases()
        self.signature = signature
        self.secret_names = secret_names
        self.constructed_proof = None
        self.simulate = False

    def build_constructed_proof(self, precommitment):
        """
        A template for the proof of knowledge of a signature pi5 detailed on page 7 of the following paper : https://eprint.iacr.org/2008/136.pdf
        It uses group pairings, DLRep and And Proofs.
        public info should be : 
            - w (public key), 
            - h0 (base of the public key), 
            - generators (of length len(m)+2)

        """
        self.A1, self.A2 = precommitment[0], precommitment[1]
        g0, g1, g2 = self.generators[0], self.generators[1], self.generators[2]
        dl1 = DLRepProof(
            self.A1, Secret(self.aliases[0]) * g1 + Secret(self.aliases[1]) * g2
        )
        dl2 = DLRepProof(
            g0.group.infinite(),
            Secret(self.aliases[2]) * g1
            + Secret(self.aliases[3]) * g2
            + Secret(self.secret_names[0]) * (-1 * self.A1),
        )

        signature = AndProof(dl1, dl2)

        gen_pairs = [g.pair(self.pk.h0) for g in self.generators]
        self.pair_lhs = self.A2.pair(self.pk.w) + (-1 * gen_pairs[0])
        generators = [
            -1 * (self.A2.pair(self.pk.h0)),
            self.generators[2].pair(self.pk.w),
            gen_pairs[2],
        ]
        generators.extend(gen_pairs[1:])

        # Build secret names [e, r1, delta1, s, m_i]
        new_secret_names = (
            self.secret_names[:1]
            + [self.aliases[0], self.aliases[2]]
            + self.secret_names[1:]
        )
        pairings_proof = DLRepProof(
            self.pair_lhs, create_rhs(new_secret_names, generators)
        )

        self.constructed_proof = AndProof(signature, pairings_proof)
        return self.constructed_proof

    def get_prover(self, secret_values):
        if self.simulate:
            secret_values = {}
        return SignatureProver(self, secret_values)

    def get_proof_id(self):
        return ["SignatureProof", self.generators, self.A1, self.A2, self.pair_lhs]

    def get_verifier(self):
        return SignatureVerifier(self)

    def recompute_commitment(self, challenge, responses):
        return self.constructed_proof.recompute_commitment(challenge, responses)


class SignatureProver(Prover):
    def __init__(self, proof, secret_values):
        self.proof = proof
        self.secret_values = secret_values

    def commit(self, randomizers_dict=None):
        """
        Triggers the inside prover commit. Transfers the randomizer dict coming from above.
        """
        if self.proof.constructed_proof is None:
            raise Exception(
                "Please precommit before commiting, else proofs lack parameters"
            )
        return self.constructed_prover.commit(randomizers_dict)

    def precommit(self):
        """
        Generates the lacking information to construct a complete proof and returns it.
        At the same time, triggers the said proof construction for self and self.proof.
        After this function returns, the current prover is able to commit.
        Returned value is to be processed on the verifier side by verifier.process_precommitment( )
        """
        # Compute auxiliary commitments A1,A2 as mentioned in the paper. Needs two random values r1,r2 and associated delta1,delta2
        r1, r2 = (
            self.proof.generators[0].group.order().random(),
            self.proof.generators[0].group.order().random(),
        )
        delta1, delta2 = r1 * self.proof.signature.e, r2 * self.proof.signature.e
        new_secrets = [r1, r2, delta1, delta2]
        A1 = r1 * self.proof.generators[1] + r2 * self.proof.generators[2]
        A2 = r1 * self.proof.generators[2] + self.proof.signature.A

        self.precommitment = [A1, A2]
        self.proof.build_constructed_proof(self.precommitment)

        # Map the secret names to the values we just computed, and update the secrets dictionary accordingly
        self.constructed_dict = dict(zip(self.proof.aliases, new_secrets))
        self.constructed_dict.update(self.secret_values)
        self.constructed_prover = self.proof.constructed_proof.get_prover(
            self.constructed_dict
        )
        return self.precommitment

    def compute_response(self, challenge):
        self.challenge = challenge
        self.constructed_prover.challenge = challenge
        self.response = self.constructed_prover.compute_response(challenge)
        return self.response


class SignatureVerifier(AndProofVerifier):
    def __init__(self, proof):
        self.proof = proof

    def process_precommitment(self, precommitment):
        self.precommitment = precommitment
        self.proof.build_constructed_proof(precommitment)
        self.constructed_verifier = self.proof.constructed_proof.get_verifier()

    def send_challenge(self, com):
        self.commitment = com
        self.challenge = self.constructed_verifier.send_challenge(com)
        return self.challenge

    def check_adequate_lhs(self):
        required_lhs = self.precommitment[1].pair(self.proof.pk.w) + (
            -1 * self.proof.generators[0]
        ).pair(self.proof.pk.h0)
        if self.proof.constructed_proof.subproofs[1].lhs != required_lhs:
            return False
        return True

    def check_responses_consistency(self, response, response_dict):
        return self.constructed_verifier.check_responses_consistency(
            response, response_dict
        )
