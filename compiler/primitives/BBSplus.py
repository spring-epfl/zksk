import os, sys

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_code_path = os.path.join(root_dir, "")
if src_code_path not in sys.path:
    sys.path.append(src_code_path)

from primitives.DLRep import *
from CompositionProofs import *
from BilinearPairings import *


class Signature:
    """
    A named tuple for a (A,e,s) signature.
    """

    def __init__(self, A, e, s_):
        self.A = A
        self.e = e
        self.s = s_

    def verify_signature(self, pk, messages):
        """
        Verifies the validity of the signature with respect to the given public key and set of messages.
        """
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

    def verify_blinding(self, pk):
        """
        Prototypes a ZK proof for the Pedersen commitment to messages and uses it to
        verify the non-interactive proof passed as argument.
        """
        if self.NIproof is None:
            raise Exception("No proof to verify")
        generators = pk.generators[1 : len(self.NIproof.responses) + 1]
        lhs = self.commitment_message
        secret_vars = [Secret() for i in range(len(self.NIproof.responses))]
        proof = DLRepProof(lhs, wsum_secrets(secret_vars, generators))
        return proof.verify(self.NIproof)


class SignatureCreator:
    """
    Constructs a UserCommitment i.e the presigned product along if blind with a proof of correct construction (non_interactive)
    """

    def __init__(self, pk):
        self.pk = pk
        self.s1 = None

    def commit(self, messages, zkp=False):
        """
        If zkp parameter is set to True, prepares a pedersen commitment to the set of messages to be signed and a non-interactive proof of correct construction.
        Else, simply constructs the product of the attributes.
        Packs the product/commitment and the optional proof in a UserCommitmentMessage object.
        """
        lhs = self.pk.generators[0].group.wsum(
            messages, self.pk.generators[2 : len(messages) + 2]
        )
        NIproof = None
        if zkp:
            self.s1 = self.pk.generators[0].group.order().random()
            lhs = self.s1 * self.pk.generators[1] + lhs
            # define secret names as s' m1 m2 ...mL
            names = [Secret() for _ in range(len(messages) + 1)]
            secrets = [self.s1] + messages
            rhs = wsum_secrets(names, self.pk.generators[1 : len(messages) + 2])
            pedersen_proof = DLRepProof(lhs, rhs)
            NIproof = pedersen_proof.prove(dict(zip(names, secrets)))
        return UserCommitmentMessage(lhs, NIproof)

    def obtain_signature(self, presignature):
        """
        Updates the received presignature into a complete signature.
        s1 is the part of the signature blinding factor which is on the user side.
        """
        if self.s1 is None:
            new_s = presignature.s
        else:
            new_s = presignature.s + self.s1
        return Signature(presignature.A, presignature.e, new_s)


class KeyPair:
    """
    Packs a public key with its private key and a list of canonical bases to use in proofs.
    """

    def __init__(self, bilinearpair, length):
        """
        :param bilinearpair: Of type BilinearGroupPair, featuring a G1 and a G2 group from which are drawn the g_is and h0.
        :param length: An upperbound on the number of generators needed to compute the proof. Should be at least 2 + the number of messages.
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
    """
    An abstraction for a public key.
    """

    def __init__(self, w, generators, h0):
        """
        Initializes the attributes and precomputes the group pairings.
        :param w: The public key value.
        :param generators: the G1 generators to use in proofs. Length should be at least 2 + number of messages.
        """
        self.w = w
        self.generators = generators
        self.h0 = h0
        self.gen_pairs = [g.pair(self.h0) for g in self.generators]


class SecretKey:
    def __init__(self, value, keypair):
        self.generators = keypair.generators
        self.h0 = keypair.h0
        self.gamma = value

    def sign(self, lhs):
        """
        Signs a committed message (typically a product, blind or not) ie returns A,e,s2 such that A = (g0 + s2*g1 + Cm) * 1/e+gamma
        If the product was blinded by the user's s1 secret value, user has to update the signature.
        """
        pedersen_product = lhs
        e = self.h0.group.order().random()
        s2 = self.h0.group.order().random()
        prod = self.generators[0] + s2 * self.generators[1] + pedersen_product
        A = (self.gamma + e).mod_inverse(self.h0.group.order()) * prod
        return Signature(A, e, s2)


class SignatureProof(BaseProof):
    """
    Proof of knowledge of a (A,e,s) signature over a set (known length) of (hidden) messages.
    """

    def __init__(self, secret_vars, pk, signature=None, binding=True):
        """
        Instantiates a Signature Proof which is an augmented version of AndProof allowing to access additional parameters.
        If the object is used for proving, it requires a signature argument.
        If binding keyord argument is set to True, the constructor will parse the two first elements of secret_vars as the Secret variables for the e and s attributes of the signature.
        Else, will internally declare its own.
        """
        self.ProverClass, self.VerifierClass = SignatureProver, SignatureVerifier
        self.pk = pk
        self.precommitment_size = 2
        if not binding:
            # We add two Secret slots for e and s if necessary
            secret_vars = [Secret(), Secret()] + secret_vars
        # We need L+1 generators for L messages. secret_vars are messages plus 'e' and 's'
        self.generators = pk.generators[: len(secret_vars)]
        self.aliases = [Secret(), Secret(), Secret(), Secret()]
        self.signature = signature
        self.constructed_proof = None
        # Below is boilerplate
        self.secret_vars = secret_vars
        if signature is not None:
            # Digest the signature parameters
            self.secret_vars[0].value = signature.e
            self.secret_vars[1].value = signature.s
        self.simulation = False

    def build_constructed_proof(self, precommitment):
        """
        A template for the proof of knowledge of a signature pi5 detailed on page 7 of the following paper : https://eprint.iacr.org/2008/136.pdf
        :param precommitment: the A1 and A2 parameters which depend on the secret signature and the Prover's randomness.
        """
        self.precommitment = precommitment
        self.A1, self.A2 = precommitment[0], precommitment[1]
        g0, g1, g2 = self.generators[0], self.generators[1], self.generators[2]
        dl1 = DLRepProof(self.A1, self.aliases[0] * g1 + self.aliases[1] * g2)
        dl2 = DLRepProof(
            g0.group.infinite(),
            self.aliases[2] * g1
            + self.aliases[3] * g2
            + self.secret_vars[0] * (-1 * self.A1),
        )
        self.pair_lhs = self.A2.pair(self.pk.w) + (-1 * self.pk.gen_pairs[0])
        generators = [
            -1 * (self.A2.pair(self.pk.h0)),
            self.generators[2].pair(self.pk.w),
            self.pk.gen_pairs[2],
        ]
        generators.extend(self.pk.gen_pairs[1 : len(self.generators)])
        # Build secret names [e, r1, delta1, s, m_i]
        new_secret_vars = (
            self.secret_vars[:1]
            + [self.aliases[0], self.aliases[2]]
            + self.secret_vars[1:]
        )
        pairings_proof = DLRepProof(
            self.pair_lhs, wsum_secrets(new_secret_vars, generators)
        )
        self.constructed_proof = AndProof(dl1, dl2, pairings_proof)
        self.constructed_proof.lhs = [
            subp.lhs for subp in self.constructed_proof.subproofs
        ]
        return self.constructed_proof


class SignatureProver(BaseProver):
    def precommit(self):
        """
        Generates the lacking information to construct a complete proof and returns it.
        At the same time, triggers the said proof construction for self and self.proof.
        After this function returns, the current prover is able to commit.
        Returned value is to be processed on the verifier side by verifier.process_precommitment( )
        """
        if self.proof.signature is None:
            raise Exception("No signature given!")
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
        self.process_precommitment(new_secrets)
        return self.precommitment


class SignatureVerifier(BaseVerifier):
    pass
