"""
ZK proof for a BBS+ signature.
"""

# TODO: Fix the docs.


from zksk.expr import Secret, wsum_secrets
from zksk.composition import ExtendedProofStmt, AndProofStmt
from zksk.primitives.dlrep import DLRep


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
    Embed the product to be pre-signed by the issuer.

    If blinded by a user's Pedersen commitment, a NI proof is also specified.
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
        proof = DLRep(lhs, wsum_secrets(secret_vars, generators))
        return proof.verify(self.NIproof)


class SignatureCreator:
    """
    Pre-signed product along with a NIZK proof of correct construction.

    Args:
        pk (PublicKey): Public key.
    """

    def __init__(self, pk):
        self.pk = pk
        self.s1 = None

    def commit(self, messages, zkp=True):
        """
        If ``zkp`` parameter is set to True, prepares a Pedersen commitment to the set of messages to be
        signed and a non-interactive proof of correct construction.  Otherwise, simply construct the
        product of the attributes.

        Pack the product/commitment and the optional proof in a :py:class:`UserCommitmentMessage` object.
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
            pedersen_proof = DLRep(lhs, rhs)
            NIproof = pedersen_proof.prove(dict(zip(names, secrets)))
        return UserCommitmentMessage(lhs, NIproof)

    def obtain_signature(self, presignature):
        """Update the received pre-signature into a complete signature."""
        # s1 is the part of the signature blinding factor which is on the user side.
        if self.s1 is None:
            new_s = presignature.s
        else:
            new_s = presignature.s + self.s1
        return Signature(presignature.A, presignature.e, new_s)


class Keypair:
    """
    A public-private key pair, along with a list of canonical bases to use in proofs.

    Args
        bilinearpair (:py:class:`pairings.BilinearGroupPair`): Bilinear group pair.
        length: Upper bound on the number of generators needed to compute the proof.
            Should be at least 2 + the number of messages.
    """

    def __init__(self, bilinearpair, length):
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
    """Public key"""

    def __init__(self, w, generators, h0):
        """
        Initializes the attributes and pre-computes the group pairings.

        Args
            w: Value of the public key
            generators: the :math:`\mathbb{G}_1` generators to use in proofs. Length should be at
                least 2 + number of messages.
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
        Sign a committed message (typically a product, blinded or not), i.e. returns (A,e,s2) such
        that A = (g0 + s2*g1 + Cm) * 1/e+gamma If the product was blinded by the user's s1 secret
        value, user has to update the signature.

        TODO: Fix math in the docstring.
        """
        pedersen_product = lhs
        e = self.h0.group.order().random()
        s2 = self.h0.group.order().random()
        prod = self.generators[0] + s2 * self.generators[1] + pedersen_product
        A = (self.gamma + e).mod_inverse(self.h0.group.order()) * prod
        return Signature(A, e, s2)


class SignatureStmt(ExtendedProofStmt):
    """
    Proof of knowledge of a (A,e,s) signature over a set (known length) of (hidden) messages.
    """

    def __init__(self, secret_vars, pk, signature=None, binding=True):
        """
        Instantiates a Signature Proof which is an augmented version of AndProofStmt allowing to access additional parameters.
        If the object is used for proving, it requires a signature argument.
        If binding keyord argument is set to True, the constructor will parse the two first elements of secret_vars as the Secret variables for the e and s attributes of the signature.
        Else, will internally declare its own.
        TODO: secret_vars -> msg?
        """

        self.pk = pk
        self.signature = signature
        if not binding:
            # We add two Secret slots for e and s if necessary
            secret_vars = [Secret(), Secret()] + secret_vars

        # We need L+1 generators for L messages. secret_vars are messages plus 'e' and 's'
        self.generators = pk.generators[: len(secret_vars)]
        self.constructed_proof = None

        # The prover will compute the following secrets:
        self.r1, self.r2, self.delta1, self.delta2 = Secret(), Secret(), Secret(), Secret()

        # Below is boilerplate
        # TODO: handle secret_vars in super constructor
        self.secret_vars = secret_vars
        if signature is not None:
            # Digest the signature parameters
            self.secret_vars[0].value = signature.e
            self.secret_vars[1].value = signature.s
        self.simulation = False

    def precommit(self):
        """
        Generates the lacking information to construct a complete proof and returns it.
        At the same time, triggers the said proof construction for self and self.proof.
        After this function returns, the current prover is able to commit.
        Returned value is to be processed on the verifier side by verifier.process_precommitment( )
        """
        if self.signature is None:
            raise Exception("No signature given!")
        # Compute auxiliary commitments A1,A2 as mentioned in the paper. Needs two random values r1,r2 and associated delta1,delta2

        # Set true value to computed secrets
        order = self.generators[0].group.order()
        r1, r2 = order.random(), order.random()
        self.r1.value, self.r2.value = r1, r2
        self.delta1.value = r1 * self.signature.e % order
        self.delta2.value = r2 * self.signature.e % order

        precommitment = {}
        precommitment["A1"] = r1 * self.generators[1] + r2 * self.generators[2]
        precommitment["A2"] = r1 * self.generators[2] + self.signature.A

        return precommitment

    def construct_proof(self, precommitment):
        """
        A template for the proof of knowledge of a signature pi5 detailed on page 7 of the following paper : https://eprint.iacr.org/2008/136.pdf
        :param precommitment: the A1 and A2 parameters which depend on the secret signature and the Prover's randomness.
        """
        self.A1, self.A2 = precommitment["A1"], precommitment["A2"]
        g0, g1, g2 = self.generators[0], self.generators[1], self.generators[2]

        dl1 = DLRep(self.A1, self.r1 * g1 + self.r2 * g2)
        dl2 = DLRep(
            g0.group.infinite(),
            self.delta1 * g1
            + self.delta2 * g2
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
            + [self.r1, self.delta1]
            + self.secret_vars[1:]
        )
        pairings_proof = DLRep(
            self.pair_lhs, wsum_secrets(new_secret_vars, generators)
        )

        self.constructed_proof = AndProofStmt(dl1, dl2, pairings_proof)
        self.constructed_proof.lhs = [
            subp.lhs for subp in self.constructed_proof.subproofs
        ]
        return self.constructed_proof

    def simulate_precommit(self):
        """
        Draws A1, A2 at random.
        """
        group = self.generators[0].group

        precommitment = {}
        precommitment["A1"] = group.order().random() * group.generator()
        precommitment["A2"] = group.order().random() * group.generator()
        return precommitment

