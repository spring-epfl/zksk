"""
ZK proof of knowledge of a BBS+ signature.

This proof can be used to build blacklistable anonymous credential schemes.

See "`Constant-Size Dynamic k-TAA`_" by Au et al., 2008 for the details.

.. _`Constant-Size Dynamic k-TAA`:
   https://eprint.iacr.org/2008/136.pdf

"""

import attr

from zksk.expr import Secret, wsum_secrets
from zksk.extended import ExtendedProofStmt
from zksk.composition import AndProofStmt
from zksk.primitives.dlrep import DLRep
from zksk.utils import make_generators


@attr.s
class BBSPlusSignature:
    """
    BBS+ signature.
    """

    A = attr.ib()
    e = attr.ib()
    s = attr.ib()

    def verify_signature(self, pk, messages):
        """
        Verify the validity of the signature w.r.t the given public key and set of messages.
        """
        generators = pk.generators[: len(messages) + 2]
        product = generators[0] + generators[0].group.wsum(
            ([self.s] + messages), generators[1:]
        )
        return self.A.pair(pk.w + self.e * pk.h0) == product.pair(pk.h0)


@attr.s
class UserCommitmentMessage:
    """
    Embed the product to be pre-signed by the issuer.

    If blinded by a user's Pedersen commitment, a NI proof is also specified.
    """

    com_message = attr.ib()
    com_nizk_proof = attr.ib(default=None)

    def verify_blinding(self, pk):
        """
        Verify the NIZK proof for Pedersen commitment.
        """
        if self.com_nizk_proof is None:
            raise ValueError("No proof to verify")

        # TODO: Extract into a separate ExtendedProofStmt.
        lhs = self.com_message
        generators = pk.generators[1 : len(self.com_nizk_proof.responses) + 1]
        secret_vars = [Secret() for _ in self.com_nizk_proof.responses]
        proof = DLRep(lhs, wsum_secrets(secret_vars, generators))

        return proof.verify(self.com_nizk_proof)


class BBSPlusSignatureCreator:
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
        Construct the product of messages and optionaly a Pedersen commitment and its proof.

        Args:
            messages: Messages (attributes) to commit to
            zkp (bool): Whether to construct a Pedersen commitment and proof the knowledge of the
                messages for this commitment.

        Returns:
            :py:class:`UserCommitmentMessage`: user's packed commitment.
        """
        lhs = self.pk.generators[0].group.wsum(
            messages, self.pk.generators[2 : len(messages) + 2]
        )
        com_nizk_proof = None
        if zkp:
            self.s1 = self.pk.generators[0].group.order().random()
            lhs = self.s1 * self.pk.generators[1] + lhs

            # TODO: Extract into a separate ExtendedProofStmt.
            secret_vars = [Secret() for _ in range(len(messages) + 1)]
            secrets = [self.s1] + messages
            rhs = wsum_secrets(secret_vars, self.pk.generators[1 : len(messages) + 2])
            com_stmt = DLRep(lhs, rhs)
            com_nizk_proof = com_stmt.prove(
                {s: v for s, v in zip(secret_vars, secrets)}
            )

        return UserCommitmentMessage(com_message=lhs, com_nizk_proof=com_nizk_proof)

    def obtain_signature(self, presignature):
        """
        Make a complete signature from the received pre-signature.

        Args:
            presignature (:py:class:`BBSPlusSignature`): presignature

        Returns:
            :py:class:`BBSPlusSignature`: Signature.
        """

        # s1 is the part of the signature blinding factor which is on the user side.
        if self.s1 is None:
            new_s = presignature.s
        else:
            new_s = presignature.s + self.s1
        return BBSPlusSignature(A=presignature.A, e=presignature.e, s=new_s)


@attr.s
class BBSPlusKeypair:
    """
    A public-private key pair, along with a list of canonical bases to use in proofs.
    """

    generators = attr.ib()
    h0 = attr.ib()
    sk = attr.ib()
    pk = attr.ib()

    @staticmethod
    def generate(bilinear_pair, num_generators):
        """
        Generate a keypair.

        Args:
            bilinear_pair (:py:class:`pairings.BilinearGroupPair`): Bilinear group pair.
            num_generators: Upper bound on the number of generators needed to compute the proof.
                Should be at least `2 + the number of messages`.

        Returns:
            :py:class:`BBSPlusKeypair`: Keypair.
        """
        # TODO: Check if this +2 is not redundant.
        generators = make_generators(num_generators + 2, group=bilinear_pair.G1)
        h0 = bilinear_pair.G2.generator()
        sk = BBSPlusSecretKey(
            gamma=bilinear_pair.G1.order().random(), generators=generators, h0=h0,
        )
        pk = BBSPlusPublicKey(w=sk.gamma * h0, generators=generators, h0=h0)
        return BBSPlusKeypair(generators=generators, h0=h0, sk=sk, pk=pk)
        # self.sk.pk = self.pk


@attr.s
class BBSPlusPublicKey:
    """
    BBS+ public key.

    Automatically pre-computes the generator pairings :math:`e(g_i, h_0)`.
    """

    w = attr.ib()
    h0 = attr.ib()
    generators = attr.ib()

    def __attrs_post_init__(self):
        """Pre-compute the group pairings."""
        self.gen_pairs = [g.pair(self.h0) for g in self.generators]


@attr.s
class BBSPlusSecretKey:
    """
    BBS+ private key.
    """

    h0 = attr.ib()
    gamma = attr.ib()
    generators = attr.ib()

    def sign(self, lhs):
        r"""
        Sign a committed message (typically a product, blinded or not),

        A signature is :math:`(A, e, s_2)` such that
        :math:`A = (g_0 + s_2 g_1 + C_m) \cdot \frac{1}{e+\gamma}`.

        If the product was blinded by the user's :math:`s_1` secret value, user has to update the
        signature.
        """
        pedersen_product = lhs
        e = self.h0.group.order().random()
        s2 = self.h0.group.order().random()
        prod = self.generators[0] + s2 * self.generators[1] + pedersen_product
        A = (self.gamma + e).mod_inverse(self.h0.group.order()) * prod
        return BBSPlusSignature(A=A, e=e, s=s2)


class BBSPlusSignatureStmt(ExtendedProofStmt):
    """
    Proof of knowledge of a BBS+ signature over a set of (hidden) messages.

    The proof can be made `binding`: bind the secrets to another proof. If the proof is not binding,
    it is not possible to assert that the same secrets were used in any other proof.

    Args:
        secret_vars: Secret variables.
            If binding, the two first elements of secret_vars as the Secret variables for the ``e``
            and ``s`` attributes of the signature.
        pk (:py:class:`BBSPlusPublicKey`): Public key.
        signature (:py:class:`BBSPlusSignature`): Signature. Required if used for proving.
        binding (bool): Whether the signature is binding.
        simulated (bool): If this proof is a part of an or-proof: whether it should be simulated.
    """

    def __init__(self, secret_vars, pk, signature=None, binding=True, simulated=False):
        self.pk = pk
        self.signature = signature
        if not binding:
            # We add two Secret slots for e and s if necessary
            secret_vars = [Secret(), Secret()] + secret_vars

        # We need L+1 generators for L messages. secret_vars are messages plus 'e' and 's'
        self.bases = pk.generators[: len(secret_vars)]
        self.order = self.bases[0].group.order()

        # The prover will compute the following secrets:
        self.r1, self.r2, self.delta1, self.delta2 = (
            Secret(),
            Secret(),
            Secret(),
            Secret(),
        )

        # Below is boilerplate
        self.secret_vars = secret_vars
        if signature is not None:
            # Digest the signature parameters
            self.secret_vars[0].value = signature.e
            self.secret_vars[1].value = signature.s

        self.set_simulated(simulated)

    def precommit(self):
        """
        Generate the lacking information to construct a complete proof.

        The precommitment comprises the ``A1`` and ``A2`` commitments that depend on the secret
        signature and the Prover's randomness.
        """
        if self.signature is None:
            raise ValueException("No signature given!")

        # Compute auxiliary commitments A1,A2 as mentioned in the paper. Needs two random values r1,r2 and associated delta1,delta2
        # Set true value to computed secrets
        r1, r2 = self.order.random(), self.order.random()
        self.r1.value, self.r2.value = r1, r2
        self.delta1.value = r1 * self.signature.e % self.order
        self.delta2.value = r2 * self.signature.e % self.order

        precommitment = {}
        precommitment["A1"] = r1 * self.bases[1] + r2 * self.bases[2]
        precommitment["A2"] = r1 * self.bases[2] + self.signature.A

        return precommitment

    def construct_stmt(self, precommitment):
        r"""
        Proof of knowledge of a signature.

        This is an implementation of a proof :math:`\Pi_5` detailed on page 7 of the `Constant-Size
        Dynamick-TAA` paper.
        """

        self.A1, self.A2 = precommitment["A1"], precommitment["A2"]
        g0, g1, g2 = self.bases[0], self.bases[1], self.bases[2]

        dl1 = DLRep(self.A1, self.r1 * g1 + self.r2 * g2)
        dl2 = DLRep(
            g0.group.infinite(),
            self.delta1 * g1 + self.delta2 * g2 + self.secret_vars[0] * (-1 * self.A1),
        )

        self.pair_lhs = self.A2.pair(self.pk.w) + (-1 * self.pk.gen_pairs[0])
        bases = [
            -1 * (self.A2.pair(self.pk.h0)),
            self.bases[2].pair(self.pk.w),
            self.pk.gen_pairs[2],
        ]
        bases.extend(self.pk.gen_pairs[1 : len(self.bases)])

        # Build secret names [e, r1, delta1, s, m_i]
        new_secret_vars = (
            self.secret_vars[:1] + [self.r1, self.delta1] + self.secret_vars[1:]
        )
        pairings_stmt = DLRep(self.pair_lhs, wsum_secrets(new_secret_vars, bases))

        constructed_stmt = AndProofStmt(dl1, dl2, pairings_stmt)
        constructed_stmt.lhs = [p.lhs for p in constructed_stmt.subproofs]
        return constructed_stmt

    def simulate_precommit(self):
        """
        Draw :math:`A_1`, :math:`A_2` at random.
        """
        group = self.bases[0].group

        precommitment = {}
        precommitment["A1"] = group.order().random() * group.generator()
        precommitment["A2"] = group.order().random() * group.generator()
        return precommitment
