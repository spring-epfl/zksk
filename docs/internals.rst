How It Works
------------

TODO: This is a mess.

Sigma-procotols
^^^^^^^^^^^^^^^

We recall the concept of a *Sigma-protocol* for zero-knowledge proofs. It is a protocol between a
*Prover* and a *Verifier*.

Before the protocol starts the Prover and the Verifier share some "public information", namely an
elliptic curve group along with a set of generators in this group, and the values for which we want
to prove certain properties/decomposition.

The interaction in the Sigma-protocol consists of three steps:
1. Prover → Verifier: sends *commitment*
2. Prover ← Verifier: sends *challenge*
3. Prover → Verifier: sends *response*.

After the interaction is completed, the Verifier locally *verifies*, i.e., recomputes a
pseudo-commitment from the challenge and the responses, and compares it to the received commitment.


Normally, a commitment is produced using *randomizers*, one randomizer for each secret.

Composition
^^^^^^^^^^^

If the proof is a composition of subproofs, a global challenge and global randomizers are shared
(i.e the subproofs are **not** run independently from each other). 

- The ``challenge`` is common to a whole protocol. In the case of the or-proof, sub-challenges are
  drawn, i.e., each subproof runs (simulated or not) with its own challenge. 
  This explains the constraint about reoccuring secrets in and out of an or-proof: a 
  malicious Verifier can retrieve a secret which appears under several challenges and a unique
  commitment. A solution is to change the statement syntax into a canonical form, where the or is 
  on top of the tree.
- The ``randomizers`` are the random values used to produce commitments. They are paired with the
  secrets, to ensure that a reoccuring secret produces identical responses. If there are :math:`n`
  secrets of :math:`m` distinct values, there are :math:`m` distinct randomizers.
- The ``responses`` are ordered as the secrets were ordered: for :math:`n` secrets, there are
  :math:`n` responses.

"Extended proofs"
^^^^^^^^^^^^^^^^^

An :py:class:`base.ExtendedProof` makes use of precommitments, i.e., parameters which are not known
at the proof instantiation and are computed by the proving side.  Therefore, they have to be sent
explicitly in a preliminary round for interactive protocols, and as an additional attribute in
non-interactive or simulation transcripts.

The protocol of an extended proof is as follows:

1. he proof is built and its attributes are set, but cannot run most methods
2. Upon processing of the precommitment, a separate and complete regular proof
   (:py:class:`base.Proof`) is constructed inside the extended proof.
3. All the usual methods are redirected to this internal constructed proof.

The ``Prover`` and ``Verifier`` work in the same way, embedding a ``constructed_prover`` (resp
``constructed_verifier``).

Fiat-Shamir Heuristic
^^^^^^^^^^^^^^^^^^^^^

The library supports the non-interactive version of the proofs via the Fiat-Shamir heuristic. The
challenge hash contains the proof statement and all the bases, including (in the case of "extended
proofs") the precommitments. In particular, it embeds the left-hand-side of the proof statement for
security reasons [BPW12]_.

Reference
^^^^^^^^^

.. [BPW12] D. Bernhard, O. Pereira, and B. Warinschi, “How not to prove
   yourself: Pitfalls of the Fiat-Shamir heuristic and applications to
   Helios,” in International Conference on the Theory and Application of
   Cryptology and Information Security. Springer, 2012, pp. 626–643.
