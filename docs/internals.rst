How it works
------------

This compiler will basically help you instantiate a *Prover* and a
*Verifier* object and make them talk (in the case of an interactive
proof). If the proof is a conjunction of subproofs, a global *challenge*
and global *randomizers* are shared (i.e the subproofs are **not** run
independently from each other). The sigma protocol (interactive) is the
following :

**Initial state** : the Prover and the Verifier share some "public
information", namely - an EcGroup (elliptic curve group, see petlib)
along with a set of generators of this group - the left-hand-side value
of the claim i.e the value for which we want to prove knowledge of
certain properties/decomposition - the syntax of the claim including the
pseudonyms of the secrets

The interaction then is :

                                                          Prover -----
commitment ---> Verifier

                                                          Prover <-----
challenge ------ Verifier

                                                          Prover ------
response -----> Verifier

After which the Verifier locally *verifies* i.e recomputes a
pseudo-commitment from the challenge and the responses, and compares it
to the received commitment.

In the case of a **non-interactive (NI) proof** the Prover - commits -
generates a deterministic challenge by hashing the commitment and all
the public information - responds as if this challenge had been sent by
a Verifier - outputs the challenge and the response.

A verifier can then compute the pseudo-commitment, hash it with the
public information and assert he indeed obtains the challenge. Note that
this verification relies on cryptographic hash function properties : it
is very unlikely to find R' such that hash(R' + *fixed\_string* ) is
equal to hash(R + *fixed\_string*), i.e if a pseudo-commitment is indeed
a pre-image of the challenge, it is the actual commitment almost surely.

If the proof uses a precommitment, it is generated and processed as a
preliminary round before generating and processing the commitment.

A look at the variables
^^^^^^^^^^^^^^^^^^^^^^^

-  The ``challenge`` is common to a whole protocol. In the case of the
   Or Proof, subchallenges are drawn i.e each subproof runs (simulated
   or not) with its own challenge. > This explains the constraint about
   reoccuring secrets in and out of an Or statement : we know a
   malicious Verifier can retrieve a secret which appear under several
   challenges and a unique commitment. A solution is to change the
   statement syntax into a canonical form, where the Or are on top of
   the tree.
-  The ``randomizers`` are the random values used to produce
   commitments. They are paired with the secrets, to ensure that a
   reoccuring secret will produce identical responses. If there are N
   secrets of M distinct values, there are M distinct randomizers.
-  The ``responses`` are ordered as the secrets were ordered : for N
   secrets, there are N responses.

Precommitments
^^^^^^^^^^^^^^

In the case of the ``DLRepNotEqualProof`` and ``SignatureProof``, we
make use of precommitments i.e parameters which are not known at the
proof instantiation and are computed by the proving side. Therefore,
they have to be sent explicitly in a preliminary round for interactive
protocols, and as an additional attribute in non-interactive or
simulation transcripts.

The internal structure of these two proof classes is as follows: - The
proof is built and its attributes set, but cannot run most methods -
Upon processing of the precommitment, a separate and complete proof is
constructed inside the main proof - All usual methods are redirected to
this internal constructed proof.

The ``Prover`` and ``Verifier`` work in the same way, embedding a
``constructed_prover`` (resp ``constructed_verifier``).

[1] : J. Camenisch and M. Stadler, “Proof systems for general statements
about discrete logarithms,” Tech. rep. 260, Mar. 1997

[2] : R. Henry and I. Goldberg, “Thinking inside the BLAC box: smarter
protocols for faster anonymous blacklisting,” in Proceedings of the 12th
ACM workshop on Workshop on privacy in the electronic soci- ety. ACM,
2013, pp. 71–82.

[3] : M. H. Au, W. Susilo, and Y. Mu, “Constant-size dynamic k-TAA,” in
International Conference on Security and Cryptography for Networks.
Springer, 2006, pp. 111–125.

[4] D. Bernhard, O. Pereira, and B. Warinschi, “How not to prove
yourself: Pitfalls of the Fiat-Shamir heuristic and applications to
Helios,” in International Conference on the Theory and Application of
Cryptology and Information Security. Springer, 2012, pp. 626–643.
