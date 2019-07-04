Tutorial
========

User Guide
----------

    This section is about code examples and practice. If you want to
    read about what is going on, you can read the `How it
    works <#how-it-works>`__ section first.

    Important : the computations are done within cyclic groups induced
    by elliptic curves. Points of those groups are written in uppercase,
    scalar number in lowercase. We advise you to read `petlib's
    documentation page <https://petlib.readthedocs.io/en/latest/>`__.
    What we refer as *secrets* are a custom hashable objects embedding
    integers.

What you want to do
^^^^^^^^^^^^^^^^^^^

Build expressions using the following blocks (classes which all inherit
from a ``Proof`` primitive and thus can be composed) :

-  **Discrete Logarithm Representation (DLRep)** primitive to prove
   knowledge of integers ``x``\ i such that a base ``Y`` can be written
   as the product of ``Gi``\ ^\ ``xi`` with ``Gi`` known bases.
-  **DLRepNotEqual** primitive, to prove inequality of two discrete
   logarithms, one of which must be known
-  this protocol is drawn from the BLAC scheme [2].
-  **SignatureProof** primitive, to prove knowledge of a BBS+ signature
   over a set of credentials.
-  This protocol is drawn from the BBS+ scheme [3].
-  **And** conjunctions
-  **Or** conjunctions

Choose a proof mode among :

-  Interactive proof (local)
-  Non-interactive proof
-  Simulation

And output a proof transcript or in the case of an interactive proof a
couple Prover/Verifier which will execute a sigma protocol for your
proof.

Syntax and setup examples
~~~~~~~~~~~~~~~~~~~~~~~~~

An elementary interactive proof
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We want to build a proof for the following statement (using
[Camenisch-Stadler][1] notation) :

                                                              
        PK{ (x1, x2): Y = G1^x1 \* G2^x2 }

First, note that as ``*`` denotes a group operation, it is just a matter
of notation to replace it by ``+``, and to replace the ``^`` by a ``*``.
The above expression becomes

                                                              
        PK{ (x1, x2): Y = x1 \* G1 + x2 \* G2}

This is the syntax we will use from now on, to ensure compatibility with
the *petlib* library. > Warning : the next steps use petlib's BigNumber
and EllipticCurve (*petlib.bn*, *petlib.ec*) syntax. We encourage you to
get familiar with them `on petlib's documentation
page <https://petlib.readthedocs.io/en/latest/>`__.

Let's build the proof environment : we set the group elements (elliptic
curve points, the ``Gi``) and the secrets ``xi``.

.. code:: python

    G = EcGroup()
    g = G.generator()    # This sets up the group and a first generator 
    g1 = G.hash_to_point("An")      # Collecting various points in the group for the example 
    g2 = G.hash_to_point("Elementary")  
    g2 = G.hash_to_point("Proof")   
    g2 = 5 * g      
    g3 = 10 * g         

    x1 = Secret(value = 21)      # Preparing the secrets,
    x2 = Secret(value = 35)      # typically large petlib.bn.Bn 

Then creating a proof requires the following syntax:

.. code:: python

    from DLRep import *
    from Abstractions import * 

    y = x1.value * g1 + x2.value * g2   
                # Building the left-hand-side of the claim

    my_proof = DLRepProof(y, x1 * g1 + x2 * g2)
                # Statement mimics the proof mathematical expression

That's almost it for the setup ! Since we want an interactive proof, we
are going to instantiate a Verifier and a Prover objects from this
proof. In a realistic setup, one would not get both from the same proof
object (typically the prover and the verifier side would not even be
running on the same machine), but the result is the same.

To do that we just call :

.. code:: python

    prover = proof.get_prover()
    verifier = proof.get_verifier()

The secret values (here 21 and 35) can also be specified at this step
instead of earlier. See `Secrets <#Secrets>`__ section.

And now the fun begins
''''''''''''''''''''''

The Prover and Verifier are going to interact along a **sigma
protocol**, ending by the verifier accepting or rejecting the proof.

.. code:: python

    commitment = prover.commit()
    challenge = verifier.send_challenge(commitment)
    response = prover.compute_response(challenge)
    verifier.verify(response)

Done ! Caution: for more complicated proofs (DLRepNotEqual,
SignatureProof), one more step is necessary at the beginning of the
exchange. See the dedicated section.

Secrets
^^^^^^^

We use a ``Secret( )`` class constructor which will optonally embed a
value. The idea is to **declare** unique secrets and then use them. If
the secret contains a value the proof will be able to use it, otherwise
it will wait for a dictionary to get a prover object.

.. code:: python

    x = Secret(value=4)
    proof = DLRepProof(Y, x * G)
    prover = proof.get_prover()

    # Is equivalent to

    x = Secret()
    proof = DLRepProof(Y, x * G)
    prover = proof.get_prover({x:4})

A first composed proof
^^^^^^^^^^^^^^^^^^^^^^

We want to build the "And" of two Discrete Logarithms proofs:

                                            PK{ (x1, x2, x3): Y1 = x1 \*
G1 + x2 \* G2    &&   Y2 = x1 \* G3 + x3 \* G4 }

As before, we set the points ``Gi`` and the secrets ``xi``.

.. code:: python

    from DLRep import *
    from Abstractions import *

    G = EcGroup()           # Setup the group
    g1 = G.generator()              
    g2 = G.hash_to_point("2")   # Collecting various points for the example 
    g3 = G.hash_to_point("bananas")         

    x1 = Secret(value = 3)      
    x2 = Secret(value = 40)     # Declaring the secrets
    x3 = Secret(value = 12)
    x4 = Secret(value = 7)

Then creating the proof :

.. code:: python

    y1 = x1.value * g1 + x2.value * g2 # Building left-hand-sides of the claims
    y2 = x1.value * g3 + x3.value * g4

    and_proof = DLRepProof(y1, x1 * g1 + x2 * g2) 
            & DLRepProof(y2, x1 * g3 + x3 * g4)

This syntax allows you to almost copy the mathematical expression of the
proof in the Camenisch-Stadler notation. You can also instantiate
subproofs separately and pass them to the ``AndProof()`` constructor,
which the above syntax calls in fact for you :

.. code:: python

    proof_1 = DLRepProof(y1, x1 * g1 + x2 * g2)
    proof_2 = DLRepProof(y2, x1 * g3 + x3 * g4)

    and_proof = AndProof(proof1, proof2)

The two ways to construct the AndProof are equivalent and work with an
arbitrary number of parameters.

Note that composing proofs takes into consideration the reoccuring
secrets i.e

.. code:: python

    x1 = Secret(value = 4)
    x2 = Secret(value = 4)
    and_proof1 = DLRepProof(y1, x1 * g1) & DLRepProof(y2, x2 * g2)

and

.. code:: python

    and_proof2 = DLRepProof(y1, x1 * g1) & DLRepProof(y2, x1 * g2)  

are **not** equivalent since the second one will run verifications to
assert the same secret value (in fact, even the same ``Secret`` object
!) was used.

Our setup is done, the rest is the same protocol `as in the first
proof <#and-now-the-fun-begins>`__.

An other composed proof : Or block
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This time we want to create an Or Proof of two discrete logarithms
proofs:

                                                            PK{ (x1,
x2): Y1 = x1 \* G1    \|\|   Y2 = x2 \* G2 }

you would do the following to setup the proof (say the ``xi`` and ``Gi``
have been setup already similarly as above):

.. code:: python

    y1 = x1.value * g1
    y2 = x2.value * g2
    proof = DLRepProof(y1, x1 * g1) | DLRepProof(y2, x2 * g2)

Or use an ``OrProof()`` constructor exactly as for the And statement
seen above.

The rest is the same as above, that is you still have to create a Prover
and a Verifier by calling the ``get_prover()`` and ``get_verifier()``
methods of the Proof object. The OrProver will in fact be composed of
one legit subprover and run simulations for the other subproofs.

    Tip : You don't need to provide all the secret values for the Or
    Proof. The compiler will draw at random which subproof to compute,
    but first will chose only among those you provided all secrets for.

You might want to set yourself which subproofs you want to simulate, for
this just do (before retrieving the Prover, of course!)

.. code:: python

    proof.subproofs[i].simulation = True

Which will give this subproof probability 0 to be picked for the legit
computation. > When doing ``orp = pp1 | pp2``, it is copies of ``pp1``
and ``pp2`` which are used. Modifying the original objects would not do
anything so you have to modify the actual subproof.

Of course you can also compose Or and And !
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Say you want to write the following proof :

                                            PK{ (x1, x2, x3): (Y1 = x1
\* G1    \|\|   Y2 = x2 \* G2)    &&   Y3 = x3 \* G3 }

The setup would be

.. code:: python

    y1 = x1.value * g1
    y2 = x2.value * g2
    y3 = x3.value * g3
    proof = (DLRepProof(y1, x1 * g1) | DLRepProof(y2, x2 * g2)) 
            & DLRepProof(y3, x3 * g3)

Some special cases are forbidden !
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. You are not allowed to operate between elements of different group
   orders for now.

2. You want to ensure some properties about identical secrets. It
   implies that when reusing a secret :math:`x` with two different group
   points ``Ga``, ``Gb``, the groups induced by ``Ga`` and ``Gb``\ $
   must have the same order. This could cause `this
   proof <#a-first-composed-proof>`__ to fail !

3. You never want to instantiate a flawed proof, and the current
   architecture is too naive to rewrite for you a bad statement. In
   particular, no secret should appear at the same time in and out of an
   Or Proof. This forbids, for example

                                             PK{ (x1, x2): Y1 = x1 \* G1
   &&  ( Y2 = x2 \* G2    \|\|   Y3 = x1 \* G3 ) }

           because x1 appears in two incompatible places. See more in
`the theory part <#how-it-works>`__.

    | Don't mess with the syntax !
    | Proving non-interactively { Y = x1 \* G1 + x2 \* G2 } and
      verifying { Y = x2 \* G2 + x1 \* G1 } will fail as proofs generate
      and compare hashes of their string identifier, and are not clever
      enough to understand commutativity.

Using Non-interactive Proofs and Simulations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

NI proofs
'''''''''

Once you have built your proof with fully constructed Secret objects
(see `Secrets <#secrets>`__)

.. code:: python

    transcript = proof.prove()

If the secrets are not completely built at the proof instantiation, add
the dictionary as parameter. The returned object will be a
``NonInteractiveTranscript``, embedding a challenge, a list of
responses, a hash of the proof statement and optionnaly a precommitment.
It fits into

.. code:: python

    proof.verify(transcript) # Typically called from a separate instance of Proof

Which will verify the proof transcripts are the same, process the
precommitment if there is one, and verify the challenge and response are
consistent. The hash contains the proof statement and all the bases
including (if it applies) the precommitments. In particular, it embeds
the left-hand-side of the proof statement for security reasons [4].

Simulations
'''''''''''

Just like for non-interactive proofs (except now you don't need the
secret values!), just call

.. code:: python

    sim = proof.simulate()  # Optional argument: challenge to enforce

which returns a ``SimulationTranscript`` very much similar to a
``NonInteractiveTranscript``, but which will not be accepted by the
canonic verification method seen above.

An other primitive: Inequality of two discrete logarithms
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To prove knowledge of ``x`` such that Y1 = x \* G1 and Y2 != x \* G2.

The associated class is ``DLRepNotEqual`` and is constructed as follows,
for x = 12 for example:

.. code:: python

    x = Secret(value = 12)
    proof = DLRepNotEqual([Y1, G1], [Y2, G2], x)

    Due to the internal proof construction, this proof does not bind the
    secret value ``x`` by default. To enable this feature, the proof
    constructor has to be called with the optional parameter ``binding``
    set to ``True``).

Once the proof is constructed, the same methods as before
(``get_prover()``, ``get_verifier()``, ``prove()``, ``verify()``, etc.)
apply.

A complete protocol: the BBS+ scheme
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We provide a way to obtain blind signatures over a set of
messages/credentials, along with a ``SignatureProof`` primitive (to use
much like the ``DLRep`` seen before). > This protocol uses group
pairings as defined in bplib. The interface has been wrapped so the
pairings behave as usual EcPt (additive points) ##### Obtaining a
signature The idea is to request an issuer -- identified by a public key
``pk`` and a secret key ``sk`` -- to blindly sign a list of messages
``m_i``. The user will blind these attributes by a secret attribute
``s1``.

The resulting number is sent to the issuer along with a proof of correct
construction (a ``DLRepProof``).

.. code:: python

    # NMAX is an upperbound on the number of generators to be used
    mG = BilinearGroupPair()
    keypair = KeyPair(mG, NMAX) 

    # Construct a UserCommitment object embedding the blinded block and the proof of correct construction.
    creator = SignatureCreator(pk)
    usr_commitment = creator.commit(messages)

    # Get the blinded block signed by the issuer (through its secret key). It returns a (A, e, s) signature we then update by adding to s the value s1 drawn before.
    presignature = sk.sign(lhs.commitment_message)
    signature = creator.obtain_signature(presignature)

The final signature validity can be verified by calling

.. code:: python

    signature.verify(pk, messages)

and the issuer can verify the correct construction (step 2) with

.. code:: python

    usr_commitment.verify_blinding(pk)

Proving knowledge of a signature
''''''''''''''''''''''''''''''''

Once the user has the final signature, it can prove knowledge of it by
calling

.. code:: python

    e, s = Secret(value=signature.e), Secret(value=signature.s)
    messages = [Secret(value=m1)..., Secret(value=mn)]
    proof = SignatureProof([e, s, *messages], pk, signature)

The ``e`` and ``s`` Secret instances are necessary so the proof can bind
them to an other proof, e.g. in an ``And`` conjunction. If you do not
care about binding ``e`` and ``s`` to other proofs you can skip them,
only pass the messages and set a ``binding`` keyword argument to False.

.. code:: python

    messages = [Secret(value=m1)..., Secret(value=mn)]
    proof = SignatureProof(messages, pk, signature, binding=False)

The ``signature`` argument is required for the proving side. Of course,
the verifying side would call

.. code:: python

    e, s = Secret(), Secret()   # Omitted if not binding
    messages = [Secret()..., Secret()]
    proof = SignatureProof([e, s, *messages], pk)

From this Proof objects, one can run the usual methods ``get_prover()``,
``get_verifier()``, ``prove()``, ``verify()``, etc.

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

Tests and documentation
^^^^^^^^^^^^^^^^^^^^^^^

We built the tests using pytest. To launch the tests you can simply run

::

    python -m pytest

from the root directory of the project.

::

    bash create_pydoc.bash

Will create the directory ./documentation and generate all the
documentation in html format of the source code in ./compiler.

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
