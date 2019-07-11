User Guide
----------

This page will outline possible use cases of the libraries and walk through several examples.

Notation and syntax
^^^^^^^^^^^^^^^^^^^
The computations are done within cyclic groups induced by elliptic curves. When we use mathematical
expressions, we write points in those groups in uppercase, and scalar numbers in lowercase. We write
the group operation additively, i.e., :math:`+` denotes the group operation.


.. Note ::
   In code, we follow the Python conventions and write both groups and group elements in lowercase.

.. Tip ::
   We use the petlib library for working with elliptic curves. We advise you to read `petlib's
   documentation page <https://petlib.readthedocs.io/en/latest/>`__. 

We use Camenisch-Stadler notation [CS97]_ for zero-knowledge proofs. A proof of knowledge of a
secret integer :math:`x` such that :math:`Y = x G` for some group element :math:`G` is denoted as
follows:

.. math ::
   PK \{ x : Y = x G \}


Overview 
^^^^^^^^
This library enables zero-knowledge proofs that are composed of the following blocks:

- **Discrete Logarithm representation.** A proof of knowledge of secret integers :math:`x_i`,
  such that :math:`Y` can be written as :math:`Y = \sum_i x_i G_i`:

  .. math ::
   
   PK \{ (x_0, x_1, ..., x_n): Y = x_0 G_0 + x_1 G_1 + ... + x_n G_n \}

- **And** conjunctions of other proofs.
- **Or** conjunctions of other proofs.
- Your own custom proof.

Apart from DLRep, we include some other useful primitives in the library distribution:

- **Inequality of discrete logarithms,** with one of the logarithms that must be known. This
  protocol is drawn from the BLAC scheme [HG13]_.
- **BBS+ signature proof** to prove knowledge of a signature over a set of attribute-based
  credentials [ASM06]_.

The library supports three different modes of proves:

- **Interactive** proof. You can get the messages that need to be transmitted between a prover and
  verifier, along with functionality to verify those messages.
- **Non-interactive** proof through Fiat-Shamir heuristic. 
- Simulation.


A simple interactive proof
^^^^^^^^^^^^^^^^^^^^^^^^^^

We want to build a proof for the following statement:

.. math ::

   PK \{ (x_1, x_2): Y = x_0 G_1 + x_1 G_1 \}

.. Tip ::
   
   The next steps use petlib's big number and elliptic curve syntax (``petlib.bn``,
   ``petlib.ec``) syntax. We encourage you to get familiar with them on `petlib's
   documentation page <https://petlib.readthedocs.io/en/latest/>`__.

First, we set up the group elements: elliptic curve points :math:`G_i`, and the secrets :math:`x_i`.

.. literalinclude:: ../examples/simple_dlrep.py
   :lines: 15-21

Then, we can create a proof like this:

.. literalinclude:: ../examples/simple_dlrep.py
   :lines: 25-29

In this section, we build an interactive proof. For that, we are going to instantiate a
:py:class:`Verifier` and a :py:class:`Prover`. In a realistic setup, one would not get both from the
same proof object (typically the prover and the verifier sides are not running on the same machine),
but the result is the same.

.. literalinclude:: ../examples/simple_dlrep.py
   :lines: 32-34

The secret values can also be specified at this step instead of earlier. See the `Secrets
<#Secrets>`__ section.

The Prover and Verifier are going to interact using a sigma protocol, ending with the verifier
accepting or rejecting the proof.

.. literalinclude:: ../examples/simple_dlrep.py
   :lines: 36-39

.. ATTENTION::
   For more complicated proofs, one more step is necessary at the
   beginning of the exchange. See the next sections.

Secrets
^^^^^^^
A :py:class:`Secret` objects represent the secret integer in a zero-knowledge proof. A secret has
a name, and a value, but both can be empty. It can be constructed without any arguments:

.. code:: python

   x = Secret()

In this case, a name is assigned automatically.

To provide a value, construct a secret like this:

.. code:: python

   x = Secret(value=42)

If a secret contains a value, the proof will be able to use it, otherwise a prover will wait for a
dictionary that maps secrets to values. The following two equivalent snippets illustrate this:

.. code:: python

   x = Secret(value=4)
   proof = DLRepProof(y, x * G)
   prover = proof.get_prover()

.. code:: python

   x = Secret()
   proof = DLRepProof(y, x * G)
   prover = proof.get_prover({x: 4})

Composing proofs with "and"
^^^^^^^^^^^^^^^^^^^^^^^^^^^
We show how to build an "and"-composition of two discrete logarithm proofs:

.. math::
   PK \{ (x_0, x_1, x_2): \underbrace{Y_0 = x_0 G_0 + x_1 G_1}_{\text{First statement}}
      \land \underbrace{Y_1 = x_1 G_2 + x_2 G_3}_{\text{Second statement}} \}

As before, we initialize the points :math:`G_i` and the secrets :math:`x_i`.

.. literalinclude:: ../examples/andproof.py
   :lines: 14-26

Then, we can create the "and"-proof like this:

.. literalinclude:: ../examples/andproof.py
   :lines: 30-36

This syntax enables us to almost copy the mathematical expression of the proof in the
Camenisch-Stadler notation.

We can also instantiate subproofs separately and pass them to the
:py:class:`zkbuilder.composition.AndProof`. In fact, the above is just a simplified way of writing
the following:

.. literalinclude:: ../examples/andproof.py
   :lines: 39-42

The two ways to construct the AndProof are equivalent and work with an arbitrary number of
parameters.

Composing proofs takes into consideration the reoccuring secrets. The following are two **not**
equivalent snippets:

.. literalinclude:: ../examples/andproof.py
   :lines: 58-60

.. literalinclude:: ../examples/andproof.py
   :lines: 62-63

They are not equivalent as the second one will verify that the same
:py:class:`zkbuilder.expr.Secret` object is used. 

Running the protocol is the same as in the previous example.

Composing proofs with "or"
^^^^^^^^^^^^^^^^^^^^^^^^^^

This time we want to create an Or Proof of two discrete logarithms
proofs:

PK{ (x1, x2): Y1 = x1 \* G1    \|\|   Y2 = x2 \* G2 }

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
    keypair = Keypair(mG, NMAX) 

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


References
^^^^^^^^^^

.. [CS97] J. Camenisch and M. Stadler, "Proof systems for general statements
   about discrete logarithms," Tech. rep. 260, Mar. 1997
.. [HG13] R. Henry and I. Goldberg, "Thinking inside the BLAC box: smarter
   protocols for faster anonymous blacklisting," in Proceedings of the 12th
   ACM workshop on Workshop on privacy in the electronic society. ACM,
   2013, pp. 71–82.
.. [ASM06] M. H. Au, W. Susilo, and Y. Mu, "Constant-size dynamic k-TAA," in
   International Conference on Security and Cryptography for Networks.
   Springer, 2006, pp. 111–125.
