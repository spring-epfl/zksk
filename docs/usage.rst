Basic Usage
-----------

This page will outline possible use cases of the library and walk through several examples.

Notation and Syntax
^^^^^^^^^^^^^^^^^^^
The computations are done within cyclic groups induced by elliptic curves. When we use mathematical
expressions, we write points in those groups in uppercase, and scalar numbers in lowercase. We write
the group operation additively, i.e., :math:`+` denotes the group operation.

In code, however, we follow the Python conventions and write both groups and group elements in lowercase.

We use Camenisch-Stadler notation [CS97]_ for zero-knowledge proofs. A proof of knowledge of a
secret integer :math:`x` such that :math:`Y = x G` for some group element :math:`G` is denoted as
follows:

.. math ::
   PK \{ x : Y = x G \}

.. Tip ::
   We use `petlib <https://github.com/gdanezis/petlib>`__ library for working with elliptic curves.
   We strongly advise you to take a look at petlib's `documentation page
   <https://petlib.readthedocs.io/en/latest/>`__. 

Overview 
^^^^^^^^
This library enables zero-knowledge proofs that are composed of the following blocks:

- **Discrete Logarithm representation.** A proof of knowledge of secret integers :math:`x_i`,
  such that :math:`Y` can be written as :math:`Y = \sum_i x_i G_i`:

  .. math ::
   
   PK \{ (x_0, x_1, ..., x_n): Y = x_0 G_0 + x_1 G_1 + ... + x_n G_n \}

- **And** conjunctions of other proofs.
- **Or** conjunctions of other proofs.
- Your own custom proof primitive.

Apart from DLRep, we include some other useful primitives in the library distribution:

- **Inequality of discrete logarithms,** with one of the logarithms that must be known. This
  protocol is drawn from the BLAC scheme [HG13]_.

- **BBS+ signature proof** to prove knowledge of a signature over a set of attribute-based
  credentials [ASM06]_.

The library supports three different modes of using zero-knowledge proofs:

- **Interactive** proof. You can get the messages that need to be transmitted between a prover and
  a verifier, along with functionality to verify those messages.

- **Non-interactive** proof through Fiat-Shamir heuristic. 

- Simulation.


A Simple Interactive Proof
^^^^^^^^^^^^^^^^^^^^^^^^^^

In this example, we will build a ZK proof for the following statement:

.. math ::

   PK \{ (x_1, x_2): Y = x_0 G_1 + x_1 G_1 \}

.. Tip ::
   
   The next steps use petlib's big number and elliptic curve syntax (``petlib.bn``,
   ``petlib.ec``) syntax. We encourage you to get familiar with them on petlib's
   `documentation page <https://petlib.readthedocs.io/en/latest/>`__.

First, we set up the group elements: elliptic curve points :math:`G_i`, and the secrets :math:`x_i`.

.. literalinclude:: ../examples/simple_dlrep.py
   :lines: 15-21

Then, we can create a proof like this:

.. literalinclude:: ../examples/simple_dlrep.py
   :lines: 25-29

In this section, we build an interactive proof. For that, we are going to instantiate a
:py:class:`Verifier` and a :py:class:`Prover`. In a realistic setup, one would not get both from the
same proof object (typically the prover and the verifier sides are not running on the same machine).

.. literalinclude:: ../examples/simple_dlrep.py
   :lines: 32-33

The secret values can also be specified at this step instead of earlier. See the `Secrets
<#Secrets>`__ section.

The Prover and Verifier are going to interact using a Sigma-protocol, ending with the verifier
accepting or rejecting the proof.

.. literalinclude:: ../examples/simple_dlrep.py
   :lines: 36-38

Secrets
^^^^^^^

A :py:class:`Secret` objects represent the secret integer in a zero-knowledge proof. A secret has
a name and a value, but both can be empty. It can be constructed without any arguments:

.. code:: python

   x = Secret()

In this case, a name is assigned automatically.

To provide a value, construct a secret like this:

.. code:: python

   x = Secret(value=42)

If a secret contains a value, the proof will be able to use it, otherwise a prover will wait for a
dictionary that maps secrets to values. The following two equivalent snippets illustrate this:

.. code:: python

   x = Secret(value=4, name="x")
   proof = DLRepProof(y, x * G)
   prover = proof.get_prover()

.. code:: python

   x = Secret(name="x")
   proof = DLRepProof(y, x * G)
   prover = proof.get_prover({x: 4})

Composing Proofs with "And"
^^^^^^^^^^^^^^^^^^^^^^^^^^^
In this example, we show how to build an "and"-composition of two discrete-logarithm proofs:

.. math::
   PK \{ (x_0, x_1, x_2): \underbrace{Y_0 = x_0 G_0 + x_1 G_1}_{\text{First statement}}
      \land \underbrace{Y_1 = x_1 G_2 + x_2 G_3}_{\text{Second statement}} \}

As before, we initialize the points :math:`G_i` and the secrets :math:`x_i`.

.. literalinclude:: ../examples/andproof.py
   :lines: 14-26

.. Tip ::

   If you need several group generators, as above, you can use the :py:func:`utils.make_generators`
   function.

Then, we can create the "and"-proof like this:

.. literalinclude:: ../examples/andproof.py
   :lines: 30-36

This syntax enables us to almost copy the mathematical expression of the proof in the
Camenisch-Stadler notation.

We can also instantiate subproofs separately and pass them to the
:py:class:`composition.AndProof`. In fact, the above is just a simplified way of writing
the following:

.. literalinclude:: ../examples/andproof.py
   :lines: 39-42

The two ways to construct the AndProof are equivalent and work with an arbitrary number of
parameters.

Composing proofs takes into consideration the re-occuring secrets. The following are two **not**
equivalent snippets:

.. literalinclude:: ../examples/andproof.py
   :lines: 58-60

.. literalinclude:: ../examples/andproof.py
   :lines: 62-63

They are not equivalent as the second one will verify that the same
:py:class:`expr.Secret` object is used. 

Running the protocol is the same as in the previous example.

Composing proofs with "Or"
^^^^^^^^^^^^^^^^^^^^^^^^^^

In this example, we show how to build an "or"-composition of two discrete-logarithm proofs:

.. math::
   PK \{ (x_0, x_1): \underbrace{Y_0 = x_0 G_0}_{\text{First statement}}
         \lor \underbrace{Y_1 = x_1 G_1}_{\text{Second statement}} \}

Or-proofs are slightly more complicated than and-proofs. 

First, we set up the proof:

.. code:: python

   y1 = x1.value * g1
   y2 = x2.value * g2
   proof = DLRepProof(y1, x1 * g1) | DLRepProof(y2, x2 * g2)

Or use an ``OrProof()`` constructor exactly as for the And statement seen above.

The rest is the same as above, that is you still have to create a Prover and a Verifier by calling
the ``get_prover()`` and ``get_verifier()`` methods of the Proof object. The OrProver will in fact
be composed of one legit subprover and run simulations for the other subproofs.

.. Note::

   When constructing an or-proof, ``orp = p1 | p2``, the ``p1`` and ``p2`` are copied. After the
   or-proof is constructed, modifying the original objects does not change the composed proof.

.. Tip::
   
   You don't need to provide all the secret values for the or-proof. The library will draw at random
   which subproof to compute, but first will chose only among those for which you provided all
   secrets.

You might want to set yourself which subproofs you want to simulate before constructing the prover:

.. code:: python

   proof.subproofs[i].simulation = True

This will ensure that this subproof is not picked for the legit computation. 


Composing "And" and "Or"
^^^^^^^^^^^^^^^^^^^^^^^^

You can have complex composition trees:

.. math::

   PK\{ (x_0, x_1, x_2): (Y_0 = x_0 G_0 \lor Y_1 = x_1 G_1) \land Y_2 = x_2 G_2 \}

The setup would be

.. code:: python

    y1 = x1.value * g1
    y2 = x2.value * g2
    y3 = x3.value * g3
    proof = (DLRepProof(y1, x1 * g1) | DLRepProof(y2, x2 * g2)) 
            & DLRepProof(y3, x3 * g3)

Some Special Cases are not Allowed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The library cannot prevent all cases of flawed proofs, but it will try its best to detect issues.
For that, it needs to impose certain limitations on the expressivity of the proofs.

1. When reusing a secret :math:`x` with two different group points :math:`G_0`, :math:`G_1`, the
   groups induced by :math:`G_0` and :math:`G_1` must have the same order. Otherwise, proof `like
   this <#a-first-composed-proof>`__ will fail.
2. No secret should appear at the same time in and out of an or-proof. This proof will fail to
   instantiate:
   
   .. math::

      PK\{ (x_0, x_1): Y_0 = x_0 G_0  \land  (Y_1 = x_1 G_1  \lor Y_2 = x_0 G_2 ) \}

3. You must use the same order in expressions when proving and verifying. Proving non-interactively
   :math:`PK\{(x_0, x_1): Y = x_0 G_0 + x_1 G_1 \}`, but verifying
   :math:`PK\{(x_0, x_1): Y = x_1 G_1 + x_0 G_0 \}` will fail as proofs generate and compare
   order-sensitive identifiers.

Using Non-Interactive Proofs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Once you have built your proof with fully constructed Secret objects
(see `Secrets <#secrets>`__)

.. code:: python

   nizk = stmt.prove()

The returned object will be a ``NonInteractiveTranscript``, embedding a challenge, a list of
responses, a hash of the proof statement and optionnaly a precommitment.

To verify the non-interactive proof goes as follows:

.. code:: python

   stmt.verify(nizk)


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

