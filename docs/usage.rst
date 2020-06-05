Basic Usage
-----------

This page outlines walks through the basic usage of ``zksk`` library, leveraging only built-in primitives.

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

- **AND**, conjunctions of other proofs.
- **OR**, disjunctions of other proofs.
- Your own custom proof primitive.

Apart from discrete-logarithm representations, we include :ref:`other useful primitives
<included_primitives>` in the library distribution.

The library supports three different modes of using zero-knowledge proofs:

- **Interactive** proof. You can get the messages that need to be transmitted between a prover and
  a verifier, along with functionality to verify those messages.

- **Non-interactive** proof through Fiat-Shamir heuristic.

- Simulation.


Defining a Simple Proof Statement
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this example, we define a proof for the following statement:

.. math ::

   PK \{ (x_1, x_2): Y = x_0 G_1 + x_1 G_1 \}

.. Tip ::

   The next steps use petlib's big number and elliptic curve syntax (``petlib.bn``,
   ``petlib.ec``). We encourage you to get familiar with them on petlib's
   `documentation page <https://petlib.readthedocs.io/en/latest/>`__.

First, we set up the group elements: elliptic curve points :math:`G_i`, and the secrets :math:`x_i`.

.. literalinclude:: ../examples/simple_dlrep.py
   :lines: 15-21

Then, we can define a proof statement like this:

.. literalinclude:: ../examples/simple_dlrep.py
   :lines: 25-29

See the next section for more details about secrets and expressions that can
be specified in ``zksk``.

Executing the Proofs
^^^^^^^^^^^^^^^^^^^^

``zksk`` supports both intractive and non-interactive proof modes.  To execute the interactive proof
protocol, we are going to instantiate a :py:class:`zksk.base.Verifier` and a
:py:class:`zksk.base.Prover`. In a realistic setup, one would not get both from the same proof
object (typically the prover and the verifier sides are not running on the same machine).

.. literalinclude:: ../examples/simple_dlrep.py
   :lines: 32-33

The prover and verifier are going to interact using a sigma protocol, ending with the verifier
accepting or rejecting the proof.

.. literalinclude:: ../examples/simple_dlrep.py
   :lines: 36-38

Once you have defined your proof along with the values of the secrets, you can
call the :py:meth:`zksk.base.Prover.prove` method to get a non-interactive ZK proof
(NIZK):

.. literalinclude:: ../examples/simple_dlrep.py
   :lines: 41

The returned :py:class:`zksk.base.NIZK` object embeds a challenge, a list of
responses, a hash of the proof statement and a precommitment, if any.

To verify a NIZK, the verifier needs reconstruct the same statement and
call :py:meth:`zksk.base.Verifier.verify`:

.. literalinclude:: ../examples/simple_dlrep.py
   :lines: 42

Secrets and Expressions
^^^^^^^^^^^^^^^^^^^^^^^

A :py:class:`zksk.expr.Secret` objects represent the secret integer in a zero-knowledge proof. A secret has
a name and a value, but both can be empty. It can be constructed without any arguments:

.. literalinclude:: ../examples/expressions.py
   :lines: 15

In this case, a name is assigned automatically.

To provide a value, construct a secret like this:

.. literalinclude:: ../examples/expressions.py
   :lines: 16

If a secret contains a value, the proof will be able to use it, otherwise a prover will wait for a
dictionary that maps secrets to values. The following two equivalent snippets illustrate this:

.. literalinclude:: ../examples/expressions.py
   :lines: 18-22

.. literalinclude:: ../examples/expressions.py
   :lines: 24-28

The names of secrets do not matter, they are only used for debugging purposes. All secrets can be
left unnamed.

Multiplying secrets by elliptic curve points, as in ``x * G``, produces expressions. Expressions can
also be added together. In general, an expression has the following form:

.. math::

   x_0 G_0 + x_1 G_1 + ... + x_n G_n

For example:

.. literalinclude:: ../examples/expressions.py
   :lines: 31-35

``expr`` here represents :math:`x G + y H`.

If secrets have their values set, you can also evaluate an expression using
:py:meth:`zksk.expr.Expression.eval` method:

.. literalinclude:: ../examples/expressions.py
   :lines: 38-40

This can simplify the redundant definition of a proof above:

.. literalinclude:: ../examples/expressions.py
   :lines: 43

Composing Proofs with AND
^^^^^^^^^^^^^^^^^^^^^^^^^
In this example, we show how to build an "and"-composition of two discrete-logarithm proofs:

.. math::
   PK \{ (x_0, x_1, x_2): \underbrace{Y_0 = x_0 G_0 + x_1 G_1}_{\text{First statement}}
      \land \underbrace{Y_1 = x_0 G_2 + x_2 G_3}_{\text{Second statement}} \}

As before, we initialize the points :math:`G_i` and the secrets :math:`x_i`.

.. literalinclude:: ../examples/andproof.py
   :lines: 14-26

.. Tip ::

   If you need several group generators, as above, you can use the :py:func:`zksk.utils.groups.make_generators`
   function.

Then, we can create the "and"-proof like this:

.. literalinclude:: ../examples/andproof.py
   :lines: 30-36

This syntax enables us to almost copy the mathematical expression of the proof in the
Camenisch-Stadler notation.

We can also instantiate subproofs separately and pass them to the
:py:class:`zksk.composition.AndProofStmt`. In fact, the above is just a simplified way of writing
the following:

.. literalinclude:: ../examples/andproof.py
   :lines: 39-42

The two ways to construct the AndProofStmt are equivalent and work with an arbitrary number of
parameters.

Composing proofs takes into consideration the re-occuring secrets. The following are two **not**
equivalent snippets:

.. literalinclude:: ../examples/andproof.py
   :lines: 58-60

.. literalinclude:: ../examples/andproof.py
   :lines: 62-64

They are not equivalent as the second one will verify that the same
:py:class:`zksk.expr.Secret` object is used.

Executing the protocol is the same as in the previous example.

Composing Proofs with OR
^^^^^^^^^^^^^^^^^^^^^^^^

In this example, we show how to build an "or"-composition of two discrete-logarithm proofs:

.. math::
   PK \{ (x_0, x_1): \underbrace{Y_0 = x_0 G_0}_{\text{First statement}}
         \lor \underbrace{Y_1 = x_1 G_1}_{\text{Second statement}} \}

Or-proofs are slightly more complicated than and-proofs.

A simple way to define this or-proof is as follows:

.. literalinclude:: ../examples/orproof.py
   :lines: 26-31

An or-proof works by simulating all subproofs but the one true subproof which will be actually
proved. Before executing the protocol, you can explicitly define which subproofs will be simulated.

.. literalinclude:: ../examples/orproof.py
   :lines: 33-34

This ensures that this subproof is not picked for the legitimate execution.

.. Note::

   When constructing an or-proof, ``orp = p1 | p2``, the ``p1`` and ``p2`` are
   copied. After the or-proof is constructed, modifying the original objects
   does not change the composed proof.

.. Tip::

   You don't need to provide all the secret values for the or-proof. The library
   will draw a random subproof to execute, but it will choose only
   among those for which you provided all secrets.

Equivalently, you can use :py:class:`zksk.composition.OrProofStmt`:

.. literalinclude:: ../examples/orproof.py
   :lines: 36-41

The built-in primitives such as :py:class:`zksk.primitives.dlrep.DLRep` accept a
``simulated`` parameter. You can use it to mark which subproof to simulate at
its construction time:

.. literalinclude:: ../examples/orproof.py
   :lines: 45-49

Executing the protocol is the same as in the previous sections.

Composing AND and OR
^^^^^^^^^^^^^^^^^^^^^^^^

You can have complex composition trees:

.. math::

   PK\{ (x_0, x_1, x_2): (Y_0 = x_0 G_0 \lor Y_1 = x_1 G_1) \land Y_2 = x_2 G_2 \}

Definining this statement amounts to the following:

.. literalinclude:: ../examples/two_level_proof.py
   :lines: 19-22

Some Special Cases are not Allowed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The library cannot prevent all cases of flawed proofs, but it will try its best to detect issues.
For that, it needs to impose certain limitations on the expressivity of the proofs.

1. When reusing a secret :math:`x` with two different group points :math:`G_0`, :math:`G_1`, the
   groups induced by :math:`G_0` and :math:`G_1` must have the same size.
2. No secret should appear at the same time in and out of an or-proof. This proof will fail to
   instantiate:
  
   .. math::

      PK\{ (x_0, x_1): Y_0 = x_0 G_0  \land  (Y_1 = x_1 G_1  \lor Y_2 = x_0 G_2 ) \}

3. You must use the same order in expressions when proving and verifying. Proving non-interactively
   :math:`PK\{(x_0, x_1): Y = x_0 G_0 + x_1 G_1 \}`, but verifying
   :math:`PK\{(x_0, x_1): Y = x_1 G_1 + x_0 G_0 \}` will fail as proofs generate and compare
   order-sensitive identifiers.


.. [CS97] J. Camenisch and M. Stadler, "Proof systems for general statements
   about discrete logarithms," Tech. rep. 260, Mar. 1997
