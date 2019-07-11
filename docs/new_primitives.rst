Creating your own proof primitives
----------------------------------

You can also easily define your own proof primitives and use them in new proofs.
The library already uses this technique to define several new proof primitives.
In this guide we will see how to define our own primitives.

A primitive for proving knowledge of an ElGamal plaintext
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We start with a simple new primitive. Consider an additive ElGamal ciphertext

.. math:: c = (c_1, c_2) = (rG, rH + mG)

for a group with generator :math:`G` and public key :math:`H = xG`. The owner
the private key :math:`x` can decrypt the ciphertext by computing

.. math:: T = c_2 - x \cdot c_1 = mG

and then finding :math:`m` through trial and error, a lookup table, or a
discrete-logarithm finding algorithm such as the baby-step giant-step algorithm.

We construct a new primitive that proves that the creator of the ciphertext
:math:`c` knows the encrypted message :math:`m` and the randomizer :math:`r`. In
Camenisch-Stadler notation:

.. math:: PK\{ (x, r) : c_1 = r G \land c_2 = r H + m G \}.

The first step in defining a new primitive is to determine its inputs and
secrets. In this case, the public input is the ciphertext :math:`c` and a public
key ``pk`` containing the points :math:`G` and :math:`H`. Moreover, the prover
has two secrets, the message :math:`m` and the randomizer :math:`r`. To define a
new primitive with these parameters, we inherit from ``ExtendedProof``. The
constructor simply stores the values we pass.

.. literalinclude:: ../examples/primitive_knowledge_elgamal.py
   :lines: 28,63-70

Next, we define which statement corresponds to our new primitive.

.. literalinclude:: ../examples/primitive_knowledge_elgamal.py
   :lines: 72-75

Which is a direct translation of the Camenischh-Stadler notation defined above.
And that's it! See ``examples/primitive_knowledge_elgamal.py`` for the full
runnable example.
