Creating Your Own Proof Primitives
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

Which is a direct translation of the Camenischh-Stadler notation defined above. This function must
take an extra argument ``precommitment``. But this argument is not used here. 

A primitive for proving inequality of discrete logarithms
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The previous primitive was very simple. We can also define more complicated
primitives. In this section we show how to construct a primitive for proving
that two discrete logarithms are not equal:

    .. math:: PK\{ (x): H_0 = x \cdot h_0 \land H_1 \neq x \cdot h_1 \}

or in words, that the discrete logarithm of :math:`H_0` with respect to
:math:`h_0` is not equal to the discrete logarithm of :math:`H_1` with respect
to :math:`h_1`.

Let :math:`x` be the private input of the prover such that :math:`H_0 = x \cdot h_0`. To prove the
above statement in zero-knowledge, we must proceed as follows [HG13]_:

 1. The prover picks a blinding factor :math:`r`, computes the auxiliary commitment
     :math:`C = r (x h_1 - H_1)`, and sends :math:`C` to the verifier.

 2. The prover and the verifier then engage in the zero-knowledge proof

    .. math:: PK\{ (\alpha, \beta): 1 = \alpha \cdot h_0 + \beta \cdot H_0 \land C = \alpha \cdot h_1 + \beta \cdot H_1 \}

    where the prover uses :math:`\alpha = x r \mod q` and :math:`\beta = -r \mod q`.

 3. Finally, the verifier accepts if the proof in step 2 succeeds, and if the commitment :math:`C \neq 1`.

This protocol is indeed a zero-knowledge proof. And, by combining steps 1 and 3 into step 2, can be
seen as a Sigma protocol. Internally, we still use a standard sigma protocol. However, we notice two
major changes. First, the prover precomputes a commitment, that then becomes part of the constructed
proof statement. Second, after verifying the constructed proof, the verifier needs to perform
another verification.  The ``ExtendedProof`` class allows us to define the extra steps.

We again first determine the inputs to the primitive. The public inputs are the pairs :math:`(H_0,
h_0)` and :math:`(H_1, h_1)`. The prover takes as private input the secret :math:`x` such that
:math:`H_0 = x \cdot h_0`. Again we override ``ExtendedProof`` and store the inputs:

.. literalinclude:: ../examples/primitive_dlrep_notequal.py
   :lines: 13-21

Note that the constructor also defines the secrets ``alpha`` and ``beta`` that will be used in the
constructed proof from step 2 above. The compute the commitment :math:`C` we override the
``precommit(self)`` method to compute a precommitment containing :math:`C`:

.. literalinclude:: ../examples/primitive_dlrep_notequal.py
   :lines: 23-32

Recall from before that the secrets :math:`\alpha` and :math:`\beta` depend on the user's secret
:math:`x` and the randomizer :math:`r` we use to compute the commitment. Since we now know all these
values, we can compute the real values of the constructed secrets :math:`\alpha` and :math:`\beta`,
and store them.

For simplicity, ``precommitment`` is a single group element here. However, in bigger primitives, it
might make more sense to define it as a dictionary instead. In fact, any object would work, as long
as it is serializable.

The ``precommit(self)`` method is only called by the prover. The verifier will integrate the
precommitment from the prover before constructing the proof. As above, we override
``construct_proof(self, precommitment)`` to define how to do so:

.. literalinclude:: ../examples/primitive_dlrep_notequal.py
   :lines: 34-38

Note that the constructed proof is a straightforward interpretation of the zero-knowledge proof from
step 2 above. When using our new primitive, the prover and verifier will now automatically prove
respectively verify the constructed proof that we just defined.

Finally, the verifier must ensure that the commitment :math:`C` is not the identity element. To
ensure that, we additionally override ``is_valid(self)``:

.. literalinclude:: ../examples/primitive_dlrep_notequal.py
   :lines: 40-41

If defined, the verifier will run the checks in ``is_valid`` before accepting the proof. And that is
it, our new primitive can now be used in bigger proofs.

The full implementation in the library of ``DLRepNotEqual`` is a little bit more complicated. Note
that in the above protocol, the secret ``x`` is not actually used directly in the proof. The full
version allows explicit binding of the secret ``x``.

Enabling Simulations
^^^^^^^^^^^^^^^^^^^^

If a new primitive only overrides ``construct_proof`` then simulations are automatically enabled.
However, the library cannot always compute a legitimate precommitment by itself. Therefore, it is
necessary to override ``simulate_precommit(self)`` to enable proper simulations.

For example, in the above proof of inequality of discrete logarithms the commitment :math:`C` is
just a random group element. Therefore, we can set:

.. literalinclude:: ../examples/primitive_dlrep_notequal.py
   :lines: 43-45

References
^^^^^^^^^^

.. [HG13] R. Henry and I. Goldberg, "Thinking inside the BLAC box: smarter
   protocols for faster anonymous blacklisting," in Proceedings of the 12th
   ACM workshop on Workshop on privacy in the electronic society. ACM,
   2013, pp. 71–82.
