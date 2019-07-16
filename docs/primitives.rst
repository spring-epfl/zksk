.. _included_primitives:

Included Primitives
-------------------

Inequality of Discrete Logarithms
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This primitive represents a proof of knowledge of :math:`x` such that two
DL representations are not equal:

.. math::

   PK\{ x: Y_0 = x G_0 \land Y_1 \neq x G_1 \}

This protocol is a part of the BLAC scheme [HG13]_.

The associated class ``DLNotEqual`` is constructed as follows:

.. code:: python

   x = Secret(value=12)
   stmt = DLNotEqual([y0, g0], [y1, g1], x)

Due to the internal proof construction, this proof does not bind the
secret value ``x`` by default. To enable this feature, the proof
constructor has to be called with the parameter ``binding=True``.

Knowledge of the BBS+ Signature
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This primitive provide a way to obtain blind signatures over a set of
attribute-based credentials [ASM06]_.

The protocol uses group pairings (see :py:mod:`zksk.pairings`).

Obtaining a Signature
"""""""""""""""""""""

The idea is to request an issuer -- identified by a public key ``pk`` and a
secret key ``sk`` -- to blindly sign a list of messages :math:`m_i`. The user will
blind these attributes by a secret attribute :math:`s_1`.

The resulting number is sent to the issuer along with a proof of correct
construction.

.. code:: python

   group_pair = BilinearGroupPair()
   keypair = Keypair(group_pair, num_generators) 

   # Construct a UserCommitment object embedding the blinded block and the proof
   # of correct construction.
   creator = BBSPlusSignatureCreator(pk)
   usr_commitment = creator.commit(messages)

   # Get the blinded block signed by the issuer (through its secret key). It
   # returns a signature that we then update by adding s_1.
   presignature = sk.sign(lhs.com_message)
   signature = creator.obtain_signature(presignature)

The final signature validity can be verified by calling:

.. code:: python

   signature.verify(pk, messages)

The issuer can verify the correct construction as follows:

.. code:: python

   usr_commitment.verify_blinding(pk)

Proving Knowledge of a Signature
''''''''''''''''''''''''''''''''

Once the user has the final signature, she can prove she has it:

.. code:: python

   e, s = Secret(value=signature.e), Secret(value=signature.s)
   messages = [Secret(value=m1), ..., Secret(value=m_n)]
   proof = SignatureStmt([e, s, *messages], pk, signature)

The :math:`e` and :math:`s` secrets are necessary so the proof can bind them to
another proof, e.g. in an AND conjunction. If you do not care about binding
:math:`e` and :math:`s` to other proofs, you can skip them, only pass the messages and
set a ``binding=False``.

.. code:: python

   messages = [Secret(value=m1)..., Secret(value=mn)]
   stmt = BBSPlusSignatureStmt(messages, pk, signature, binding=False)

The ``signature`` argument is required for the proving side. 
The verifier can run this:

.. code:: python

   e, s = Secret(), Secret()   # Omitted if not binding
   messages = [Secret(), ..., Secret()]
   stmt = BBSPlusSignatureStmt([e, s, *messages], pk)

Afterwards, a prover and verifier can run the proof protocol.


.. [HG13] R. Henry and I. Goldberg, "Thinking inside the BLAC box: smarter
   protocols for faster anonymous blacklisting," in Proceedings of the 12th
   ACM workshop on Workshop on privacy in the electronic society. ACM,
   2013, pp. 71–82.

.. [ASM06] M. H. Au, W. Susilo, and Y. Mu, "Constant-size dynamic k-TAA," in
   International Conference on Security and Cryptography for Networks.
   Springer, 2006, pp. 111–125.
