Included Primitives
-------------------

``dl_notequal``: Inequality of Two Discrete Logarithms
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This primitive represents a proof of knowledge of :math:`x` such that two
DL representations are not equal:

.. math::

   PK\{ Y_0 = x \* G_0 and Y_2 != x G_1 \}

The associated class ``DLNotEqual`` is constructed as follows:

.. code:: python

    x = Secret(value = 12)
    proof = DLNotEqual([Y1, G1], [Y2, G2], x)

    Due to the internal proof construction, this proof does not bind the
    secret value ``x`` by default. To enable this feature, the proof
    constructor has to be called with the optional parameter ``binding``
    set to ``True``).

Once the proof is constructed, the same methods as before
(``get_prover()``, ``get_verifier()``, ``prove()``, ``verify()``, etc.)
apply.

``bbsplus``: the BBS+ Signature Scheme
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We provide a way to obtain blind signatures over a set of
messages/credentials, along with a ``SignatureStmt`` primitive (to use
much like the ``DLRep`` seen before). This protocol uses group
pairings as defined from bplib package. The interface has been wrapped so the
pairings behave as usual EcPt (additive points)

Obtaining a Signature
"""""""""""""""""""""

The idea is to request an issuer -- identified by a public key
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

Proving Knowledge of a Signature
''''''''''''''''''''''''''''''''

Once the user has the final signature, it can prove knowledge of it by
calling

.. code:: python

    e, s = Secret(value=signature.e), Secret(value=signature.s)
    messages = [Secret(value=m1)..., Secret(value=mn)]
    proof = SignatureStmt([e, s, *messages], pk, signature)

The ``e`` and ``s`` Secret instances are necessary so the proof can bind
them to an other proof, e.g. in an ``And`` conjunction. If you do not
care about binding ``e`` and ``s`` to other proofs you can skip them,
only pass the messages and set a ``binding`` keyword argument to False.

.. code:: python

    messages = [Secret(value=m1)..., Secret(value=mn)]
    proof = SignatureStmt(messages, pk, signature, binding=False)

The ``signature`` argument is required for the proving side. Of course,
the verifying side would call

.. code:: python

    e, s = Secret(), Secret()   # Omitted if not binding
    messages = [Secret()..., Secret()]
    proof = SignatureStmt([e, s, *messages], pk)

From this Proof objects, one can run the usual methods ``get_prover()``,
``get_verifier()``, ``prove()``, ``verify()``, etc.

