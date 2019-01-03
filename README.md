# fall18-cs523-zkcompiler

A toolkit to build zero-knowledge proofs along sigma protocols.

To use it, you should install :
  - petlib, see https://petlib.readthedocs.io/en/latest/ 
      Warning : petlib has not released a version compatible with OpenSSL 1.1 or newer yet. 
  - msgpack
  - hashlib

## How to use :

### Prepare your ingredients : 
	Build an expression using the following blocks
- Discrete Logarithm Representation
- And conjunctions
- Or conjunctions

### Choose a dish :
	The default commit, challenge, response, verify is the interactive version
- Interactive proof (local)
- Non-interactive proof
- Simulation

Be careful, if a secret (e.g "x^(0)") appears both inside an outside an OrProof **an error will be raised**.

### Syntax and setup
Find below examples of proof creation :

- Say we want to create the following And proof of two Discrete Logarithms proofs:  PK{(x^(_1),x^(_2),x^(_3),x^(_4)): y^(_1) = x^(_1) * g^(_1) + x^(_2) * g(_2) AND y(_2) = x(_1) * g(_3) + x(_3) * g(_3) + x(_4) * g(_5)}
You want to set the ECpt (elliptic curve points, the g_i) and the secrets x_i.

	g = EcGroup().generator()
	g1 = 2 * g
	g2 = 5 * g
	g3 = 10 * g

	x1 = 10
	x2 = 15
	x3 = 35
	x4 = 11

then you create the proof using the following syntax:

	from DLRep import *
	from Subproof import Secret

	y1 = x1 * g1 + x2 * g2
	y2 = x1 * g3 + x3 * g4 + x4 * g5 
	proof = DLRepProof(y1, Secret("x1") * g1 + Secret("x2") * g2) & DLRepProof(y2, Secret("x1") * g3 + Secret("x3") * g4 + Secret("x4") * g5)

A remark about the infix operator &, it represents the conjunction between the two DLRepProof.

All that is left to do fot the setup is to create a verifier and a prover from this proof.
To do that we have to feed the secrets values to the prover that only knows their names:
	prover = proof.get_prover({"x1": x1, "x2": x2, "x3": x3, "x4": x4})
	verifier = proof.get_verifier()

After that all that is left to do is to make the prover and verifier interact. verifiy() returns 
a boolean telling whether the proof is verified or not.
	commitment = prover.commit()
	challenge = verifier.send_challenge(commitment)
	response = prover.compute_response(challenge)
	verifier.verify(response)

- Say we want to create an or proof of two discrete logarithms proofs: PK{(x1,x2): y1 = x1 * g1 OR y2 = x2 * g2 }

you would do the following to setup the proof (say xi-s and gi-s have been setup already similarly as above):

	y1 = x1 * g1
	y2 = x2 * g2
	proof = DLRepProof(y1, Secret("x1") * g1) | DLRepProof(y2, Secret("x2") * g2)

the rest is the same as above. That is you still have to create a prover and a verifier by calling the get_prover() and get_verifier() methods of the Proof object.

- Of course you can also compose or proof and and proofs. Say you want to write the following proof: PK{(x1,x2,x3): y1 = x1 * g1 OR y2 = x2 * g2 AND y3 = x3 * g3}:

 the initial setup of the proof would be:

	y1 = x1 * g1
	y2 = x2 * g2
	y3 = x3 * g3
	proof = DLRepProof(y1, Secret("x1") * g1) | DLRepProof(y2, Secret("x2") * g2) & DLRepProof(y3, Secret("x3") * g3)

*&* and *|* have the same precedence as *and* and *or* in python. Therefore you can rely on your usual boolean logic to write your proofs.

## How it works : 

ZKC will basically instantiate a *Prover* and a *Verifier* object and make them talk (in the case of an interactive proof). If the proof is a conjunction of subproofs, a global challenge and global randomizers are shared (i.e the subproofs are not run independently from each other).
The sigma protocol (**interactive**) is the following : 

**Initial state** : the Prover and the Verifier share some "public information", namely
 - an ECGroup (elliptic curve group, see petlib) along with a set of generators of this group
 - the left-hand-side value of the claim i.e the value for which we want to prove knowledge of certain properties/decomposition
 - the syntax of the claim including the pseudonyms of the secrets
 
 The interaction is :
          
Prover ----- commitment ---> Verifier

Prover <----- challenge ------ Verifier
           
Prover ------ response -----> Verifier

After which the Verifier locally "verifies" i.e locally recomputes a pseudo-commitment from the challenge and the responses, and compares it to the actual commitment.

In the case of a **non-interactive (NI) proof** the Prover commits, generates a deterministic challenge by hashing the commitment and all the public information. He then responds as if this challenge had been sent by a Verifier, and outputs the challenge and the response. A verifier can then compute the pseudo-commitment, hash it with the public information and assert he indeed obtains the challenge.
Note that this verification relies on cryptographic hash function properties : it is very unlikely to find R' such that hash(R' + *fixed_string* ) is equal to hash(R + *fixed_string*), i.e if a pseudo-commitment is indeed a pre-image of the challenge, it is the actual commitment almost surely.
