# fall18-cs523-zkcompiler

A python toolkit to build zero-knowledge proofs along sigma protocols. 

To use it, you should install :
  - petlib, see https://petlib.readthedocs.io/en/latest/ 
      Warning : petlib has not released a version compatible with OpenSSL 1.1 or newer yet. 
  - msgpack
  - hashlib
  - python 3 or newer


## How to use :
> This section is about code examples and practice.If you want to understand what is going on, you can read the [How it works](#how-it-works) section first.

> Important : the computations are done within cyclic groups induced by elliptic curves.  Points of those groups are written in uppercase, scalar number in lowercase.
> What we refer as *secrets* are integers. We advise you to read [petlib's documentation page](https://petlib.readthedocs.io/en/latest/).

#### What you want to do

Build expressions using the following blocks :

	- Discrete Logarithm Representation
	- And conjunctions
	- Or conjunctions

Choose a proof mode among :

	- Interactive proof (local)
	- Non-interactive proof
	- Simulation


### Syntax and setup examples
#### An elementary proof

We want to build a proof for the following statement (using [Camenisch-Stadler][1] notation) :

### 
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;PK{ (x1, x2): Y = G1^x1 * G2^x2 }


First, note that as `*` denotes a group operation, it is just a matter of notation to replace it by `+`, and to replace the `^` by a `*`. The above expression becomes 

### 
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;PK{ (x1, x2): Y = x1 * G1 + x2 * G2}


This is the syntax we will use from now on, to ensure compatibility with the *petlib* library. 
> Warning : the next steps use petlib's BigNumber and EllipticCurve (*petlib.bn*, *petlib.ec*) syntax. We encourage you to get familiar with them [on petlib's documentation page](https://petlib.readthedocs.io/en/latest/).



Let's build the proof environment : we set the ECpts (elliptic curve points, the `Gi`) and the secrets `xi`.


	g = EcGroup().generator()	# This sets up the group and a first generator
	g1 = 2 * g			
	g2 = 5 * g		# Collecting various points in the group for the example 
	g3 = 10 * g			

	x1 = 10			# Preparing the secrets. This is a dummy setup, typically they
	x2 = 35			# are large integers or petlib.bn.Bn instances


Then creating a proof requires the following syntax:

	from DLRep import *
	from Subproof import Secret

	y = x1 * g1 + x2 * g2			# Building the left-hand-side of the claim
	
	my_proof = DLRepProof(y1, Secret("x1") * g1 + Secret("x2") * g2)

		# Which mimics the proof mathematical expression

		# Or, alternatively :
	
	my_proof = DLRepProof([g1, g2], ["x1", x2"], y)

		# Which can be simpler to integrate in code. Be careful, the lists are ordered !


That's almost it for the setup ! We want to instantiate a Verifier and a Prover objects from this proof.  
To do that we feed the prover with the secret values, identified by their names :

	prover = proof.get_prover({"x1": x1, "x2": x2}) # Python dictionary
	verifier = proof.get_verifier()

##### And now the fun begins : 
These two are going to interact along the **Sigma Protocol**, returning (with the *verify* method) a boolean telling whether the proof is verified or not.


	commitment = prover.commit()
	challenge = verifier.send_challenge(commitment)
	response = prover.compute_response(challenge)
	verifier.verify(response)

Done ! 


#### A first composed proof
 We want to build the "And" of two Discrete Logarithms proofs:  

### 
&nbsp;&nbsp; 
&nbsp;&nbsp; &nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;PK{ (x1, x2, x3): Y1 = x1 * G1 + x2 * G2 &nbsp;&nbsp; &&&nbsp;&nbsp; Y2 = x1 * G3 + x3 * G4 }



As before, we set the points `Gi` and the secrets `xi`.


	g = EcGroup().generator()	# This sets up the group and a first generator
	g1 = 3 * g			
	g2 = 12 * g		# Collecting various points in the group for the example 
	g3 = 10 * g			

	x1 = 10			
	x2 = 15			# Preparing the secrets. This is a dummy setup, typically they
	x3 = 40			# are large integers or petlib.bn.Bn instances
	x4 = 11

Then creating the proof :

	from DLRep import *
	from Subproof import Secret

	y1 = x1 * g1 + x2 * g2			# Building the left-hand-side of the claims
	y2 = x1 * g3 + x3 * g4
	
	and_proof = DLRepProof(y1, Secret("x1") * g1 + Secret("x2") * g2) & DLRepProof(y2, Secret("x1") * g3 + Secret("x3") * g4)

 Again, this syntax allows you to almost copy the mathematical expression of the proof in the Camenisch-Stadler notation.
 You can also instantiate subproofs separately and pass them (possibly as a list) to the AndProof() constructor, which the above syntax calls in fact for you :

	proof_1 = DLRepProof(y1, Secret("x1") * g1 + Secret("x2") * g2)
	proof_2 = DLRepProof(y2, Secret("x1") * g3 + Secret("x3") * g4)

	and_proof = AndProof(proof1, proof2) # OR
	and_proof = AndProof([proof1, proof2])

In the first example, the infix operator `&` calls a binary AndProof().  

Our setup is done, the rest is the same protocol [as in the first proof](#and-now-the-fun-begins). 




#### An other composed proof : Or block
This time we want to create an Or Proof of two discrete logarithms proofs: 


### 
&nbsp;&nbsp; 
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;PK{ (x1, x2): Y1 = x1 * G1 &nbsp;&nbsp; ||&nbsp;&nbsp; Y2 = x2 * G2 }

you would do the following to setup the proof (say the `xi` and `Gi` have been setup already similarly as above):

	y1 = x1 * g1
	y2 = x2 * g2
	proof = DLRepProof(y1, Secret("x1") * g1) | DLRepProof(y2, Secret("x2") * g2)

	# Or, again

	first_subproof = DLRepProof(y1, Secret("x1") * g1)
	second_subproof = DLRepProof(g2, "x2", y2)		# Remember this other syntax ?
	proof = first_subproof | second_subproof

The rest is the same as above, that is you still have to create a Prover and a Verifier by calling the `get_prover()` and `get_verifier()` methods of the Proof object.
The Or Prover will in fact be composed of one legit subprovers and  the rest will be simulators.

> Tip : You don't need to provide all the secrets for the Or Proof. The compiler will draw at random which subproof to compute, but first eliminates those you did not provide secrets for.

You might want to set yourself which subproofs you want to simulate, for this just do

		first_subproof.set_simulate()

Which will give this subproof probability 0 to be picked for legit computation.

#### Of course you can also compose Or and And !
Say you want to write the following proof : 

### 
&nbsp;&nbsp; 
&nbsp;&nbsp; &nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;PK{ (x1, x2, x3): Y1 = x1 * G1 &nbsp;&nbsp; ||&nbsp;&nbsp; Y2 = x2 * G2 &nbsp;&nbsp; &&&nbsp;&nbsp; Y3 = x3 * G3 }


The setup would be 

	y1 = x1 * g1
	y2 = x2 * g2
	y3 = x3 * g3
	proof = DLRepProof(y1, Secret("x1") * g1) | DLRepProof(y2, Secret("x2") * g2) & DLRepProof(y3, Secret("x3") * g3)

> `&` and `|` have the same precedence as native `&` and `|` in Python. Therefore you can rely on your usual boolean logic to write your proofs.

#### Some special cases are forbidden ! 

1. You want the group operation to have meaning, for that you are not allowed to operate between elements of different groups.

2. You want to ensure some properties about identical secrets. It implies that when reusing a secret $x$ with two different group points `Ga`, `Gb`, the groups induced by `Ga` and `Gb`$ must have the same order. This could cause [this proof](#a-first-composed-proof) to fail !

3. You never want to instantiate a flawed proof, and the current architecture is too naive to rewrite for you a bad statement. In particular, no secret should appear at the same time in and out of an Or Proof. This forbids, for example 
### &nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;PK{ (x1, x2): Y1 = x1 * G1 &nbsp;&nbsp; &&&nbsp;&nbsp;( Y2 = x2 * G2 &nbsp;&nbsp; ||&nbsp;&nbsp; Y3 = x1 * G3 ) }

&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;because x1 appears in two incompatible places. This is a subtlety we'll go through in the next part.

#### Using Non-interactive Proofs and Simulations
##### NI proofs :
Once you have built your proof and your Prover and Verifier objects, just call

		prover.get_NI_proof()
Which returns a (challenge, response) tuple you can plug into

		verifier.verify_NI(challenge, response)

> Don't mess with the syntax !   
> Proving non-interactively { Y = x1 * G1 + x2 * G2 }  and verifying { Y = x2 * G2 + x1 * G1 } will fail as the non-interactive proof generates a string identifier for the statement, and is not clever enough to understand commutativity.  
> Don't worry : using only the high-level functions we presented should never trigger this behaviour.
##### Simulations :
When you have your proof, instead of calling `proof.get_prover( ... )`, just call

		proof.get_simulator()

which returns commitment, challenge, response you can feed to

		verifier.verify(response, commitment, challenge)	
		# The ordering is unpractical because the latter are optional arguments



## How it works : 

ZKC will basically help you instantiate a *Prover* and a *Verifier* object and make them talk (in the case of an interactive proof). If the proof is a conjunction of subproofs, a global *challenge* and global *randomizers* are shared (i.e the subproofs are **not** run independently from each other).
The sigma protocol (interactive) is the following : 

**Initial state** : the Prover and the Verifier share some "public information", namely
 - an ECGroup (elliptic curve group, see petlib) along with a set of generators of this group
 - the left-hand-side value of the claim i.e the value for which we want to prove knowledge of certain properties/decomposition
 - the syntax of the claim including the pseudonyms of the secrets
 
 The interaction then is :
          


&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Prover ----- commitment ---> Verifier




&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Prover <----- challenge ------ Verifier
           

&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Prover ------ response -----> Verifier

After which the Verifier locally *verifies* i.e locally recomputes a pseudo-commitment from the challenge and the responses, and compares it to the actual commitment.


In the case of a **non-interactive (NI) proof** the Prover 
- commits
- generates a deterministic challenge by hashing the commitment and all the public information
- responds as if this challenge had been sent by a Verifier
-  outputs the challenge and the response.
  
 A verifier can then compute the pseudo-commitment, hash it with the public information and assert he indeed obtains the challenge.
Note that this verification relies on cryptographic hash function properties : it is very unlikely to find R' such that hash(R' + *fixed_string* ) is equal to hash(R + *fixed_string*), i.e if a pseudo-commitment is indeed a pre-image of the challenge, it is the actual commitment almost surely.


#### A look at the variables
- The `challenge` is common to a whole protocol. In the case of the Or Proof, subchallenges are drawn i.e each subproof runs (simulated or not) with its own challenge.
> This explains the constraint about reoccuring secrets in and out of an Or statement : we know a malicious Verifier can retrieve a secret which appear under several challenges and a unique commitment. A solution is to change the statement syntax into a canonical form, where the Or are on top of the tree.
- The `randomizers` are the random values used to produce commitments. They are paired with the secrets, to ensure that a reoccuring secret will produce identical responses. If there are N secrets of M distinct values, there are M distinct randomizers.
- The `responses` mimic the proof statement and are ordered as the secrets were ordered : If there are N secrets, there are N responses.



[1] :  J. Camenisch and M. Stadler, “Proof systems for general statements about discrete logarithms,”
Tech. rep. 260
, Mar. 1997