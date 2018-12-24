# fall18-cs523-zkcompiler

A toolkit to build zero-knowledge proofs along sigma protocols.

To use it, you should install :
  - petlib, see https://petlib.readthedocs.io/en/latest/ 
      Warning : petlib has not released a version compatible with OpenSSL 1.1 or newer yet. 
  - msgpack
  - pytest
  - hashlib

## How to use :

You can implement (local) interactive proofs, and non-interactive proofs. These includes simulations of proofs.
Proofs you can implement are conjunctions of Discrete Logarithm Representations, And blocks and Or blocks.
Find below examples of proof creation :

-



## How it works : 

ZKC will basically instantiate a *Prover* and a *Verifier* object and make them talk (in the case of an interactive proof). If the proof is a conjunction of subproofs, a global challenge and global randomizers are shared (i.e the subproofs are not run independently from each other).
The sigma protocol is the following : 

Initial state : the Prover and the Verifier share some "public information", namely
 - an ECGroup (elliptic curve group, see petlib) along with a set of generators of this group
 - the left-hand-side value of the claim i.e the value for which we want to prove knowledge of certain properties/decomposition
 - the syntax of the claim including the pseudonyms of the secrets
 
 Now the interaction :
 
          `code`
Prover ---------------> Verifier

          challenge
Prover <--------------- Verifier

           response
Prover ---------------> Verifier

After which the Verifier locally "verifies" i.e locally recomputes a pseudo-commitment from the challenge and the responses, and compares it to the actual commitment.

In the case of a **non-interactive (NI) proof** the Prover commits, generates a deterministic challenge by hashing the commitment and all the public information. He then responds as if this challenge had been sent by a Verifier, and outputs the challenge and the response. A verifier can then compute the pseudo-commitment, hash it with the public information and assert he indeed obtains the challenge.
Note that this verification does not need to know the actual commitment since due to the cryptographic hash function properties, it is very unlikely to find R' such that hash(R' + *fixed_string* ) is equal to hash(R + *fixed_string*), i.e if a pseudo-commitment is indeed a pre-image of the challenge, it is the actual commitment almost surely.
