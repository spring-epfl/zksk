# fall18-cs523-zkcompiler

On master branch : is dirty. should not get dirtier -> test and modifications happen on the other branches which will be merged
                   when appropriate.

- SigmaProtocol defines the pattern of every proof with a Verifier and a Prover object
- Various versions of Pedersen protocol : one for 2 claims (Decoupled), one for an arbitrary number of claims(Gen), 
  one outdated version(pedersen.py). The 2 latter stay here for various reasons but should not be updated.
- ChaumPedersen
  
  
 On 'test' branch : adaptation of the existing proofs into parametrized version
 
 - PedersenwithParams along with SigmaProtocol implement a more realistic use of the API where the script is given
  a concrete proof to compute with secrets and public info, instead of generating them.
 - ChaumPedersen : same as master for now
  
 On 'SimonDev' branch : new proofs being developed (Or proof)
 
