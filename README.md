# fall18-cs523-zkcompiler

On master branch : 

-SigmaProtocol defines the pattern of every proof with a Verifier and a Prover object
- Various versions of Pedersen protocol : one for 2 claims (Decoupled), one for an arbitrary number of claims(Gen), 
  one outdated version(pedersen.py). The 2 latter stay here for various reasons but should not be updated.
-ChaumPedersen
  
  Pedersen Protocol is actually where we test the API features. 
  
 On 'test' branch : where the actual things happen
 
 -PedersenwithParams along with SigmaProtocol implement a more realistic use of the API where the script is given
  a concrete proof to compute with secrets and public info, instead of generating them. Also here will be the first
  big fix for camelCase and indentations.
 -ChaumPedersen
  
