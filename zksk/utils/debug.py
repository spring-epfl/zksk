"""
Utils that can be useful for debugging.
"""


class SigmaProtocol:
    """
    Sigma-protocol runner.

    Args:
        verifier: Verifier object
        prover: Prover object
    """

    def __init__(self, verifier, prover):
        self.verifier = verifier
        self.prover = prover

    def verify(self, verbose=True):
        """Run the verification process."""

        # Funky names.
        victor = self.verifier
        peggy = self.prover

        precommitment = peggy.precommit()
        victor.process_precommitment(precommitment)
        commitment = peggy.commit()
        challenge = victor.send_challenge(commitment)
        response = peggy.compute_response(challenge)
        result = victor.verify(response)

        if verbose:
            if result:
                print("Verified for {0}".format(victor.__class__.__name__))
            else:
                print("Not verified for {0}".format(victor.__class__.__name__))

        return result
