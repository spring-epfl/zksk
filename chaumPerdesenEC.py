import random, string
from collections import namedtuple
from petlib.ec import EcGroup


class Prover:
    def __init__(self, params):
        self.params = params
        self.secret = (
            params.o.random()
        )  # peggy wishes to prove she knows the discrete logarithm equal to this value

        # we see that Prover and Verifier have both a well defined set of interfaces
        # to communicate with each other

    def setVerifier(self, verifier):
        self.verifier = verifier

    def commit(self):
        G, g1, g2, o, = self.params
        self.k = o.random()
        commitment = (self.k * g1, self.k * g2)
        publicInfo = (self.secret * g1, self.secret * g2)
        self.verifier.sendChallenge(commitment, publicInfo)

    def sendResponse(self, challenge):
        response = self.k + (-challenge) * self.secret
        self.verifier.verify(response)


class Verifier:
    def __init__(self, params):
        self.params = params

    def setProver(self, prover):
        self.prover = prover

    def sendChallenge(self, commitment, publicInfo):
        self.commitment = commitment
        self.publicInfo = publicInfo
        self.challenge = self.params.o.random()
        self.prover.sendResponse(self.challenge)

    def verify(self, response):
        G, g1, g2, o = self.params
        (y1, y2) = self.publicInfo
        (r1, r2) = self.commitment
        tmp1 = (response * g1) + (self.challenge * y1)
        tmp2 = (response * g2) + (self.challenge * y2)
        print("(r1, r2) = ({0}, {1}) == ({2}, {3}) ?".format(r1, r2, tmp1, tmp2))
        if (r1, r2) == (tmp1, tmp2):
            print("Verified")
        else:
            print("Not verified")


def randomword(length):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


SetupOutputParams = namedtuple("SetupOutputParams", "G g1 g2 o")


def setup():
    G = EcGroup(713)
    g1 = G.generator()
    randWord = randomword(30).encode("UTF-8")
    g2 = G.hash_to_point(randWord)  # a second generator for G
    o = G.order()
    return SetupOutputParams(G, g1, g2, o)


params = setup()

victor = Verifier(params)
peggy = Prover(params)

victor.setProver(peggy)
peggy.setVerifier(victor)

peggy.commit()
