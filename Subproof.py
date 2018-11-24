from DLRep import DLRepProof
from petlib.ec import EcPt

class PublicInfo:
    def __init__(self, public_info):
        self.public_info = public_info
        self.secrets = []
        self.generators = []

    def __eq__(self, rightSide):
        if isinstance(rightSide, RightSide):
            return DLRepProof(rightSide.pts, rightSide.secrets, self.public_info)
        else: 
            raise Exception("undefined behaviour for this input")

class RightSide:
    def __init__(self, secret_name, ecPt):
        if not isinstance(secret_name, str) or not isinstance(ecPt, EcPt):
            raise Exception("in {0} * {1}, the first parameter should be a string (the secret name), and the second parameter should be an elliptic curve point".format(secret_name, ecPt))
        self.secrets = [secret_name]
        self.pts = [ecPt]
    def __add__(self, other):
        if not isinstance(other, RightSide):
            raise Exception("${0} doesn't correspond to something like \"x1\" * g1 + \"x2\" * g2 + ... + \"xn\" * gn")
        self.secrets.extend(other.secrets)
        self.pts.extend(other.pts)
        return self
        

class Sec:
    def __init__(self, secret_name):
        self.secret_name = secret_name

    def __mul__(self, ecPt):
        if not isinstance(ecPt, EcPt):
            raise Exception("parameter should be an elliptic curve point", ecPt)
        return RightSide(self.secret_name, ecPt)

