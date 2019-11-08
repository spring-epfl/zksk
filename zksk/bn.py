if 'BACKEND' not in globals():
    BACKEND = "relic"

class Bn:
    def __new__(cls, *args, **kwargs):
        if BACKEND == "openssl":
            from petlib.bn import Bn
            return Bn.__new__(cls, *args, **kwargs)
        elif BACKEND == "relic":
            from petrelic.bn import Bn
            return Bn.__new__(cls, *args, **kwargs)
        else:
            raise NotImplementedError

    def from_hex(*args, **kwargs):
        if BACKEND == "openssl":
            from petlib.bn import Bn
            return Bn.from_hex(*args, **kwargs)
        elif BACKEND == "relic":
            from petrelic.bn import Bn
            return Bn.from_hex(*args, **kwargs)
        else:
            raise NotImplementedError
