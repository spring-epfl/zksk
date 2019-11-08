BACKEND = "openssl"


class Bn:
    def __new__(cls, *args, **kwargs):
        if BACKEND == "openssl":
            from petlib.bn import Bn
            return Bn.__new__(cls, *args, **kwargs)
        elif BACKEND == "relic":
            # Use petrelic's Bn
            pass
        else:
            raise NotImplementedError
