BACKEND = "openssl"

if BACKEND == "openssl":
    from petlib.bn import Bn
elif BACKEND == "relic":
    from petrelic.bn import Bn
else:
    raise NotImplementedError
