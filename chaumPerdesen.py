# the following is in a
# find a prime number q to use as the abelian group order.
# try with q = 713
# create this abelian group.
# find random g and h that are generators in this abelian group.
from petlib.bn import Bn


def addToFactors(nb, arrayOfFactors):
    if len(arrayOfFactors) > 0 and arrayOfFactors[-1][0] == nb:
        arrayOfFactors[-1] = (nb, arrayOfFactors[-1][1] + 1)
    else:
        arrayOfFactors.append((nb, 1))
    return arrayOfFactors


def findPrimeDecomposition(n):
    k = 2
    arrayOfFactors = []
    while n > 1:
        if n % k == 0:  # if k evenly divides into n
            arrayOfFactors = addToFactors(k,
                                          arrayOfFactors)  # this is a factor
            n = n / k  # divide n by k so that we have the rest of the number left.
        else:
            k = k + 1
    return arrayOfFactors


def findGenerator(primeDecomposition, groupOrder, upperBound=0):
    bnGroupOrder = Bn(groupOrder + 1)
    #	if upperBound > 0:
    #		primeDecomposition = list(filter(lambda pair: pair[0] < upperBound, primeDecomposition))
    randomNumbersUsed = set()
    while True:
        g = bnGroupOrder.random()
        if g in randomNumbersUsed:
            continue
        randomNumbersUsed.add(g)
        b = True
        for (primeNb, power) in primeDecomposition:
            print("groupOrder, primeNb  ", groupOrder, primeNb)
            power = int(groupOrder / primeNb)
            modulo = (
                groupOrder + 1
            )  # assuming the group order is the order of (Z/qZ)* where q (=groupOrder+1) is prime
            y = g.mod_pow(power, modulo)
            print("g, power, modulo, result", g, power, modulo, y)
            if y == Bn(1):
                print("Y = ", y)
                b = False
                break
        if b:
            return g


# (3175) mod (8831)
q = 1300907
order = q - 1  # 712 find prime factorisation of 712


n = order

primeDecomposition = findPrimeDecomposition(order)
print("Prime decomposition ", primeDecomposition)
g = findGenerator(primeDecomposition, order)
print("FOUND A GENERATOR ", g)

# PEGGY: find a random k and sends r = g^k to victor
# VICTOR SENDS PEGGY  e
# PEGGY COMPUTES s = k + xe mod(q) and sends s to victor
# VICTOR COMPUTES r = g^s y^-e from petlib.bn import Bn
# proverInitial()
# verifier

