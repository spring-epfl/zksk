from PedersenWithParams import *

N = 5
G = EcGroup(713)
tab_g = []
tab_g.append(G.generator())
for i in range (1,N):
    randWord = randomword(30).encode("UTF-8")
    tab_g.append(G.hash_to_point(randWord)) 
o = G.order()
secrets = []
for i in range(len(tab_g)): #we build N secrets
    secrets.append(o.random())

powers = [a*b for a,b in zip (secrets, tab_g)] #We build the public info with the secrets and the generators
public_info = G.infinite()
for y in powers:
    public_info += y

def test_pedersen_true(): #Legit run
    pedersen_true = PedersenProtocol(PedersenVerifier, PedersenProver, public_info, tab_g, secrets)
    proved = pedersen_true.run()
    assert proved == True

def test_pedersen_wrong_public(): #We use generators and secrets from previous run but random public info
    randWord = randomword(30).encode("UTF-8")
    public_wrong = G.hash_to_point(randWord)
    pedersen_public_wrong = PedersenProtocol(PedersenVerifier, PedersenProver, public_wrong, tab_g, secrets)
    wrong_pub = pedersen_public_wrong.run()
    assert wrong_pub == False

def test_pedersen_rand_secrets():#We use generators and public info from previous run but random secrets
    rand_secrets = []
    for i in range(len(tab_g)): #we build N secrets
        rand_secrets.append(o.random())
    pedersen_wrong_secrets = PedersenProtocol(PedersenVerifier, PedersenProver, public_info, tab_g, rand_secrets)
    wrong_secrets = pedersen_wrong_secrets.run()
    assert wrong_secrets == False


def test_pedersen_simulation():
    pass
