#Script designed for identification pkeys up to 256 bit. Task#422-28301-NC
#from sage.all_cmdline import *
import sys 
print("Embedding Technique: Calculated Forge :)")
print("Created with custom factors and filter")
import collections
import hashlib
import random
#import olll
import os
import sys
from bitcoin import *
from urllib.request import urlopen

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
n = N

print('Enter your public key in compressed form, x value, with 02 or 03 :)')
pubkey = input()

import gmpy2
def mod_inv(a,b):
  return int(gmpy2.invert(a,b))

def cp2up(x):
	p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
	p = int(p)
	x1 = (x[:2])
	x2 = (x[2:])
	x2 = int(x2,16)
	ysquared = ((x2*x2*x2+7) % p)   
	#ysquared = int(ysquared)
	yy = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
	y = pow(ysquared, yy, p)
	y = int(y)
	y2 = int((y * -1) % p)
	if x1 == "02":#sometimes this has to be switched to "03" to get correct signatures, glitch in the matrix, joking
		return x2,y2
	else:
		return x2,y

PP = cp2up(pubkey)#used in verify and forging calculation
print(hex(PP[1]))
# Modular arithmetic ##########################################################
g = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
G = g

'''
def getraw(txid):
    try:
        htmlfile = urlopen("https://blockchain.info/rawtx/%s?format=hex" % txid, timeout = 60)
    except:
        print('Unable to connect internet to fetch RawTx. Exiting..')
        sys.exit(1)
    else: res = htmlfile.read().decode('utf-8')
    return res

def get_rs(sig):
    rlen = int(sig[2:4], 16)
    r = sig[4:4+rlen*2]
    s = sig[8+rlen*2:]
    return r, s
    
def split_sig_pieces(script):
    sigLen = int(script[2:4], 16)
    sig = script[2+2:2+sigLen*2]
    r, s = get_rs(sig[4:])
    pubLen = int(script[4+sigLen*2:4+sigLen*2+2], 16)
    pu = script[4+sigLen*2+2:]
    return r, s, pu

def parseTx(txn):
    if len(txn) < 130:
        print('[WARNING] rawtx most likely incorrect. Please check..')
        sys.exit(1)
    inp_list = []
    ver = txn[:8]
    inp_nu = int(txn[8:10], 16)
    
    first = txn[0:10]
    cur = 10
    for m in range(inp_nu):
        prv_out = txn[cur:cur+64]
        var0 = txn[cur+64:cur+64+8]
        cur = cur+64+8
        scriptLen = int(txn[cur:cur+2], 16)
        script = txn[cur:2+cur+2*scriptLen] #8b included
        r, s, pubb = split_sig_pieces(script)
        seq = txn[2+cur+2*scriptLen:10+cur+2*scriptLen]
        if pubtoaddr(pubb) == address:
            inp_list.append([prv_out, var0, r, s, pubb, seq])
            cur = 10+cur+2*scriptLen
        else:
            return False
    rest = txn[cur:]
    return [first, inp_list, rest]

def getrsz(parsed):
    res = []
    first, inp_list, rest = parsed
    tot = len(inp_list)
    for one in range(tot):
        e = first
        for i in range(tot):
            e += inp_list[i][0] # prev_txid
            e += inp_list[i][1] # var0
            if one == i: 
                e += '1976a914' + HASH160(inp_list[one][4]) + '88ac'
            else:
                e += '00'
            e += inp_list[i][5] # seq
        e += rest + "01000000"
        z = hashlib.sha256(hashlib.sha256(bytes.fromhex(e)).digest()).hexdigest()
        z1 = (int(z, 16))
        r = (int(inp_list[one][2],16))
        s = (int(inp_list[one][3],16))
        sigs = write(r,s,z1)
'''
def HASH160(pubk_hex):
    return hashlib.new('ripemd160', hashlib.sha256(bytes.fromhex(pubk_hex)).digest() ).hexdigest()
  
def modInv(n, p):
    return pow(n, p - 2, p)

def write(r,s,z):
    with open('file.txt', 'a') as out:
        out.write(h(r)+","+h(s)+","+h(z)+'\n')

def jordan_isinf(p):
    return p[0][0] == 0 and p[1][0] == 0


def mulcoords(c1, c2):
    return (c1[0] * c2[0] % P, c1[1] * c2[1] % P)


def mul_by_const(c, v):
    return (c[0] * v % P, c[1])

def addcoords(c1, c2):
    return ((c1[0] * c2[1] + c2[0] * c1[1]) % P, c1[1] * c2[1] % P)

def subcoords(c1, c2):
    return ((c1[0] * c2[1] - c2[0] * c1[1]) % P, c1[1] * c2[1] % P)

def invcoords(c):
    return (c[1], c[0])

def jordan_add(a, b):
    if jordan_isinf(a):
        return b
    if jordan_isinf(b):
        return a
    if (a[0][0] * b[0][1] - b[0][0] * a[0][1]) % P == 0:
        if (a[1][0] * b[1][1] - b[1][0] * a[1][1]) % P == 0:
            return jordan_double(a)
        else:
            return ((0, 1), (0, 1))

    xdiff = subcoords(b[0], a[0])
    ydiff = subcoords(b[1], a[1])
    m = mulcoords(ydiff, invcoords(xdiff))
    x = subcoords(subcoords(mulcoords(m, m), a[0]), b[0])
    y = subcoords(mulcoords(m, subcoords(a[0], x)), a[1])
    return (x, y)

def jordan_double(a):
    if jordan_isinf(a):
        return ((0, 1), (0, 1))
    num = addcoords(mul_by_const(mulcoords(a[0], a[0]), 3), [0, 1])
    den = mul_by_const(a[1], 2)
    m = mulcoords(num, invcoords(den))
    x = subcoords(mulcoords(m, m), mul_by_const(a[0], 2))
    y = subcoords(mulcoords(m, subcoords(a[0], x)), a[1])
    return (x, y)

def jordan_multiply(a, n):
    if jordan_isinf(a) or n == 0:
        return ((0, 0), (0, 0))
    if n == 1:
        return a
    if n < 0 or n >= N:
        return jordan_multiply(a, n % N)
    if n % 2 == 0:
        return jordan_double(jordan_multiply(a, n // 2))
    else:  # n % 2 == 1:
        return jordan_add(jordan_double(jordan_multiply(a, n // 2)), a)

def to_jordan(p):
    return ((p[0], 1), (p[1], 1))

def from_jordan(p):
    return (p[0][0] * modInv(p[0][1], P) % P, p[1][0] * modInv(p[1][1], P) % P)

def mul(a, n):
    """
    Multiply an ECPoint.
    @param {number} a - An ECPoint
    @param {number} n - A Big Number
    """
    return from_jordan(jordan_multiply(to_jordan(a), n))

def div(a, n):
    """
    Divide an ECPoint.
    @param {number} a - An ECPoint
    @param {number} n - A Big Number
    """
    return from_jordan(jordan_multiply(to_jordan(a), modInv(n, N) % N))

def add(a, b):
    """
    Add two ECPoints.
    @param {number} a - An ECPoint
    @param {number} b - An ECPoint
    """
    return from_jordan(jordan_add(to_jordan(a), to_jordan(b)))

def sub(a, b):
    """
    Subtract two ECPoints.
    @param {number} a - An ECPoint
    @param {number} b - An ECPoint
    """
    return from_jordan(jordan_add(to_jordan(a), to_jordan((b[0], P - (b[1] % P)))))

def negate(a):
    return (a[0], P - (a[1] % P))

def h(n):
  return hex(n).replace("0x","").zfill(64)

# Keypair generation and ECDSA ################################################
def verify(public_key, message, signature):
    z=message 
    r, s = signature
    w = mod_inv(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    x, y = add(mul(g, u1),mul(public_key,u2))
    if (r % N) == (x % N):
        return True
    else:
        return False
        
X = 0x1000#change this value to get correct readings
def forge(g,p):
    #r = PP[0]                                          
    s = (((((add(mul(G,g),mul(PP,p)))[0])*modInv(p,N)))%N)
    r = ((add(mul(G,g),mul(PP,p)))[0]%N)
    z = ((s*g)%N)
    signature = r,s
    if verify(PP, z, signature) == True:
        K = (((z+(X*r))*modInv(s,N))%N)
        K = int(K)
        num = K #count total number of bits in da nonce
        length = len(bin(num))
        length -=2
        zs = ((((z*modInv(s,N)%N))))
        rs = ((((r*modInv(s,N)%N))))
        SR = ((s-r)%N)
        Kk = h(K)
        KK = (Kk[-3:]) 
        if KK == "141":
            write(r,s,z)
            print("R","=",(h(r)))
            print("S","=",(h(s)))
            print("Z","=",(h(z)))
            print("K = ",   h(K) ,length, 'bits')
            print("Z/(s-r)",h(((z)*modInv(SR,N))%N))
            print("Z/S=",h(((zs))))
            print("R/S=",h(((rs))))
            print("RS-ZS=",h(((rs-zs))%N))
            print("------------------------------------------------------------------------------")

def verify(pp, message, signature):
    z=message
    r, s = signature
    w = modInv(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    x, y = add(mul(G,u1),mul(pp,u2))
    if (r % N) == (x % N):
        return True
    else:
        return False

######################## SECRET INFORMATION #############################
print("Heavy A.I. Q_tm Generator")
modulo = 115792089237316195423570985008687907852837564279074904382605163141518161494337
# Generate random transaction
import random
for _ in range(1,3900000):
  a = random.randrange(1,2**256)#change if uwanna
  c = random.randrange(1,2**256)#change if uwanna
  forge(a,c)#I wish you a g.l. (:::)
  #lastly,ugotsomethinbetter??
