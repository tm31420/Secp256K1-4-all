# Author unknown
# modified by strum

import sys
import random
from sage.all_cmdline import *   
from bitcoin import *

order = int(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
filename=sys.argv[1]
#B = 176#int(sys.argv[2])
limit = 393693#?
run_mode = "LLL"
address = "17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT"#"17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT"
import gmpy2
def modular_inv(a,b):
  return int(gmpy2.invert(a,b))

def load_csv(filename):
  msgs = []
  sigs = []
  pubs = []
  fp = open(filename)
  n=0
  for line in fp:
    if n < limit:
      l = line.rstrip().split(",")
      #sys.stderr.write(str(l)+"\n")
      R,S,Z = l
      msgs.append(int(Z,16))
      sigs.append((int(R,16),int(S,16)))
      #pubs.append(pub)
      n+=1
  return msgs,sigs,pubs

msgs,sigs,pubs = load_csv(filename)

msgn, rn, sn = [msgs[-1], sigs[-1][0], sigs[-1][1]]
rnsn_inv = rn * modular_inv(sn, order)
mnsn_inv = msgn * modular_inv(sn, order)

def make_matrix(msgs,sigs,pubs,B):
  m = len(msgs)
  #sys.stderr.write("Using: %d sigs...\n" % m)
  #sys.stderr.write("Bit range: %d...\n" %B)
  matrix = Matrix(QQ,m+2, m+2)

  for i in range(0,m):
    #matrix.append([0] * i + [order] + [0] * (m-i+1))
    matrix[i,i] = order

  #print(matrix)

  for i in range(0,m):
    x0=(sigs[i][0] * modular_inv(sigs[i][1], order)) - rnsn_inv
    x1=(msgs[i] * modular_inv(sigs[i][1], order)) - mnsn_inv
    #print(m,i,x0,x1)
    matrix[m+0,i] = x0
    matrix[m+1,i] = x1

  #print("m",m)
  #print("i",i)
 
  matrix[m+0,i+1] = (int(2**B) / order)
  matrix[m+0,i+2] = 0
  matrix[m+1,i+1] = 0
  matrix[m+1,i+2] = 2**B

  return matrix

#sys.stderr.write(str(matrix)+"\n")

keys=[]
def try_red_matrix(m):
  for row in m:
    potential_nonce_diff = row[0]
    #print (potential_nonce_diff)
    # Secret key = (rns1 - r1sn)-1 (snm1 - s1mn - s1sn(k1 - kn))
    potential_priv_key = (sn * msgs[0]) - (sigs[0][1] * msgn) - (sigs[0][1] * sn * potential_nonce_diff)
    try:
      potential_priv_key *= modular_inv((rn * sigs[0][1]) - (sigs[0][0] * sn), order)

      key = potential_priv_key % order
      if key not in keys:
        keys.append(key)

    except Exception as e:
      sys.stderr.write(str(e)+"\n")
      pass
 
def display_keys(keys):
  for key in keys:
    v = "%064x" % key
    myhex = v[:64]
    priv = myhex
    pub = privtopub(priv)
    v = int(v,16)
    if v < 0x1000000000000000000000000000000:
      print(priv)
    pubkey1 = encode_pubkey(privtopub(priv), "bin_compressed")
    addr = pubtoaddr(pubkey1)
    n = addr
    if n.strip() == address: 
      print ("found!!!",addr,myhex)
      sys.exit()
      
for i in range(174,256):
  i = int(i)
  matrix = make_matrix(msgs,sigs,pubs,i)
  matrix = matrix.LLL()
  try_red_matrix(matrix)
  display_keys(keys)# prints hex keys, mostly 2nd one is correct 