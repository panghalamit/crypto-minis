from Crypto.Hash import SHA256
from Crypto.PublicKey.RSA import RSAImplementation
from Crypto.Random import random
from Crypto.Util import number
import hashlib
from math import ceil
import sys


def getOctetSize(n) :
    '''get number octets for the number'''
    nbits=1
    while n :
        n >>= 1
        nbits+=1
    q,_ = divmod(nbits, 8)
    return q


def I2OSP(x, xLen):
    '''non-negative integer to octect string of size xLen'''
    if x > pow(256,xLen) :
        '''Number cant be expressed using xLen bytes'''
        raise  Exception('Exception: Number too large')
    else :
        octet_s = number.long_to_bytes(x, xLen)
        return b''+octet_s

def OS2IP(X):
    '''converts byte string into integer, inverse of I2OSP'''
    integer = number.bytes_to_long(X)
    return integer



def EC2OSP(ecp):
	'''conversion of EC point to an m-octet string with point compression'''
	if(check_infinity(ecp)) :
		return b''+number.long_to_bytes(0,1)
	else :
		octet_xp = I20SP(ecp.x, ecpgetOctetSize(q))
		if(ecp.y%2 == 0) :
			return b''+number.long_to_bytes(2,1)+octet_xp
		else :
			return b''+number.long_to_bytes(3,1)+octet_xp




def OS2ECP(X):
	'''conversion of an m-octet string to EC point'''
	if(X.length == 1):
		return infinity
	else :
		xp = number.bytes_to_long(X[1:])
		Y = number.bytes_to_long(X[0])
		if(Y==2):
			y_p=0
		else if(Y==3):
			y_p=1
		else return INVALID

		beta = sqrtmod(evalec(xp))
		if(beta%2 == y_p) :
			yp=beta
		else :
			yp=p-beta
		return ECP(xp,yp)



def RS2ECP(RX):
	'''conversion of a random 2n-octet string to an EC point'''
	return OS2ECP(b''number.long_to_bytes(2,1)+RX)


def ECVRF_prove(y, x, alpha):
	'''returns VRF proof pi, given public key y, private key x and input message alpha'''
	h = ECVRF_hash_to_curve(y, alpha)
	gamma = h^x
	k = getRandom(0, q-1)
	c = ECVRF_hash_points(g, h, y, gamma, g^k, h^k)
	s = k - multmod(c,x,q)
	pi = EC2OSP(gamma) + I20SP(c, n) + I2OSP(s, 2*n)
	return pi


def ECVRF_proof2hash(pi):
	''' returns hash value beta from VRF proof pi'''
	(gamma, c,s) = ECVRF_decode_proof(pi)
	if gamma is INVALID :
		return INVALID
	beta = SHA256(EC2OSP(gamma^cofactor))
	return beta

def ECVRF_verify(y, pi, alpha):
	''' returns VALID or INVALID given input as public key y, VRF proof pi and input message alpha'''
	(gamma, c, s) = ECVRF_decode_proof(pi)
	if gamma is INVALID :
		return 'INVALID'
	u = EC_ADD(y^c, g^s)
	h = ECVRF_hash_to_curve(y, alpha)
	v = EC_ADD(gamma^c, h^s)
	c_ = ECVRF_hash_points(g,h,y,gamma, u, v)
	if (c == c_) :
		return 'VALID'
	else:
	 return 'INVALID'


def ECVRF_hash_to_curve(y, alpha):
	''' returns a EC point in G given input string alpha and public key'''
	ctr=0
	pk = EC2OSP(y)
	h=INVALID
	while h is INVALID or h is infinity:
		CTR = I2OSP(ctr, 4)
		ctr += 1
		attempted_hash = SHA256(pk + alpha + CTR)
		h = RS2ECP(attempted_hash)
		if h is not INVALID and cofactor >1:
			h = h^cofactor
	return h




def ECVRF_hash_points(ecp_list): 
	'''returns hashe of  a number of EC points'''
	P=b''
	for p_i in ecp_list:
		P += EC2OSP(p_i)
	h1 = SHA256(P)
	h2 = h1[0:n]
	h = OS2IP(h2)
	return h


def ECVRF_decode_proof(pi):
	'''returns c, s and gamma, given encoded proof pi'''
	gamma_ = pi[0:m]
	c_ = pi[m:m+n]
	s_ = pi[m+n:]
    gamma = OS2ECP(gamma_)
	if gamma is INVALID :
		return (INVALID, INVALID, INVALID)
	c = OS2IP(c_)
	s = OS2IP(s_)
	return (gamma, c, s)


