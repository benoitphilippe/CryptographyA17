#!/usr/bin/env python3.6
#encoding=utf-8

""" Gère la génération de nombre Premier """

from Cryptodome.Util.number import getPrime, size
from secrets import randbelow
from random import randrange

def getStrongPrime(N):
    """ Génère un nombre premier p de N bits de tel sorte que :
    (p-1)/2 = q et q aussi premier """
    p = getPrime(N)
    while not miller_rabin((p-1)//2):
        p = getPrime(N)
    return p

def getStongGenerator(p):
    """ Génère un generateur de Z/Zp
    On compte sur le fait que p soit un nombre premier issue
    de getStrongPrime juste audessus
    comme ça on connait la décomposition de p-1
    """
    q = (p-1)//2
    if not miller_rabin(q):
        raise ValueError("p doit être issue de la fonction getStrongPrime")
    a = randbelow(p)
    while pow(a,2,p) == 1 or pow(a, q, p) == 1 or a <= 1:
        a = randbelow(p)
    return a

def miller_rabin(n, k=30):
    if n == 2:
	    return True
    if not n & 1:
	    return False

    def check(a, s, d, n):
    	x = pow(a, d, n)
    	if x == 1:
    		return True
    	for i in range(s - 1):
    		if x == n - 1:
    			return True
    		x = pow(x, 2, n)
    	return x == n - 1

    s = 0
    d = n - 1

    while d % 2 == 0:
    	d >>= 1
    	s += 1

    for i in range(k):
    	a = randrange(2, n - 1)
    	if not check(a, s, d, n):
    		return False
    return True

# benchmark of 10000 iterations of miller_rabin(100**10-1); Which is not prime.

# 10000 calls, 11111 per second.
# 74800 function calls in 0.902 seconds


def test():
    N = 512 # au-dessus ça devient trop long
    p = getStrongPrime(N)
    print(p)
    for i in range(5):
        print(getStongGenerator(p)) 


if __name__ == '__main__':
    test()