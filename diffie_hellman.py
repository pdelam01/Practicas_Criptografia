# Diffie-Hellman Implementation
# -----------------------------
# Implement a function to generate a random prime p of n bits and 
# a random appropriate generator g for G = Z/pZ∗
#
# Common key K = g^(a*b) mod p
# Pub key = g^a mod p
# Priv key = a / {2, ..., p-2}


import random
import math
import pi
from funcs import (
    blocks_from_bytes, power_mod, compute_block_size, bytes_from_block,
    estimate_k, bitlength, coprimes, random_probable_prime,
    multiplicative_inverse, random_odd_number_nbits, miller_rabin
)

def diffie_primes(nlen: int, tries: int = 30000) -> int:
    '''
    Compute primes for Diffie-Hellman and generate a generator g

    Parameters
    ----------
    nlen : int
        Number of bits of n
    tries : int. Default is 30000
        The number of randomly generated numbers to be tested for p and q
        in each iteration.
        If a number of random numbers equal to tries is generated, raise an
        error.

    Returns
    -------
    p,q,g:
        p and q are the primes and g the generator
    '''
    # This is a particularity of our implementation, we will see why
    if nlen < 8:
        raise ValueError("Number of bits of n must be greater than 8")    

    # NIST restrictions to ensure p and q are big enough but not too close
    q_size = math.ceil(nlen / 2)
    
    # Ensure we mimimize the probabilities of error in the primality test
    k = estimate_k(nlen, 2 ** - 128)

    valid_p = False

    while not valid_p: 
        q = random_probable_prime(random_odd_number_nbits(q_size),
                                  k = k,
                                  limit = tries)

        p = (2 * q) + 1 
        if(miller_rabin(p, k)):
            valid_p = True

    g = generate_generator(p)

    return p,q,g
        
def generate_generator(p: int) -> int:
    '''
    Generates a generator for G = Z/pZ*

    Parameters
    ----------
    p : int
        Prime number

    Returns
    -------
    int
        Generator for G = Z/pZ*
    '''
    g = random.randint(2, p - 1)
    while not is_generator(g, p):
        g = random.randint(2, p - 1)

    return g


def is_generator(g: int, p: int) -> bool:
    '''
    Checks if g is a generator for G = Z/pZ*

    Parameters
    ----------
    g : int
        Generator to be checked
    p : int
        Prime number

    Returns
    -------
    bool
        True if g is a generator for G = Z/pZ*
    '''
    if g < 2 or g > p - 1:
        return False

    for i in range(1, p - 1):
        if power_mod(g, i, p) == 1:
            return False

    return True


# RFC 3526
def rfc_3526_DH(n: int)-> tuple[int, int]:
    '''
    Returns the prime and generator for the Diffie-Hellman group n

    Parameters
    ----------
    n : int
        number of bits 

    Returns
    -------
    tuple[int, int]
        Prime and generator for the Diffie-Hellman
    '''

    if(n != 1536):
        raise Exception("El número de bits debe ser 1536") 

    p = 2**1536 - 2**1472 - 1 + 2**64 * ( math.floor(2 ** 1406 * pi.approximate_pi(len(str(2**1406))-1))  + 741804 )

    g = 2

    return p,g




# Given p = 7883, g = 2 and a user with g^ai ≡1876 mod p, form a common key with that user
def generate_key(p: int, ga_a: int) -> int:
    '''
    Generates a private and public key for Diffie-Hellman

    Parameters
    ----------
    p : int
        Prime number
    ga_a : int
        Public key of the other party

    Returns
    -------
    int
        Private common key
    '''
    a_b = random.randint(2, p - 2)
    k = power_mod(ga_a, a_b, p)

    return k


if __name__ == '__main__':
    # Part 1 - Diffie-Hellman
    p,q,g = diffie_primes(20)
    print("p: {}, q: {}, g: {}".format(p, q, g))

    # Part 2 - RFC 3526
    p_1,g_1 = rfc_3526_DH(1536)
    print("\nRFC --> p: {}, g: {}".format(p_1, g_1))

    # Part 3 - Generate k
    print(f'\nCommon key: k = {generate_key(7883, 1876)}')
