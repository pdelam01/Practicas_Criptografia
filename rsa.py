# -*- coding: utf-8 -*-
"""
Created on Wed Nov  9 12:54:13 2022

@author: David
"""
import math
from decimal import Decimal
import warnings
from funcs import (
    blocks_from_bytes, power_mod, compute_block_size, bytes_from_block,
    estimate_k, bitlength, coprimes, random_probable_prime,
    multiplicative_inverse, random_odd_number_nbits
)

def rsa_keygen(nlen: int = 2048, e: int = 2 ** 16 + 1, tries : int = 30000
               ) -> tuple[tuple[int, int], int]:
    '''
    Compute public and private keys for RSA

    Parameters
    ----------
    nlen : int
        Number of bits of n
    e: int
        Public exponent.
    tries : int. Default is 30000
        The number of randomly generated numbers to be tested for p and q
        in each iteration.
        If a number of random numbers equal to tries is generated, raise an
        error.

    Returns
    -------
    (n, e), d:
        (n, e) is the public key and d the private key
    '''
    # This is a particularity of our implementation, we will see why
    if nlen < 8:
        raise ValueError("Number of bits of n must be greater than 8")
    # Why?
    if e % 2 != 1:
        raise ValueError("e should be odd")
        
    # We are not going to enforce these limits, but they are NIST's recommendations
    if e <= 2 ** 16 or e >= 2 ** 256:
        warnings.warn("exponent e should be an odd integer between 2 ** 16 and 2 ** 256, got {}".format(e))
    if nlen not in [2048, 3072]:
        warnings.warn("bitlen should be in [2048, 3072], got {}".format(nlen))
    
    # NIST restrictions to ensure p and q are big enough but not too close
    p_size = math.ceil(nlen / 2)
    q_size = nlen - p_size
    # Why these values?
    min_p = Decimal(2 ** (p_size - 1)) * Decimal(2).sqrt()
    min_q = Decimal(2 ** (q_size - 1)) * Decimal(2).sqrt()
    min_d = 2 ** (nlen // 2)
    p_q_diff = 2 ** (nlen // 2 - 100)
    
    # Ensure we mimimize the probabilities of error in the primality test
    #k = estimate_k(nlen, 2 ** - 128)
    k = 12
    
    valid_d = False
    # d must not be too small and the number of bits of n must be exactly nlen
    # in accordance to NIST specifications
    while not valid_d:
        def valid_p(p_candidate):
            return p_candidate >= min_p and coprimes(p_candidate - 1, e)
        
        p = random_probable_prime(random_odd_number_nbits(p_size),
                                  k = k, test_func = valid_p,
                                  limit = tries)            
        
        def valid_q(q_candidate):
            return (
                q_candidate >= min_q
                and coprimes(q_candidate - 1, e)
                and abs(p - q_candidate) >= p_q_diff
            )
        
        q = random_probable_prime(random_odd_number_nbits(q_size), k = k, 
                                  test_func = valid_q, limit = tries)
        
        # Preserves properties of RSA and gives smaller values of d, 
        # which accelerates computations
        carmichael_lambda = math.lcm(p - 1, q - 1)
        d = multiplicative_inverse(e, carmichael_lambda)
        n = p * q
        
        # Check loop conditions
        valid_d = d > min_d
    return (n, e), d



def rsa_conversion(by: bytes, n: int, ex: int, extract_blocks_size: int
                   ) -> list[int]:
    '''
    Executes RSA exponentiation on bytes and returns the blocks

    Parameters
    ----------
    by : bytes
        Message to be processed
    n : int
        Public modulus
    ex : int
        The exponent
    extract_blocks_size : int
        Size of the blocks to be extracted from the message

    Returns
    -------
    list[int]
        Exponentiated blocks.

    '''
    blocks = blocks_from_bytes(by, extract_blocks_size)
    return [power_mod(block, ex, n) for block in blocks]
    


def rsa_encrypt(by: bytes, n: int, e: int) -> bytes:
    '''
    Encrypt a message using RSA

    Parameters
    ----------
    text : bytes
        Message to encrypt
    n: int
        Public modulus of receiver
    e : int
        Public exponent of receiver
    Returns
    -------
    bytes
        The encrypted message
    '''
    block_size = compute_block_size(n)
    encrypted_block_size = block_size + 1
    
    last_size = len(by) % block_size    
    last_size = last_size or block_size
    encrypted = rsa_conversion(by, n, e, block_size)
    encrypted = [block.to_bytes(encrypted_block_size, byteorder="big") 
                 for block in encrypted]
    
    # We add an additional block with size of the last one.
    # This is necessary to properly decrypt leading null bytes
    padding_block = rsa_conversion(
        last_size.to_bytes(block_size, byteorder="big"), n, e, block_size)
    padding_block = [block.to_bytes(encrypted_block_size, byteorder="big")
                     for block in padding_block]
    encrypted = (b'').join(encrypted + padding_block)
    return encrypted



def rsa_decrypt(by: bytes, n: int, d: int) -> bytes:
    '''
    Decrypt en encrypted message with RSA

    Parameters
    ----------
    text : str
        Encrypted text
    n : int
        Receiver public modulus
    d : int
        Receiver private key

    Returns
    -------
    str.
        The original message
    '''
    encrypted_block_size = compute_block_size(n) + 1
    
    decrypted = rsa_conversion(by, n, d, encrypted_block_size)
    last_size = decrypted[-1]
    
    # decrypt the last block independently
    last_block = [bytes_from_block(decrypted[-2], last_size)]
    
    decrypted = decrypted[:-2]
    decrypted = [bytes_from_block(block, encrypted_block_size - 1) 
                 for block in decrypted]
    decrypted = (b'').join(decrypted + last_block)
    
    return decrypted


if __name__ == "__main__":
    (n, e), d = rsa_keygen(1024)
    #print("n:", n)
    #print("e:", e)
    #print("d:", d)

    # Mis claves
    n = 102177145502170449647535015823292055188749752771393005649892105979200067597554948297407387457859709511918845152650987194391543702482122356296402530264892095093397819813676815413255338683528599712279533202539803336778869663204648825602128229440285623432111299318482515655843275628377999479423128550587755875503
    e = 65537
    d = 17208298266325988952571337368960832188623607980442350120705618501692490442162637011651952928363009349494243761117922260068307423533979668090110058864439114949608358158668299897624131119416547961751622408610791793739698108332224032333596259924479570716158944433163524524645330628485919309011531489979608391873
    
    # Claves públicas del compañero
    bob_n = 26048554081918254772402396727078703502465630597557533117266018789540485475780747197584786190583271659321248729334208524047445737010919616936750858444125060319935027986793977486364471226442713933107427185696864514440603036987197122052742572277872232336254534169638265140240086157981444129651777094261637305372368382906823741917018463938809736866185156571482505798855621207493962046944957554996630201900999421476673956674245683880443049677156075409792647550985559524417635425479290915851823838059536484410257318950869021661885086295099873576476184621848777021277715499350226940503299366676306029946602286741170650381573
    bob_e = 1048577
    bob_encrypted = b'\x90\x14\xa1\x07\x0e%wj\xf8w.\xfe\xf2\xb0r\xdd\xf3 k\xe8\xa4 3t\x8dU\xcb\xa0\xab$w\xc5Z\x1d;\xf0$\xf7\xdb\x0c\xaf\xa1\xbdr\xf2\xbe\x07\xd6z\x08N\xb9\x923Y\xd7\x81P\x8b\xd99\x1a\xd2\xc5\xa9\x82mt\xaa\x98\xe8O\\\xf48\xf5\x14\xa2\xc1\xe1\x87C.\x05\xfa\xcc\x1f\xca\xc0\x82M\xfd\xd9\x90\x9a\x19L\xff\x98\x05\x89\xf2\x9e\xb9-\\\xc3\xaf\xc3=1\x98\x17\xa7\xb92\x16|\x08+YN\x15\x94$\xfb64\x88R\xad\xe9,\x1a\x8b\x17\xdd\x81\xf4EH?7\x1ec/\xc12\xb9"|g\x07\xf1Z\xbc&\xf7\x9c\xe0\xb1\xeb\x8f\xb2,\xb0U\xfcz\xd5\xe6\xbb\xdb\xe8\x90<\xac\xb4}\xf9z\xc5\x98\xc5\xd8\xc2\x1dtM\xce~\xb3\x89w\xff7To\x16\r,B\xc7\xb8d\x7f\x0bf#\x1d\x8a\xe3(\x8d\xf7\x8ei{\x11\xdf\xaa-\xdf\xcf`I\x82\x91\xad\xb8j+\xd2\xd9\xfcK\xfe\x0b!\xab\xe9\x11w\x94\xa8\x06\x10\xf1>\xed\x8az`\xa5A\xc8'

    # ============================ RSA Encryption =============================== #
    my_message = "Hola! Espero que estés bien. Este es un mensaje de prueba para RSA. ¡Saludos!"
    my_message_encoded = my_message.encode("utf-16")
    my_message_encrypted = rsa_encrypt(my_message_encoded, bob_n, bob_e)
    print("Mi mensaje encriptado: ", my_message_encrypted)

    # ============================ RSA Decryption =============================== #
    bob_decrypted = rsa_decrypt(bob_encrypted, n, d)
    print("\nMensaje de Bob: ", bob_decrypted.decode("utf-16"))