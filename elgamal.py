# ElGamal Implementation
# ----------------------
# Enc: c1 = g^k mod p, 
#      c2 = m * B^k = m * (g^ai)^k mod p
#
# Dec: m = c2 * (c1^ai)^-1 mod p

import secrets
from funcs import (
    block_from_bytes, blocks_from_bytes, bytes_from_block, compute_block_size, power_mod, multiplicative_inverse
)
from diffie_hellman import (
    diffie_primes
)

def generate_public_key(p: int, g: int, ai: int) -> int:
    '''
    Generates a public key for ElGamal
    Parameters
    ----------
    p : int
        Prime number
    g : int
        Generator for G = Z/pZ*
    ai : int
        Private key
    Returns
    -------
    int
        Public key
    '''
    return power_mod(g, ai, p)

def elgamal_keygen(p: int, g: int) -> tuple[int, int]:
    '''
    Generates a public and private key for ElGamal
    Parameters
    ----------
    p : int
        Prime number
    g : int
        Generator for G = Z/pZ*
    Returns
    -------
    tuple[int, int]
        Public and private key
    '''
    ai = secrets.choice(range(2, p-1)) # [2, p-1), since we want [2, p-2]
    pb = generate_public_key(p, g, ai)
    return pb, ai

def elgamal_encrypt(by: bytes, g: int, k: int, pk_bob: int, p: int) -> tuple[int, bytes]:
    '''
    Encrypts a message using ElGamal
    Parameters
    ----------
    by : bytes
        Message to be encrypted
    g : int
        Generator for G = Z/pZ*
    k : int
        Random number
    pk_bob : int
        Public key of Bob
    p : int
        Prime number
    Returns 
    -------
    tuple[int, bytes]
        Encrypted C1 int, C2 bytes
    '''
    encrC1 = []
    encrC2 = []

    block_size = compute_block_size(p)
    encrypted_block_size = block_size + 1
    
    last_size = len(by) % block_size    
    last_size = last_size or block_size
    encrypted = elgamal_encrypt_aux(by, g, pk_bob, p, block_size)
  
    for block in encrypted:
        encrC1.append(block[0])
        encrC2.append(block[1].to_bytes(encrypted_block_size, 'big'))

    padding_block = elgamal_encrypt_aux(last_size.to_bytes(block_size, byteorder="big"), g, pk_bob, p, block_size)
    
    for block in padding_block:
        encrC1.append(block[0])
        encrC2.append(block[1].to_bytes(encrypted_block_size, 'big'))

    list = []
    for elementC1, elementC2 in zip(encrC1, encrC2):
        list.append((elementC1, elementC2))
    
    return list

def elgamal_encrypt_aux(by: bytes, g: int, pk_bob: int, p: int, extract_blocks_size: int) -> list[tuple[int, int]]:
    '''
    Encrypts a message using ElGamal Parameters
    ----------
    by : bytes
        Message to be encrypted
    g : int
        Generator for G = Z/pZ*
    pk_bob : int
        Public key of Bob
    p : int
        Prime number
    extract_blocks_size : int
        Size of the blocks to be extracted from the message
    Returns
    -------
    list[tuple[int, int]]
        Encrypted message list of ints values C1, C2
    '''
    blocks = blocks_from_bytes(by, extract_blocks_size)
    encryptions = []

    for block in blocks:
        key = secrets.choice(range(2, p-1))
        C1 = power_mod(g, key, p)
        C2 = (block*power_mod(pk_bob, key, p))%p
        encryptions.append((C1, C2))

    return encryptions

def elgamal_decrypt(by: bytes, p: int, ai: int) -> bytes:
    '''
    Decrypts a message using ElGamal Cryptosystem
    ----------
    by : bytes
        Message to be decrypted
    p : int
        Prime number
    ai : int
        Private key
    Returns
    -------
    bytes
        Decrypted message
    '''
    decryptedC1 = []
    decryptedC2 = []
    for block in by:
        decryptedC1.append(block[0])
        decryptedC2.append(block[1])

    encrypted_block_size = compute_block_size(p) + 1

    decrypted = elgamal_decrypt_aux(decryptedC1, decryptedC2, ai, p)
    last_size = decrypted[-1]
    last_block = [bytes_from_block(decrypted[-2], last_size)]
    decrypted = decrypted[:-2]

    decrypted = [bytes_from_block(block, encrypted_block_size - 1) 
                 for block in decrypted]
    decrypted = (b'').join(decrypted + last_block)

    return decrypted

def elgamal_decrypt_aux(listC1: list, listC2: list, ai: int, p: int) -> list[int]:
    '''
    Decrypts a message using ElGamal Cryptosystem
    ----------
    listC1 : list
        List of C1 values
    listC2 : list
        List of C2 values
    ai : int
        Private key
    p : int
        Prime number
    Returns
    -------
    list[int]
        Decrypted message
    '''
    blocksC1 = []
    blocksC2 = []

    for elementC1, elementC2 in zip(listC1, listC2): #zip functions for tuples, very useful
        blocksC1.append(elementC1)
        blocksC2.append(block_from_bytes(elementC2))        

    return [blockC2*multiplicative_inverse(power_mod(blockC1, ai, p), p)%p for blockC1, blockC2 in zip(blocksC1, blocksC2)]

if __name__ == "__main__":
    # Bob's keys
    p_bob = 28499
    g_bob = 14249
    pb_bob = 14249

    # My keys
    ai = 3939
    p = 68507
    g = 64136
    k = diffie_primes(32)
    pb = 44370
    print("My public key: {}, my private key: {}".format(pb, ai))
    
    # Message and encoded message
    my_message = "Hello Pablo Welcome to Elgamal World"
    print("\nMy message: {}".format(my_message))
    my_message_encoded = my_message.encode('utf-8')
    
    # Encrypt my message
    encrypted = elgamal_encrypt(my_message_encoded, g_bob, k, pb_bob, p_bob)
    print("\nMy message encrypted: ", encrypted)

    # ============================ ElGamal Decryption =============================== #
    message_bob = [(6101, b',W'), (12630, b'[\xa9'), (22637, b'\\\xfb'), (17437, b'1\xa3'), (26901, b' $'), (24059, b'\x1b1'), (7856, b'\x01\xf4'), (8310, b'jv'), (17544, b'\x1f\x93'), (3692, b'0F'), (5227, b'X\xec'), (24706, b'\x14\x11'), (17431, b'I\xc6'), (23947, b'O\xc7'), (14533, b'e1'), (2350, b'\n\x10'), (10084, b'\x15+'), (19896, b'c\xab'), (10232, b'\x0b\xc6'), (27635, b'F\xc3'), (19861, b'E\xfb'), (3730, b'\x08n'), (13881, b'Hm'), (12498, b'Y\xe5'), (18524, b'Nc'), (9400, b'\x17\x0c'), (21909, b'] '), (6499, b'YZ'), (3225, b'2\xa8'), (15933, b'\x0b\x1d'), (20798, b'\x05\xe6'), (17950, b'\x05\xb4'), (26194, b'9\xca'), (1620, b'I\xea'), (19761, b'\x0fq'), (2851, b'm\xd4'), (13983, b'B\xe6'), (13024, b'+R'), (1070, b'5\xaa')]
    decrypted_bob = elgamal_decrypt(message_bob, p_bob, ai)
    message_decrypted_bob = decrypted_bob.decode('utf-8')
    print("\nBob's message decrypted: ", message_decrypted_bob)