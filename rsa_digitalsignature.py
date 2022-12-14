# RSA Signature implementation
# ----------------------------
# Signature: S = M^d mod n
# Verification: M = S^e mod n

import hashlib
from rsa import rsa_encrypt, rsa_decrypt

# Select a hash function from FIPS 180-4
# SHA-256 is the default
def sha256(by: bytes) -> bytes:
    '''
    Computes the SHA-256 hash of a message

    Parameters
    ----------
    by : bytes
        Message to be hashed

    Returns
    -------
    bytes
        SHA-256 hash of the message

    '''
    return hashlib.sha256(by).digest()

def rsa_sign(by: bytes, n: int, d: int) -> bytes:
    '''
    Sign a message using RSA

    Parameters
    ----------
    by : bytes
        Message to sign
    n: int
        Public modulus of receiver
    d : int
        Private exponent of receiver

    Returns
    -------
    bytes
        The signature

    '''
    return rsa_encrypt(by, n, d)

def rsa_verify(by: bytes, n: int, e: int, signature: bytes) -> bool:
    '''
    Verify a message using RSA

    Parameters
    ----------
    by : bytes
        Message to verify
    n: int
        Public modulus of receiver
    e : int
        Public exponent of receiver
    signature : bytes
        Signature to verify

    Returns
    -------
    bool
        True if the signature is valid, False otherwise

    '''
    return rsa_decrypt(signature, n, e) == by


if __name__ == "__main__":
    # My keys
    n = 110477620934049393733275265425319715013384221791352610600040838995728481009667690503849981506344012764292009379787793009565139234703193116888335807677802785350021945337615918588620239492464432226348696954426754149567553978837124726589912929545140618195782211815916207778575351484388869984100139595053059887809
    e = 65537
    d = 2049565499168129777286731315332578851190009455137091246998636700067237512055596589777747977195527140179110549322143598284881544565562948633851640338052222830151760952442709461557167119469500215039089254706556629629336762608475917540234934246658761072607271998085435334103730322596575358091993913710759490913

    # Bob's keys
    n_ = 137240983915996962747909454484640658542329656056449401370891990025072346702917945425463397482231359266614646060111542095646286224283115300273103159970060217155569265862077406621057638854015677632691187303616523985260804276248741993354084069774341050814080965415297141189501657346954323426277281084454908433239
    e_ = 65537

    # My message
    message = b"Hello World"

    #Hash of my the message
    hashed_message = sha256(message)
    print("My hashed message:", hashed_message)

    # Encrypt the message
    encrypted_message = rsa_encrypt(message, n_, e_)
    print("\nSender's encrypted message:", encrypted_message)

    # Sign the message using my private key
    signature = rsa_sign(hashed_message, n, d)
    print("\nMy signature:", signature)
    
    # ============================ RSA Signature Verification =============================== #

    # Hash of the partner's message
    encrypted_messageBob = b'\x11\xb0\x9e\xde\xeb6s\xbe\xfa\xb9\xc3\x0cx\xbb8\x9e\x94\x0e\xb2mj \x98\x1b\xd4`\xc9\x81v>lX\x81;~\xb1\x81\xc8\xd9\xc4N\x90\xc1\xc7o\xb5\x95\xf0\xa8|\xc5\xd9\xec\xb7\x96o:\xd0{Bb\x17\xde\xd2=\xad\x12{9\xf9MO\xc9\xcb2\xba\x8f)\xd8\x96t\x189H\xe4\xad\x8f\x14\xf5%\x8c\xc0\x19\xfbO\x0cIU\x82R\xe8ea\xaa=g\x1a\xe4\xd2\\\xe0@\xb6\xfb\xdb\x7f\xefT\xa6W\xd6j^H\x17\x82R\xfda\x04\x16\x07\xc0\xa5\x1b\x85\xc70\x9e\xff\xe9\x01\xba\xf1XcR\xc4\xa1x\xae,\x8b\x94\xf8)\xaa\x9d\xa8\xb9nU\x84\x94\xd4\x87\xc9\x8e0\x93\x82\x17Z\xeb\xecW\xc7u\xc90\x0b\r$x\x98l\xc5\x1e\x91lk)\xf3\xb6M(@\xf5\x13$DP\x15\xa4\xab\xf8\xbd\xe9j\xf2\xfb\x99\xc2A1:\xf5\xae\x1e\x01\x89\x02\x15P "\xee\xdc\x8eM\xb62\xe4\xe9}zV\x8a\xa4H\x18\x1dAp\x83\x8d\x86o\xcc\x0f\xfd\xdb\x7f\x97\xfa\xc8'
    
    # Signature of the partner's message
    signatureBob = b'\x1b\x80\x05U\x97\x04\xe1\xfa\xcd%\xa7eX\xc1\xab\xe1\x01L\xed*m"\xdc0U\xa5\xc5\xab\xf5\x9c\x8a\x19:\x98o\xe9\xd7\x04hr<\xb48\x19\rYWB\x832"\xab@\xab\xbe\x01\xb1\r\xe1\xbb~?\x0e\x9ci\x8ch\x97\xfd\x16\x87Rs\x12cM\xa5\xdctx\x81\xec\x818\x99.\xf4W\xec\xcb}\xc1\xa83L\x93\xa3\xdd\xc4\xca\xd0\x00\xa8\xff\x8c2\x0c\xdf\xf4y\x82\x0f\x94\xda\t\x93\x84)GK\x1a\xdb\xfd\xf0+p@\x95v\xe4\xaaM\x84\xb1\x84\x17\x90Y\xc2\nH\xe3\xb4\xe1\x1c\xd8\xc2$\x9f&\xc2\xf3\xed\x1c~n\x80\xe4\xed\xa9\xd62\x9e\x07\x8f#\xdcRQ\xbb\xdf\x1c\xa8\x1fF\x05\x0eC\x9c~\xf6\x08f\xe2-\x1e-\xe6\xa2\xf2\xf7\xc05\x1bg\x1c\x89\'\xfb@\xa3\xb7\x13rd\x05\x92X\xb2v\xc5C\xf6\xb8/R\x8f\x80\xe6\x1b}\xa9\xe7\x0c\xb2\x98\x1c\xa5\xf6\x90\xee\x03]\xc27\xb4}\x12\x84*\x93\x13.v\x86\x12\xc2M\xb6\xf9\x8a\xf4\x9f\x99\xb3\xe2'
    print("\nBob's encrypted message:", encrypted_messageBob)
    print("\nBob's signature:", signatureBob)

    # Decrypt the partner's message
    decrypted_messageBob = rsa_decrypt(encrypted_messageBob, n, d)
    print("\nDecrypted Bob's message:", decrypted_messageBob)

    # Verify the signature
    verified = rsa_verify(sha256(rsa_decrypt(encrypted_messageBob, n, d)), n_, e_, signatureBob)
    print("\nVerified:", verified)
