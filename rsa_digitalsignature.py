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
    print("\nDecrypted: ",rsa_decrypt(signature, n, e))
    return rsa_decrypt(signature, n, e) == by


if __name__ == "__main__":
    # Bob's public key
    n = 123355434931394847582156130589346765195239858952662033973669968405220821412574991703109181733654539246644904338901352138362092833002288793510559272266372536290821137928735835297624136288059785492583366524665701693180230633068234558088660840330170848973749265206460835623134857700697302798342737456620402409063
    e = 65537
    # My private key
    d = 17208298266325988952571337368960832188623607980442350120705618501692490442162637011651952928363009349494243761117922260068307423533979668090110058864439114949608358158668299897624131119416547961751622408610791793739698108332224032333596259924479570716158944433163524524645330628485919309011531489979608391873

    # My message
    message = b"Hello World"

    #Hash of my the message
    hashed_message = sha256(message)
    print("My hashed message:", hashed_message)

    # Sign the message
    signature = rsa_sign(hashed_message, n, d)
    print("\nMy signature:", signature)
    
    # ============================ RSA Signature Verification =============================== #
    test_message = b"hola buenas tardes"
    test_hashed_message = sha256(test_message)

    # Hash of the partner's message
    hashed_messageBob = b'\xce\x94I\xa0\x8bkk\x8fs\xd0V\x0c\xcf\xe0C\xb5?&\xa2)\x9b\xd8\xc3!\xe51\xf4\xa0\xc5\x7fK)'
    # Signature of the partner's message
    signatureBob = b'!gu~M.A\x9b\x03\x1e\x93\x02\xc6\xf5n\x85$f\x9d\xe3\xfa\xde\xb2D\xef\x82\xfb\xbb\xe5H]\ra\xa4\x8b\xc4\xb1\xb0\xd3\xa1\xde\x18\xef\xeb\xfa\x0bK\x96L\xd4cI\x02\xa1\xaa\xcd\x99KQSV\x81\xe6b\x9ec\n\xe9~\xab,\x7f\xfb\xd7\xedY.dR\xcf\x95\x95C\xd5\xe6\xe7\x06\xecl\xc8\xc4\xa2/L\xcf\x97Plf\xfa5(M\xf53\xd3\x0cd\xaa1\xb2\xc9\x1f\x00\x8a\xd3 5\x1f\xc8\xed&O\x0c\x89%\xd9"\x11>^\xf4_Y\xbc\x1bF\x06\xf1\xabv\x9b\xb5#\xfa\xca\x1e+\x96\xb4\t*\xa5\x8b\n*0<<\xd9o\x12\x8dI\xd4f\xce$\xeb\xb3\x98\xfey\x06\x8e\x06\x8bs\x90\x1d\xaf\xff\x9dS\x10\x8c_\xd5\x94Y\n\x0bG\xc9\x99\xfd/_\x0f\x80\x88\x97\xca\xa0\x05\xf1/\x1a\x8d[F\x7f\xb2_\x84\x06d!\xfd\xd4;uBMk.1q\xb1^\xf1\xaf\xe2\xf2A\xbbe\xf32\x8f7\xd9\xc4\xa6\x1d\x89\x81\x17^x+\xb1\xc8\x15>{'
    print("\nBob's hashed message:", hashed_messageBob)
    print("\nBob's signature:", signatureBob)

    # Verify the signature
    verified = rsa_verify(hashed_messageBob, n, e, signatureBob)
    print("\nVerified:", verified)