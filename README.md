# Practicas_Criptografia

## Public key cryptography
Exercises about different public key algorithms implemented using Python language.

### RSA Cipher
- Generate a pair of RSA keys
- Send an encrypted message encoded in UTF-8
- Decrypt the message sent to you

### Diffie-Hellman
- Implement a function to generate a random prime p of n bits and a random appropriate generator g for G = Z/pZ*. Fix p to be of the form p = 2q + 1, where q is prime (q
would be a Sophie Germain prime.
- Implement a function that returns a pair of p and g obtained from RFC 3526
- Given p = 7883, g = 2 and a user with gai ≡1876 mod p, form a common key with that user

### ElGamal
- Generate some valid p, g and public key β = g^ai
- Send an encrypted message encoded in UTF-8
- Decrypt the message sent to you

### RSA Signature
- Select one of the FIPS 180-4 hash functions to be used as part of the signature process and implement the signature scheme
- Send an encrypted and signed message
- Verify the signature and decrypt the message sent to you
