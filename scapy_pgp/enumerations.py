

PUBLIC_KEY_ALGORITHMS = {
    "RSA (Encrypt or Sign)"       : 1,
    "RSA Encrypt-Only"            : 2,
    "Rsa Sign-Only"               : 3,
    "Elgammal Encrypt-Only"       : 16,
    "DSA"                         : 17,
    "Reserved for Elliptic Curve" : 18,
    "Reserved for ECDSA"          : 19,
    "Reserved (formerly Elgamal Encrypt or Sign)" : 20,
    "Reserved for Diffie-Hellman (X9.42)"         : 21,
}

SYMMETRIC_KEY_ALGORITHMS = {
    "Plaintext"   : 0,
    "IDEA"        : 1,
    "TripleDES"   : 2,
    "CAST5"       : 3,
    "Blowfish"    : 4,
    "AES-128"     : 7,
    "AES-192"     : 8,
    "AES-256"     : 9,
    "Twofish-256" : 10
}

HASH_ALGORITHMS = {
    "MD5"       : 1,
    "SHA1"      : 2,
    "RIPEMD160" : 3,
    "SHA256"    : 8,
    "SHA384"    : 9,
    "SHA512"    : 10,
    "SHA224"    : 11
}

COMPRESSION_ALGORITHMS = {
    "Uncompressed" : 0,
    "ZIP" : 1,
    "ZLIB" : 2,
    "BZip2" : 3
}
