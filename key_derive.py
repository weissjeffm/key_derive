import scrypt
import mnemonic
from mnemonic import shamir

#updated for python 3

m = mnemonic.Mnemonic("english")
s = shamir.Shamir("english")

def derive(key, salt="", length=32):
    return scrypt.hash(key, salt, buflen=length)

def seed_words(key):
    return m.to_mnemonic(key)

def combine_derive(shares, salt="", length=32):
    #m = mnemonic.Mnemonic("english")
    return scrypt.hash(s.combine(shares), salt, buflen=length)

def derive_passphrase(key, salt="", words=4):
    return m.to_mnemonic(derive(key, salt)).split(" ")[:words]

def from_words(seed_words, salt="", words=4):
    k = m.to_entropy(seed_words)
    return derive_passphrase(bytes(k), salt, words)
