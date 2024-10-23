import hashlib
import binascii
from Crypto.Util.number import long_to_bytes, bytes_to_long

class SirpMixin:
    # Convert a hex string to an array of Integer bytes
    @staticmethod
    def hex_to_bytes(s):
        return list(bytes.fromhex(s))

    # Convert a number to a downcased hex string
    @staticmethod
    def num_to_hex(num):
        hex_str = hex(num)[2:]
        return ('0' + hex_str) if len(hex_str) % 2 else hex_str

    # Apply a one-way hash function on an unpacked hex string
    @staticmethod
    def sha_hex(h, hash_func):
        return hash_func(bytes.fromhex(h)).hexdigest()

    # Apply a one-way hash function on the string provided
    @staticmethod
    def sha_str(s, hash_func):
        return hash_func(s.encode()).hexdigest()

    # Constant time string comparison
    @staticmethod
    def secure_compare(a, b):
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

    # Modular Exponentiation
    @staticmethod
    def mod_exp(a, b, m):
        return pow(a, b, m)

    # Hashing function with padding
    @staticmethod
    def H(hash_func, n, *a):
        nlen = 2 * ((len(hex(n)[2:]) * 4 + 7) // 8)
        hashin = ''.join([('0' * (nlen - len(SirpMixin.num_to_hex(s))) + SirpMixin.num_to_hex(s) if isinstance(s, int) else
                           '0' * (nlen - len(s)) + s) for s in a if s is not None])
        return int(SirpMixin.sha_hex(hashin, hash_func), 16) % n

    # Multiplier parameter
    @staticmethod
    def calc_k(n, g, hash_func):
        return SirpMixin.H(hash_func, n, n, g)

    # Private key
    @staticmethod
    def calc_x(username, password, salt, hash_func):
        return int(SirpMixin.sha_hex(salt + SirpMixin.sha_str(f"{username}:{password}", hash_func), hash_func), 16)

    @staticmethod
    def calc_x_hex(xpassword, xsalt, hash_func):
        if not all(c in '0123456789abcdefABCDEF' for c in xpassword + xsalt):
            raise ValueError("xpassword and xsalt must be hex strings")
        return int(SirpMixin.sha_hex(xsalt + SirpMixin.sha_hex(hex(ord(':'))[2:] + xpassword, hash_func), hash_func), 16)

    # Random scrambling parameter
    @staticmethod
    def calc_u(xaa, xbb, n, hash_func):
        return SirpMixin.H(hash_func, n, xaa, xbb)

    # Password verifier
    @staticmethod
    def calc_v(x, n, g):
        return SirpMixin.mod_exp(g, x, n)

    # A = g^a (mod N)
    @staticmethod
    def calc_A(a, n, g):
        return SirpMixin.mod_exp(g, a, n)

    # B = g^b + k v (mod N)
    @staticmethod
    def calc_B(b, k, v, n, g):
        return (SirpMixin.mod_exp(g, b, n) + k * v) % n

    # Client secret
    @staticmethod
    def calc_client_S(bb, a, k, x, u, n, g):
        return SirpMixin.mod_exp((bb - k * SirpMixin.mod_exp(g, x, n)) % n, (a + x * u), n)

    # Server secret
    @staticmethod
    def calc_server_S(aa, b, v, u, n):
        return SirpMixin.mod_exp((SirpMixin.mod_exp(v, u, n) * aa), b, n)

    # M = H(H(N) xor H(g), H(I), s, A, B, K)
    @staticmethod
    def calc_M(n, g, username, xsalt, xaa, xbb, xkk, hash_func):
        hxor = SirpMixin.H(hash_func, n, n) ^ SirpMixin.H(hash_func, n, g)
        buf = (SirpMixin.num_to_hex(hxor) +
               SirpMixin.sha_str(username, hash_func) +
               xsalt + xaa + xbb + xkk)
        return hash_func(bytes.fromhex(buf)).hexdigest()

    # H(A, M, K)
    @staticmethod
    def calc_H_AMK(xaa, xmm, xkk, hash_func):
        byte_string = bytes.fromhex(xaa + xmm + xkk)
        return int(SirpMixin.sha_str(byte_string.decode('latin-1'), hash_func), 16)
